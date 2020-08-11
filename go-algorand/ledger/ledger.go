// Copyright (C) 2019 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package ledger

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/vector"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
)

// ErrNotArchival is returned whenever an operation failed because
// the ledger is non-archival.
var ErrNotArchival = fmt.Errorf("ledger is non-archival")

// Ledger is a database storing the contents of the ledger.
type Ledger struct {
	// Database connections to the DBs storing blocks and tracker state.
	// We use potentially different databases to avoid SQLite contention
	// during catchup.
	trackerDBs dbPair
	blockDBs   dbPair

	// blockQ is the buffer of added blocks that will be flushed to
	// persistent storage
	blockQ *blockQueue

	log logging.Logger

	// archival determines whether the ledger keeps all blocks forever
	// (archival mode) or trims older blocks to save space (non-archival).
	// The default is archival mode; it can be changed by SetArchival().
	archival bool

	// genesisHash stores the genesis hash for this ledger.
	genesisHash crypto.Digest

	// State-machine trackers
	accts      accountUpdates
	acctProofs acctProofTracker
	txTail     txTail
	bulletin   bulletin
	notifier   blockNotifier
	time       timeTracker
	metrics    metricsTracker

	trackers  trackerRegistry
	trackerMu deadlock.RWMutex

	headerCache heapLRUCache
}

// OpenLedger creates a Ledger object, using SQLite database filenames
// based on dbPathPrefix (in-memory if dbMem is true).  initBlocks and
// initAccounts specify the initial blocks and accounts to use if the
// database wasn't initialized before.
func OpenLedger(log logging.Logger, dbPathPrefix string, dbMem bool, initBlocks []bookkeeping.Block, initAccounts map[basics.Address]basics.AccountData, genesisHash crypto.Digest) (*Ledger, error) {
	var err error
	l := &Ledger{
		log:         log,
		archival:    true,
		genesisHash: genesisHash,
	}

	l.headerCache.maxEntries = 10

	defer func() {
		if err != nil {
			l.Close()
			if l.blockQ != nil {
				l.blockQ.close()
			}
		}
	}()

	// Backwards compatibility: we used to store both blocks and tracker
	// state in a single SQLite db file.
	var trackerDBFilename string
	var blockDBFilename string

	commonDBFilename := dbPathPrefix + ".sqlite"
	if !dbMem {
		_, err = os.Stat(commonDBFilename)
	}

	if !dbMem && os.IsNotExist(err) {
		// No common file, so use two separate files for blocks and tracker.
		trackerDBFilename = dbPathPrefix + ".tracker.sqlite"
		blockDBFilename = dbPathPrefix + ".block.sqlite"
	} else if err == nil {
		// Legacy common file exists (or testing in-memory, where performance
		// doesn't matter), use same database for everything.
		trackerDBFilename = commonDBFilename
		blockDBFilename = commonDBFilename
	} else {
		return nil, err
	}

	l.trackerDBs, err = dbOpen(trackerDBFilename, dbMem)
	if err != nil {
		return nil, err
	}

	l.blockDBs, err = dbOpen(blockDBFilename, dbMem)
	if err != nil {
		return nil, err
	}

	err = l.blockDBs.wdb.Atomic(func(tx *sql.Tx) error {
		return blockInit(tx, initBlocks)
	})
	if err != nil {
		return nil, err
	}

	l.blockQ, err = bqInit(l)
	if err != nil {
		return nil, err
	}

	// Accounts are special because they get an initialization argument (initAccounts).
	if initAccounts == nil {
		initAccounts = make(map[basics.Address]basics.AccountData)
	}

	if len(initBlocks) != 0 {
		// only needed if not initialized yet
		l.accts.initProto = config.Consensus[initBlocks[0].CurrentProtocol]
		l.acctProofs.initProto = config.Consensus[initBlocks[0].CurrentProtocol]
	}
	l.accts.initAccounts = initAccounts

	l.trackers.register(&l.accts)
	l.trackers.register(&l.acctProofs)
	l.trackers.register(&l.txTail)
	l.trackers.register(&l.bulletin)
	l.trackers.register(&l.notifier)
	l.trackers.register(&l.time)
	l.trackers.register(&l.metrics)

	err = l.trackers.loadFromDisk(l)
	if err != nil {
		return nil, err
	}

	// Check that the genesis hash, if present, matches.
	err = l.blockDBs.rdb.Atomic(func(tx *sql.Tx) error {
		latest, err := blockLatest(tx)
		if err != nil {
			return err
		}

		hdr, err := blockGetHdr(tx, latest)
		if err != nil {
			return err
		}

		params := config.Consensus[hdr.CurrentProtocol]
		if params.SupportGenesisHash && hdr.GenesisHash != genesisHash {
			return fmt.Errorf("latest block %d genesis hash %v does not match expected genesis hash %v", latest, hdr.GenesisHash, genesisHash)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return l, nil
}

// Close reclaims resources used by the ledger (namely, the database connection
// and goroutines used by trackers).
func (l *Ledger) Close() {
	l.trackerDBs.close()
	l.blockDBs.close()
	l.trackers.close()
}

// SetArchival sets whether the ledger should operate in archival mode or not.
func (l *Ledger) SetArchival(a bool) {
	l.archival = a
}

// RegisterBlockListeners registers listeners that will be called when a
// new block is added to the ledger.
func (l *Ledger) RegisterBlockListeners(listeners []BlockListener) {
	l.notifier.register(listeners)
}

// notifyCommit informs the trackers that all blocks up to r have been
// written to disk.  Returns the minimum block number that must be kept
// in the database.
func (l *Ledger) notifyCommit(r basics.Round) basics.Round {
	l.trackerMu.Lock()
	defer l.trackerMu.Unlock()
	minToSave := l.trackers.committedUpTo(r)

	if l.archival {
		// Do not forget any blocks.
		minToSave = 0
	}

	return minToSave
}

// Lookup uses the accounts tracker to return the account state for a
// given account in a particular round.  The account values reflect
// the changes of all blocks up to and including rnd.
func (l *Ledger) Lookup(rnd basics.Round, addr basics.Address) (basics.AccountData, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	// Intentionally apply (pending) rewards up to rnd.
	data, err := l.accts.lookup(rnd, addr, true)
	if err != nil {
		return basics.AccountData{}, err
	}

	return data, nil
}

// LookupWithoutRewards is like Lookup but does not apply pending rewards up
// to the requested round rnd.
func (l *Ledger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (basics.AccountData, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	data, err := l.accts.lookup(rnd, addr, false)
	if err != nil {
		return basics.AccountData{}, err
	}

	return data, nil
}

// VerifyAccountProof verifies the given account proof.
func (l *Ledger) VerifyAccountProof(unvalidated basics.UnvalidatedAccountProof) (basics.AccountProof, error) {
	l.trackerMu.RLock()
	// XXX this is safe if and only if the archive has no voting keys
	if l.archival {
		defer l.trackerMu.RUnlock()
		vparams := l.accts.parameters()
		pf, ok := unvalidated.UnsafeDecode(vparams)
		if !ok {
			return basics.AccountProof{}, fmt.Errorf("XXX account proof did not decode")
		}
		return pf, nil
	}
	f, err := l.accts.verify(unvalidated.Address, unvalidated)
	l.trackerMu.RUnlock()

	if err != nil {
		return basics.AccountProof{}, err
	}
	pf, _, err := f.call()
	return pf, err
}

// ForkSafeLookup returns the account state for a given account in a
// particular round if and only if all non-archival nodes are guaranteed to be
// able to compute the account state given recent history and the provided
// AccountProof.
func (l *Ledger) ForkSafeLookup(pf basics.UnvalidatedAccountProof, withRewards bool) (basics.AccountData, error) {
	okpf, err := l.VerifyAccountProof(pf)
	if err != nil {
		return basics.AccountData{}, err
	}
	data := okpf.AccountData

	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	res := l.accts.forkSafeLookup(pf.Round, okpf.Address, withRewards, asContext(okpf.Address, okpf))
	if res.cok {
		// account was updated recently and data is stale
		return res.curr.AccountData, nil
	}

	if withRewards {
		data, err = l.accts.applyRewards(pf.Round, data)
	}
	if err != nil {
		return basics.AccountData{}, err
	}

	return data, nil
}

// lookupForEval returns the raw accountData as stored by the
// ledger, without applying rewards, given a possibly stale accountContext,
// with respect to some particular round.  This method returns the
// best-updated accountContext for this address.
//
// lookupForEval performs a lookup whose result is consistent
// across correct, synchronized nodes.  This is important because
// lookupForEval is used to determine the validity of
// transactions in a block (and the block itself, by transitivity); if
// correct nodes disagree on the validity of a block, the protocol can
// lose liveness.
func (l *Ledger) lookupForEval(rnd basics.Round, addr basics.Address, ctx accountContext) (basics.AccountData, accountContext, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	res := l.accts.forkSafeLookup(rnd, addr, false, ctx)
	if !res.cok {
		res.curr = ctx.curr
	}
	if !res.pok {
		res.prev = ctx.prev
	}
	return res.curr.AccountData, accountContext{curr: res.curr, prev: res.prev}, nil
}

// XXXspecialContext TODO
func (l *Ledger) XXXspecialContext(rnd basics.Round, rewardsPool basics.Address, feeSink basics.Address) (rwctx accountContext, feectx accountContext, err error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	if l.archival {
		rwctx, err = l.accts.xxxAccountContext(rnd, rewardsPool)
		if err != nil {
			return
		}
		feectx, err = l.accts.xxxAccountContext(rnd, feeSink)
		return
	}

	var rwpf, feepf basics.AccountProof
	rwpf, err = l.acctProofs.accountProof(rnd, rewardsPool)
	if err != nil {
		err = fmt.Errorf("XXXspecialContext: could not get rewards proof (for %v) at %d: %v", rewardsPool, rnd, err)
		return
	}
	feepf, err = l.acctProofs.accountProof(rnd, feeSink)
	if err != nil {
		err = fmt.Errorf("XXXspecialContext: could not get fee sink proof (for %v) at %d: %v", feeSink, rnd, err)
		return
	}
	rwctx = asContext(rwpf.Address, rwpf)
	feectx = asContext(feepf.Address, feepf)
	return
}

// LookupProof implements agreement.Ledger.
func (l *Ledger) LookupProof(rnd basics.Round, addr basics.Address) (basics.AccountProof, error) {
	cached, f, err := l.lookupProof(rnd, addr)
	if err != nil {
		return basics.AccountProof{}, err
	}
	if (cached == basics.AccountProof{}) {
		return f.call(), nil
	}
	return cached, nil
}

func (l *Ledger) lookupProof(rnd basics.Round, addr basics.Address) (basics.AccountProof, vectorOpenFn, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	cached, err := l.acctProofs.accountProof(rnd, addr)
	if err == nil {
		return cached, vectorOpenFn{}, nil
	}

	if !l.archival {
		return basics.AccountProof{}, vectorOpenFn{}, ErrNotArchival
	}
	f, err := l.accts.accountProof(rnd, addr)
	return basics.AccountProof{}, f, err
}

// LookupPrevProof implements agreement.Ledger.
func (l *Ledger) LookupPrevProof(rnd basics.Round, addr basics.Address) (basics.AccountProof, error) {
	fn, err := l.lookupPrevProof(rnd, addr)
	if err != nil {
		return basics.AccountProof{}, err
	}
	return fn.call(), nil
}

func (l *Ledger) lookupPrevProof(rnd basics.Round, addr basics.Address) (vectorOpenFn, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	if !l.archival {
		return vectorOpenFn{}, ErrNotArchival
	}
	return l.accts.accountPrevProof(rnd, addr)
}

// CacheProof tells this Ledger to start durably tracking the given proof.
func (l *Ledger) CacheProof(pf basics.AccountProof) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()

	err := l.acctProofs.startTracking(pf)
	if err != nil {
		l.log.Infof("CacheProof: failed to start tracking proof %v: %v", pf, err)
	} else {
		l.log.Infof("CacheProof: as of round %d, started tracking proof of %v", pf.Round, pf.Address)
	}
}

// nextFreeSlot is guaranteed to _consistently_ (see lookupForEval) fail or succeed.
func (l *Ledger) nextFreeSlot(rnd basics.Round) (int, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.nextFreeSlot(rnd)
}

// Preimage returns the account slot preimages associated with a vector commitment.
func (l *Ledger) Preimage(rnd basics.Round, seq int) (basics.AccountChunk, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	if !l.archival {
		return basics.AccountChunk{}, ErrNotArchival
	}
	return l.accts.preimage(rnd, seq)
}

// Decommit returns an error if the given AccountChunk does not correspond to
// a valid vector.
func (l *Ledger) Decommit(chunk basics.AccountChunk) error {
	l.trackerMu.RLock()
	f, err := l.accts.decommit(chunk)
	l.trackerMu.RUnlock()

	if err != nil {
		return err
	}
	return f.call()
}

// NewChunks returns the new chunks the ledger has seen between two rounds
// and the maximum chunk sequence number it has seen last.
//
// It returns an error if it cannot compute these chunks.
func (l *Ledger) NewChunks(from, to basics.Round) (chunks []basics.AccountChunk, maxChunkSeq int, err error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.newChunks(from, to)
}

// UpdateChunk updates a chunk to a target round.
//
// It returns an error if it cannot compute the update.
func (l *Ledger) UpdateChunk(chunk basics.AccountChunk, to basics.Round) (basics.AccountChunk, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.updateChunk(chunk, to)
}

// // acctTail obtains the tail of unvalidated account proofs in a best-effort way.
// //
// // It may return an empty slice if there was insufficient time to obtain the tail.
// func (l *Ledger) acctTail(rnd basics.Round) basics.AccountTail {
// 	l.trackerMu.RLock()
// 	defer l.trackerMu.RUnlock()
// 	return l.accts.tail(rnd)
// }

func (l *Ledger) slotResidue(rnd basics.Round) (slotResidue, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.residue(rnd)
}

// Totals returns the totals of all accounts at the end of round rnd.
func (l *Ledger) Totals(rnd basics.Round) (AccountTotals, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.totals(rnd)
}

func (l *Ledger) isDup(firstValid basics.Round, lastValid basics.Round, txid transactions.Txid) (bool, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.txTail.isDup(firstValid, lastValid, txid)
}

// Latest returns the latest known block round added to the ledger.
func (l *Ledger) Latest() basics.Round {
	return l.blockQ.latest()
}

// LatestCommitted returns the last block round number written to
// persistent storage.  This block, and all previous blocks, are
// guaranteed to be available after a crash.
func (l *Ledger) LatestCommitted() basics.Round {
	return l.blockQ.latestCommitted()
}

// Committed uses the transaction tail tracker to check if txn already
// appeared in a block.
func (l *Ledger) Committed(txn transactions.SignedTxn) (bool, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.txTail.isDup(txn.Txn.First(), l.Latest(), txn.ID())
}

func (l *Ledger) blockAux(rnd basics.Round) (bookkeeping.Block, evalAux, error) {
	return l.blockQ.getBlockAux(rnd)
}

// Block returns the block for round rnd.
func (l *Ledger) Block(rnd basics.Round) (blk bookkeeping.Block, err error) {
	return l.blockQ.getBlock(rnd)
}

// BlockHdr returns the BlockHeader of the block for round rnd.
func (l *Ledger) BlockHdr(rnd basics.Round) (blk bookkeeping.BlockHeader, err error) {
	value, exists := l.headerCache.Get(rnd)
	if exists {
		blk = value.(bookkeeping.BlockHeader)
		return
	}

	blk, err = l.blockQ.getBlockHdr(rnd)
	if err == nil {
		l.headerCache.Put(rnd, blk)
	}
	return
}

// EncodedBlockCert returns the encoded block and the corresponding encodded certificate of the block for round rnd.
func (l *Ledger) EncodedBlockCert(rnd basics.Round) (blk []byte, cert []byte, err error) {
	return l.blockQ.getEncodedBlockCert(rnd)
}

// BlockCert returns the block and the certificate of the block for round rnd.
func (l *Ledger) BlockCert(rnd basics.Round) (blk bookkeeping.Block, cert agreement.Certificate, err error) {
	return l.blockQ.getBlockCert(rnd)
}

// AddBlock adds a new block to the ledger.  The block is stored in an
// in-memory queue and is written to the disk in the background.  An error
// is returned if this is not the expected next block number.
func (l *Ledger) AddBlock(blk bookkeeping.Block, cert agreement.Certificate) error {
	// passing nil as the verificationPool is ok since we've asking the evaluator to skip verification.
	updates, aux, err := l.eval(context.Background(), blk, nil, false, nil, nil)
	if err != nil {
		return err
	}

	vb := ValidatedBlock{
		blk:   blk,
		delta: updates,
		aux:   aux,
	}

	return l.AddValidatedBlock(vb, cert)
}

// AddValidatedBlock adds a new block to the ledger, after the block has
// been validated by calling Ledger.Validate().  This saves the cost of
// having to re-compute the effect of the block on the ledger state, if
// the block has previously been validated.  Otherwise, AddValidatedBlock
// behaves like AddBlock.
func (l *Ledger) AddValidatedBlock(vb ValidatedBlock, cert agreement.Certificate) error {
	// Grab the tracker lock first, to ensure newBlock() is notified before committedUpTo().
	l.trackerMu.Lock()
	defer l.trackerMu.Unlock()

	l.log.With("EXTPS", true).With("txns", len(vb.blk.Payset)).With("rnd", vb.blk.Round()).Infof("AddValidatedBlock: %d txns", len(vb.blk.Payset))

	err := l.blockQ.putBlock(vb.blk, cert, vb.aux)
	if err != nil {
		return err
	}

	l.trackers.newBlock(vb.blk, vb.delta)
	return nil
}

// WaitForCommit waits until block r (and block before r) are durably
// written to disk.
func (l *Ledger) WaitForCommit(r basics.Round) {
	l.blockQ.waitCommit(r)
}

// Wait returns a channel that closes once a given round is stored
// durably in the ledger.
// When <-l.Wait(r) finishes, ledger is guaranteed to have round r,
// and will not lose round r after a crash.
// This makes it easy to use in a select{} statement.
func (l *Ledger) Wait(r basics.Round) chan struct{} {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.bulletin.Wait(r)
}

// Timestamp uses the timestamp tracker to return the timestamp
// from block r.
func (l *Ledger) Timestamp(r basics.Round) (int64, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.time.timestamp(r)
}

// AllBalances returns a map of every account balance as of round rnd.
func (l *Ledger) AllBalances(rnd basics.Round) (map[basics.Address]basics.AccountData, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	if !l.archival {
		return nil, ErrNotArchival
	}
	return l.accts.allBalances(rnd)
}

// GenesisHash returns the genesis hash for this ledger.
func (l *Ledger) GenesisHash() crypto.Digest {
	return l.genesisHash
}

// ledgerForTracker methods
func (l *Ledger) trackerDB() dbPair {
	return l.trackerDBs
}

func (l *Ledger) trackerLog() logging.Logger {
	return l.log
}

func (l *Ledger) trackerEvalVerified(blk bookkeeping.Block, aux evalAux) (stateDelta, error) {
	// passing nil as the verificationPool is ok since we've asking the evaluator to skip verification.
	delta, _, err := l.eval(context.Background(), blk, &aux, false, nil, nil)
	return delta, err
}

// A VectorCommitmentDB is a store of vector commitments indexed by
// round and a sequence number.
type VectorCommitmentDB interface {
	Params() *vector.Parameters
	Get(rnd basics.Round, seq int) (vector.Commitment, error)
}

type ledgerVCDB Ledger

// VectorCommitments reinterpets the Ledger as a VectorCommitmentDB.
func (l *Ledger) VectorCommitments() VectorCommitmentDB {
	return (*ledgerVCDB)(l)
}

// vc is guaranteed to _consistently_ (see lookupForEval) fail or succeed.
func (l *ledgerVCDB) Get(rnd basics.Round, index int) (vector.Commitment, error) {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.vc(rnd, index)
}

// parameters returns the ledger's vector parameters
func (l *ledgerVCDB) Params() *vector.Parameters {
	l.trackerMu.RLock()
	defer l.trackerMu.RUnlock()
	return l.accts.parameters()
}

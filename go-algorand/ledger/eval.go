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
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/execpool"
)

// ErrNoSpace indicates insufficient space for transaction in block
var ErrNoSpace = errors.New("block does not have space for transaction")

// evalAux is left after removing explicit reward claims,
// in case we need this infrastructure in the future.
type evalAux struct {
}

// VerifiedTxnCache captures the interface for a cache of previously
// verified transactions.  This is expected to match the transaction
// pool object.
type VerifiedTxnCache interface {
	Verified(txn transactions.SignedTxn) (transactions.TransactionProof, bool)
}

type roundCowBase struct {
	l ledgerForEvaluator

	// The round number of the previous block, for looking up prior state.
	rnd basics.Round

	// The cache of the accountContext for the fee sink.
	feectx accountContext
}

func (x *roundCowBase) lookup(addr basics.Address, ctx accountContext) (basics.AccountData, accountContext, error) {
	if addr == x.feectx.curr.Address {
		return x.feectx.curr.AccountData, x.feectx, nil
	}

	return x.l.lookupForEval(x.rnd, addr, ctx)
}

func (x *roundCowBase) isDup(firstValid basics.Round, txid transactions.Txid) (bool, error) {
	return x.l.isDup(firstValid, x.rnd, txid)
}

// wrappers for roundCowState to satisfy the (current) transactions.Balances interface
func (cs *roundCowState) Get(addr basics.Address, pf basics.AccountProof) (basics.BalanceRecord, error) {
	acctdata, _, err := cs.lookup(addr, asContext(addr, pf))
	if err != nil {
		return basics.BalanceRecord{}, err
	}
	acctdata = acctdata.WithUpdatedRewards(cs.proto, cs.rewardsLevel())
	return basics.BalanceRecord{Addr: addr, AccountData: acctdata}, nil
}

func (cs *roundCowState) Put(record basics.BalanceRecord, pf basics.AccountProof) error {
	if (record.AccountData == basics.AccountData{}) {
		return fmt.Errorf("Put() cannot put empty AccountData; must use Clear() instead")
	}
	olddata, ctx, err := cs.lookup(record.Addr, asContext(record.Addr, pf))
	if err != nil {
		return err
	}
	cs.put(record.Addr, olddata, record.AccountData, ctx, pf)
	return nil
}

func (cs *roundCowState) getRewards(addr basics.Address, ctx accountContext) (basics.BalanceRecord, error) {
	acctdata, _, err := cs.lookup(addr, ctx)
	if err != nil {
		return basics.BalanceRecord{}, err
	}
	acctdata = acctdata.WithUpdatedRewards(cs.proto, cs.rewardsLevel())
	return basics.BalanceRecord{Addr: addr, AccountData: acctdata}, nil
}

func (cs *roundCowState) putRewards(record basics.BalanceRecord, ctx accountContext) error {
	olddata, ctx, err := cs.lookup(record.Addr, ctx)
	if err != nil {
		return err
	}
	cs.put(record.Addr, olddata, record.AccountData, ctx, basics.AccountProof{})
	return nil
}

func (cs *roundCowState) Clear(addr basics.Address, curr basics.AccountProof, prev basics.AccountProof) error {
	currctx := asContext(addr, curr)
	prevctx := asContext(addr, prev)
	currctx.prev = prevctx.prev

	olddata, ctx, err := cs.lookup(addr, currctx)
	if err != nil {
		return err
	}

	cs.put(addr, olddata, basics.AccountData{}, ctx, curr)
	return nil
}

// TODO what if Move closes from?
func (cs *roundCowState) Move(from basics.Address, to basics.Address, fromPf basics.AccountProof, toPf basics.AccountProof, amt basics.MicroAlgos, fromRewards *basics.MicroAlgos, toRewards *basics.MicroAlgos) error {
	rewardlvl := cs.rewardsLevel()

	fromBal, fromCtx, err := cs.lookup(from, asContext(from, fromPf))
	if err != nil {
		return err
	}
	fromBalNew := fromBal.WithUpdatedRewards(cs.proto, rewardlvl)

	if fromRewards != nil {
		var ot basics.OverflowTracker
		newFromRewards := ot.AddA(*fromRewards, ot.SubA(fromBalNew.MicroAlgos, fromBal.MicroAlgos))
		if ot.Overflowed {
			return fmt.Errorf("overflowed tracking of fromRewards for account %v: %d + (%d - %d)", from, *fromRewards, fromBalNew.MicroAlgos, fromBal.MicroAlgos)
		}
		*fromRewards = newFromRewards
	}

	var overflowed bool
	fromBalNew.MicroAlgos, overflowed = basics.OSubA(fromBalNew.MicroAlgos, amt)
	if overflowed {
		return fmt.Errorf("overspend (account %v, data %+v, tried to spend %v)", from, fromBal, amt)
	}
	cs.put(from, fromBal, fromBalNew, fromCtx, fromPf)

	toBal, toCtx, err := cs.lookup(to, asContext(to, toPf))
	if err != nil {
		return err
	}
	toBalNew := toBal.WithUpdatedRewards(cs.proto, rewardlvl)

	if toRewards != nil {
		var ot basics.OverflowTracker
		newToRewards := ot.AddA(*toRewards, ot.SubA(toBalNew.MicroAlgos, toBal.MicroAlgos))
		if ot.Overflowed {
			return fmt.Errorf("overflowed tracking of toRewards for account %v: %d + (%d - %d)", to, *toRewards, toBalNew.MicroAlgos, toBal.MicroAlgos)
		}
		*toRewards = newToRewards
	}

	toBalNew.MicroAlgos, overflowed = basics.OAddA(toBalNew.MicroAlgos, amt)
	if overflowed {
		return fmt.Errorf("balance overflow (account %v, data %+v, was going to receive %v)", to, toBal, amt)
	}
	cs.put(to, toBal, toBalNew, toCtx, toPf)

	return nil
}

func (cs *roundCowState) ConsensusParams() config.ConsensusParams {
	return cs.proto
}

// BlockEvaluator represents an in-progress evaluation of a block
// against the ledger.
type BlockEvaluator struct {
	state    *roundCowState
	aux      *evalAux
	validate bool
	generate bool
	txcache  VerifiedTxnCache

	prevHeader  bookkeeping.BlockHeader // cached
	proto       config.ConsensusParams
	genesisHash crypto.Digest

	block        bookkeeping.Block
	totalTxBytes int

	nextFreeSlot int
	residue      slotResidue
	tail         basics.AccountTail // TODO this should be a type to enforce the invariant that slots go in ascending order and also that there are a multiple of vsize number of slots

	vcdb VectorCommitmentDB

	verificationPool execpool.BacklogPool
}

type ledgerForEvaluator interface {
	GenesisHash() crypto.Digest
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	Lookup(basics.Round, basics.Address) (basics.AccountData, error)
	Totals(basics.Round) (AccountTotals, error)
	VectorCommitments() VectorCommitmentDB
	isDup(basics.Round, basics.Round, transactions.Txid) (bool, error)
	lookupForEval(basics.Round, basics.Address, accountContext) (basics.AccountData, accountContext, error)
	nextFreeSlot(basics.Round) (int, error)
	slotResidue(basics.Round) (slotResidue, error)
	// acctTail(basics.Round) basics.AccountTail
	XXXspecialContext(rnd basics.Round, rewardsPool basics.Address, feeSink basics.Address) (accountContext, accountContext, error)
}

// StartEvaluator creates a BlockEvaluator, given a ledger and a block header
// of the block that the caller is planning to evaluate.
//
// tail should be the tail of account slots in increasing order, and it should
// have been verified.
func (l *Ledger) StartEvaluator(hdr bookkeeping.BlockHeader, tail basics.AccountTail, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (*BlockEvaluator, error) {
	return startEvaluator(l, hdr, tail, true, nil, true, true, txcache, executionPool)
}

func startEvaluator(l ledgerForEvaluator, hdr bookkeeping.BlockHeader, tail basics.AccountTail, tailTrusted bool, aux *evalAux, validate bool, generate bool, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (*BlockEvaluator, error) {
	proto, ok := config.Consensus[hdr.CurrentProtocol]
	if !ok {
		return nil, ProtocolError(hdr.CurrentProtocol)
	}

	if aux == nil {
		aux = &evalAux{}
	}

	base := &roundCowBase{
		l: l,
		// round that lookups come from is previous block.  We validate
		// the block at this round below, so underflow will be caught.
		// If we are not validating, we must have previously checked
		// an agreement.Certificate attesting that hdr is valid.
		rnd: hdr.Round - 1,
	}

	nextSlot, err := l.nextFreeSlot(hdr.Round - 1)
	if err != nil {
		return nil, fmt.Errorf("can't get next free slot in round %d: %v", hdr.Round-1, err)
	}

	residue, err := l.slotResidue(hdr.Round - 1)
	if err != nil {
		return nil, fmt.Errorf("can't get slot residue in round %d: %v", hdr.Round-1, err)
	}

	eval := &BlockEvaluator{
		aux:              aux,
		validate:         validate,
		generate:         generate,
		txcache:          txcache,
		nextFreeSlot:     nextSlot,
		block:            bookkeeping.Block{BlockHeader: hdr},
		proto:            proto,
		genesisHash:      l.GenesisHash(),
		verificationPool: executionPool,
		tail:             tail,
		residue:          residue,
		vcdb:             l.VectorCommitments(),
	}

	if hdr.Round > 0 {
		var err error
		eval.prevHeader, err = l.BlockHdr(base.rnd)
		if err != nil {
			return nil, fmt.Errorf("can't evaluate block %v without previous header: %v", hdr.Round, err)
		}
	}

	// set the eval state with the current header
	eval.state = makeRoundCowState(base, eval.vcdb, eval.block.BlockHeader)

	if validate {
		err := eval.block.BlockHeader.PreCheck(eval.prevHeader)
		if err != nil {
			return nil, err
		}

		if !tailTrusted {
			err = validateSlotTail(eval.vcdb, eval.prevHeader.Round, eval.tail, eval.nextFreeSlot)
			if err != nil {
				return nil, fmt.Errorf("could not validate slot tail: %v", err)
			}
		}
	}

	return eval, nil
}

// Round returns the round number of the block being evaluated by the BlockEvaluator.
func (eval *BlockEvaluator) Round() basics.Round {
	return eval.block.Round()
}

// ResetTxnBytes resets the number of bytes tracked by the BlockEvaluator to
// zero.  This is a specialized operation used by the transaction pool to
// simulate the effect of putting pending transactions in multiple blocks.
func (eval *BlockEvaluator) ResetTxnBytes() {
	eval.totalTxBytes = 0
}

// Transaction tentatively adds a new transaction as part of this block evaluation.
// If the transaction cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.
func (eval *BlockEvaluator) Transaction(txn transactions.SignedTxn, pf transactions.TransactionProof) error {
	return eval.transaction(txn, pf, true)
}

// TestTransaction checks if a given transaction could be executed at this point
// in the block evaluator, but does not actually add the transaction to the block
// evaluator, or modify the block evaluator state in any other visible way.
func (eval *BlockEvaluator) TestTransaction(txn transactions.SignedTxn, pf transactions.TransactionProof) error {
	return eval.transaction(txn, pf, false)
}

// transaction tentatively executes a new transaction as part of this block evaluation.
// If the transaction cannot be added to the block without violating some constraints,
// an error is returned and the block evaluator state is unchanged.  If remember is true,
// the transaction is added to the block evaluator state; otherwise, the block evaluator
// is not modified and does not remember this transaction.
func (eval *BlockEvaluator) transaction(txn transactions.SignedTxn, cachedPf transactions.TransactionProof, remember bool) error {
	var err error
	var thisTxBytes int
	cow := eval.state.child()

	spec := transactions.SpecialAddresses{
		FeeSink:     eval.block.BlockHeader.FeeSink,
		RewardsPool: eval.block.BlockHeader.RewardsPool,
	}

	var txnpf transactions.TransactionProof
	if eval.validate {
		// Transaction valid (not expired)?
		err = txn.Txn.Alive(eval.block)
		if err != nil {
			return err
		}

		// Transaction already in the ledger?
		dup, err := cow.isDup(txn.Txn.First(), txn.ID())
		if err != nil {
			return err
		}
		if dup {
			return TransactionInLedgerError{txn.ID()}
		}

		// Well-formed on its own?
		err = txn.Txn.WellFormed(spec, eval.proto)
		if err != nil {
			return fmt.Errorf("transaction %v: malformed: %v", txn.ID(), err)
		}

		// Properly signed?
		cached := false
		if (cachedPf != transactions.TransactionProof{}) {
			txnpf = cachedPf
			cached = true
		} else if eval.txcache != nil {
			txnpf, cached = eval.txcache.Verified(txn)
		}
		if !cached {
			err = txn.PoolVerify(spec, eval.proto, eval.verificationPool)
			if err != nil {
				return fmt.Errorf("transaction %v: failed to verify signature: %v", txn.ID(), err)
			}

			// txnpf, err = txn.ValidateProof(eval.vcdb, spec)
			txnpf, err = txn.PoolValidateProof(eval.vcdb, spec, eval.verificationPool)
			if err != nil {
				return fmt.Errorf("transaction %v: failed to verify account proof: %v", txn.ID(), err)
			}
		}
	} else {
		if (cachedPf != transactions.TransactionProof{}) {
			txnpf = cachedPf
		} else {
			txnpf, err = txn.UnsafeDecodeProof(eval.vcdb, eval.verificationPool)
			// TODO it might be worth caching this
			if err != nil {
				return fmt.Errorf("transaction %v: failed to decode account proof: %v", txn.ID(), err)
			}
		}
	}

	// Apply the transaction, updating the cow balances
	err = txn.Txn.Apply(cow, txnpf, spec)
	if err != nil {
		return fmt.Errorf("transaction %v: %v", txn.ID(), err)
	}

	// There may not be enough account slots in the tail to
	// close an account.
	budget := slotDeletionsRemaining(eval.vcdb.Params(), eval.tail, eval.residue)
	deleteCost := cow.mods.pendingDeletions()
	if deleteCost > budget {
		return fmt.Errorf("transaction %v: insufficient budget to delete account: %d > %d", txn.ID(), deleteCost, budget)
	}

	// Check if any affected accounts dipped below MinBalance (unless they are
	// completely zero, which means the account will be deleted.)
	for _, addr := range cow.modifiedAccounts() {
		data, _, err := cow.lookup(addr, accountContext{}) // accounts in cow.modifiedAccounts guaranteed to not need proofs
		if err != nil {
			return err
		}

		// It's always OK to have the account move to an empty state,
		// because the accounts DB can delete it.  Otherwise, we will
		// enforce MinBalance.
		if data == (basics.AccountData{}) {
			continue
		}
	}

	if remember {
		// Remember this TXID (to detect duplicates)
		cow.addTx(txn.ID())

		eval.block.Payset = append(eval.block.Payset, txn)
		eval.totalTxBytes += thisTxBytes
		cow.commitToParent()
	}

	return nil
}

// Call "endOfBlock" after all the block's rewards and transactions are processed. Applies any deferred balance updates and computes the new slot and vector deltas.
func (eval *BlockEvaluator) endOfBlock() error {
	err := eval.state.resolveSlotUpdates(eval.prevHeader.Round, eval.nextFreeSlot, eval.residue, eval.tail)
	if err != nil {
		return err
	}

	if eval.generate {
		budget := slotDeletionsRemaining(eval.vcdb.Params(), eval.tail, eval.residue)
		deleteCost := eval.state.mods.pendingDeletions()

		// TODO assert that the tail is a multiple of vector size here?

		// invariant budget >= deleteCost was maintained during transaction()
		vsize := int(eval.vcdb.Params().VectorSize)
		for budget-vsize > deleteCost && eval.tail.Size() > 0 {
			eval.tail = eval.tail.DropFirstVector(eval.vcdb.Params())
			budget = slotDeletionsRemaining(eval.vcdb.Params(), eval.tail, eval.residue)
		}

		eval.block.SlotTail = eval.tail
		eval.block.TxnRoot = eval.block.Payset.Commit(eval.proto.PaysetCommitFlat)
		// TODO balance commit here
	}
	return nil
}

// FinalValidation does the validation that must happen after the block is built and all state updates are computed
func (eval *BlockEvaluator) finalValidation() error {
	if eval.validate {
		// check commitments
		txnRoot := eval.block.Payset.Commit(eval.proto.PaysetCommitFlat)
		if txnRoot != eval.block.TxnRoot {
			return fmt.Errorf("txn root wrong: %v != %v", txnRoot, eval.block.TxnRoot)
		}
		// TODO balance commit here
	}

	return nil
}

// GenerateBlock produces a complete block from the BlockEvaluator.  This is
// used during proposal to get an actual block that will be proposed, after
// feeding in tentative transactions into this block evaluator.
func (eval *BlockEvaluator) GenerateBlock() (*ValidatedBlock, error) {
	if !eval.generate {
		logging.Base().Panicf("GenerateBlock() called but generate is false")
	}

	err := eval.endOfBlock()
	if err != nil {
		return nil, err
	}

	err = eval.finalValidation()
	if err != nil {
		return nil, err
	}

	vb := ValidatedBlock{
		blk:   eval.block,
		delta: eval.state.mods,
		aux:   *eval.aux,
	}
	return &vb, nil
}

func (l *Ledger) eval(ctx context.Context, blk bookkeeping.Block, aux *evalAux, validate bool, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (stateDelta, evalAux, error) {
	tailTrusted := !validate
	eval, err := startEvaluator(l, blk.BlockHeader, blk.SlotTail, tailTrusted, aux, validate, false, txcache, executionPool)
	if err != nil {
		return stateDelta{}, evalAux{}, err
	}

	// TODO: batch tx sig verification: ingest blk.Payset and output a list of ValidatedTx
	// Next, transactions
	payset := blk.Payset
	for _, txn := range payset {
		select {
		case <-ctx.Done():
			return stateDelta{}, evalAux{}, ctx.Err()
		default:
		}

		err = eval.Transaction(txn, transactions.TransactionProof{})
		if err != nil {
			return stateDelta{}, evalAux{}, err
		}
	}

	// Finally, procees any pending end-of-block state changes
	err = eval.endOfBlock()
	if err != nil {
		return stateDelta{}, evalAux{}, err
	}

	// If validating, do final block checks that depend on our new state
	if validate {
		err = eval.finalValidation()
		if err != nil {
			return stateDelta{}, evalAux{}, err
		}
	}

	return eval.state.mods, *eval.aux, nil
}

// Validate uses the ledger to validate block blk as a candidate next block.
// It returns an error if blk is not the expected next block, or if blk is
// not a valid block (e.g., it has duplicate transactions, overspends some
// account, etc).
func (l *Ledger) Validate(ctx context.Context, blk bookkeeping.Block, txcache VerifiedTxnCache, executionPool execpool.BacklogPool) (*ValidatedBlock, error) {
	delta, aux, err := l.eval(ctx, blk, nil, true, txcache, executionPool)
	if err != nil {
		return nil, err
	}

	vb := ValidatedBlock{
		blk:   blk,
		delta: delta,
		aux:   aux,
	}
	return &vb, nil
}

// ValidatedBlock represents the result of a block validation.  It can
// be used to efficiently add the block to the ledger, without repeating
// the work of applying the block's changes to the ledger state.
type ValidatedBlock struct {
	blk   bookkeeping.Block
	delta stateDelta
	aux   evalAux
}

// Block returns the underlying Block for a ValidatedBlock.
func (vb ValidatedBlock) Block() bookkeeping.Block {
	return vb.blk
}

// WithSeed returns a copy of the ValidatedBlock with a modified seed.
func (vb ValidatedBlock) WithSeed(s committee.Seed) ValidatedBlock {
	newblock := vb.blk
	newblock.BlockHeader.Seed = s

	return ValidatedBlock{
		blk:   newblock,
		delta: vb.delta,
		aux:   vb.aux,
	}
}

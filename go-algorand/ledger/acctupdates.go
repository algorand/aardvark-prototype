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
	"database/sql"
	"fmt"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/vector"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
)

// A modifiedAccount represents an account that has been modified since
// the persistent state stored in the account DB (i.e., in the range of
// rounds covered by the accountUpdates tracker).
type modifiedAccount struct {
	// data stores the most recent AccountData for this modified
	// account.
	data basics.AccountData

	// ndelta keeps track of how many times this account appears in
	// accountUpdates.deltas.  This is used to evict modifiedAccount
	// entries when all changes to an account have been reflected in
	// the account DB, and no outstanding modifications remain.
	ndeltas int
}

type accountUpdates struct {
	// Connection to the database.
	dbs dbPair

	// Prepared SQL statements for fast accounts DB lookups.
	accountsq *accountsDbQueries

	// Prepared SQL statements for fast commitment DB lookups.
	veccomq *veccomDbQueries

	// Vector commitment parameters.
	vparams *vector.Parameters

	// dbRound is always exactly accountsRound(),
	// cached to avoid SQL queries.
	dbRound basics.Round

	// nextSlot is the next available slot in the accounts DB,
	// for dbRound and one for every round after it, cached
	// to avoid SQL queries.
	nextSlot []int

	// deltas stores updates for every round after dbRound.
	deltas []map[basics.Address]accountDelta

	// vcdeltas stores updates for every round after dbRound.
	vcdeltas []map[int]veccomDelta

	// slotdeltas stores slot updates for every round after dbRound.
	slotdeltas []slotDelta

	// accounts stores the most recent account state for every
	// address that appears in deltas.
	accounts map[basics.Address]modifiedAccount

	// protos stores consensus parameters dbRound and every
	// round after it; i.e., protos is one longer than deltas.
	protos []config.ConsensusParams

	// totals stores the totals for dbRound and every round after it;
	// i.e., totals is one longer than deltas.
	roundTotals []AccountTotals

	// slotResidues stores residual slots dbRound and every round after it;
	// i.e., slotResidues is one longer than deltas.
	slotResidues []slotResidue

	// initAccounts specifies initial account values for database.
	initAccounts map[basics.Address]basics.AccountData

	// initProto specifies the initial consensus parameters.
	initProto config.ConsensusParams

	// log copied from ledger
	log logging.Logger

	// lastFlushTime is the time we last flushed updates to
	// the accounts DB (bumping dbRound).
	lastFlushTime time.Time
}

func (au *accountUpdates) loadFromDisk(l ledgerForTracker) error {
	au.dbs = l.trackerDB()
	au.log = l.trackerLog()
	au.vparams = vector.MakeParameters(au.initProto.AccountVectorSize)

	if au.initAccounts == nil {
		return fmt.Errorf("accountUpdates.loadFromDisk: initAccounts not set")
	}

	err := au.dbs.wdb.Atomic(func(tx *sql.Tx) error {
		var err0 error
		err0 = accountsInit(tx, au.initAccounts, au.initProto, au.vparams)
		if err0 != nil {
			return err0
		}

		err0 = veccomInit(tx, au.initAccounts, au.initProto, au.vparams)
		if err0 != nil {
			return err0
		}

		var residue slotResidue
		au.dbRound, residue, err0 = accountsRound(tx)
		if err0 != nil {
			return err0
		}
		au.slotResidues = []slotResidue{residue}

		totals, err0 := accountsTotals(tx)
		if err0 != nil {
			return err0
		}
		au.roundTotals = []AccountTotals{totals}

		nextSlot, err0 := veccomNextFree(tx)
		if err0 != nil {
			return err0
		}
		au.nextSlot = []int{nextSlot}

		return nil
	})
	if err != nil {
		return err
	}

	au.accountsq, err = accountsDbInit(au.dbs.rdb.Handle)
	if err != nil {
		return err
	}

	au.veccomq, err = veccomDbInit(au.dbs.rdb.Handle)
	if err != nil {
		return err
	}

	hdr, err := l.BlockHdr(au.dbRound)
	if err != nil {
		return err
	}
	au.protos = []config.ConsensusParams{config.Consensus[hdr.CurrentProtocol]}

	latest := l.Latest()
	au.deltas = nil
	au.vcdeltas = nil
	au.slotdeltas = nil
	au.accounts = make(map[basics.Address]modifiedAccount)
	loaded := au.dbRound
	for loaded < latest {
		next := loaded + 1

		blk, aux, err := l.blockAux(next)
		if err != nil {
			return err
		}

		delta, err := l.trackerEvalVerified(blk, aux)
		if err != nil {
			return err
		}

		au.newBlock(blk, delta)
		loaded = next
	}

	return nil
}

func (au *accountUpdates) close() {
}

func (au *accountUpdates) roundOffset(rnd basics.Round) (offset uint64, err error) {
	if rnd < au.dbRound {
		err = fmt.Errorf("round %d before dbRound %d", rnd, au.dbRound)
		return
	}

	off := uint64(rnd - au.dbRound)
	if off > uint64(len(au.deltas)) {
		err = fmt.Errorf("round %d too high: dbRound %d, deltas %d", rnd, au.dbRound, len(au.deltas))
		return
	}

	return off, nil
}

func (au *accountUpdates) latest() basics.Round {
	return au.dbRound + basics.Round(len(au.deltas))
}

func (au *accountUpdates) applyRewards(rnd basics.Round, data basics.AccountData) (basics.AccountData, error) {
	offsetForRewards, err := au.roundOffset(rnd)
	if err != nil {
		return basics.AccountData{}, err
	}
	totals := au.roundTotals[offsetForRewards]
	proto := au.protos[offsetForRewards]
	return data.WithUpdatedRewards(proto, totals.RewardsLevel), nil
}

// A forkSafeLookupResult is guaranteed to be consistent on all correct nodes
// given a round and address.
type forkSafeLookupResult struct {
	curr slotContext
	cok  bool

	prev slotContext
	pok  bool
}

func (r forkSafeLookupResult) String() string {
	return fmt.Sprintf("{cok: %v, pok: %v, curr: %v, prev: %v}", r.cok, r.pok, r.curr, r.prev)
}

// forkSafeLookup searches for the slotContext for the address's current and
// (logical-)previous slots in the recent slot updates, returning a negative
// result if it cannot find one or both.
//
// claim is a context which could be a fresher version of the desired
// accountContext.
//
// If forkSafeLookupResult.pok is true, forkSafeLookupResult.cok is also true.
//
// forkSafeLookup is guaranteed to have consistent results across nodes which
// are up-to-date.
func (au *accountUpdates) forkSafeLookup(rnd basics.Round, addr basics.Address, withRewards bool, claim accountContext) (res forkSafeLookupResult) {
	defer func() {
		if withRewards {
			cdata, err1 := au.applyRewards(rnd, res.curr.AccountData)
			pdata, err2 := au.applyRewards(rnd, res.prev.AccountData)
			if err1 != nil || err2 != nil {
				res = forkSafeLookupResult{}
			} else {
				if res.cok {
					res.curr.AccountData = cdata
				}
				if res.pok {
					res.prev.AccountData = pdata
				}
			}
		}
	}()

	offset, err := au.roundOffset(rnd)
	if err != nil {
		return
	}

	// Check if the account has been updated recently.  Traverse the deltas
	// backwards to ensure that later updates take priority if present.
	firstGuaranteed := offset - au.protos[offset].MaxTxnLife
	if au.protos[offset].MaxTxnLife > offset {
		firstGuaranteed = 0
	}
	for offset > firstGuaranteed {
		offset--
		ok := au.slotdeltas[offset].modified(addr)
		if ok {
			d, ok := au.deltas[offset][addr]
			if ok && d.new == (basics.AccountData{}) {
				// addr was deleted at offset
				res.curr = slotContext{}
				res.cok = true

				res.prev, res.pok = au.forkSafeLookupPrev(rnd, addr) // claim.curr does not exist for rounds past offset; might or might not exist for rounds before offset
				if !res.pok {
					panic("(delete) could not find slotdelta in modified account delta")
				}
				return
			}

			// addr must exist at offset
			sd := au.slotdeltas[offset]
			c, err := sd.lookupContext(addr)
			if err != nil {
				fmt.Println("lookupContext issued on", addr)
				fmt.Println("returned error is", err)
				panic("lookupContext failed on address in slotdeltas, but address exists and was modified in slotdeltas")
			}
			res.curr = c
			res.cok = true

			res.prev, res.pok = au.forkSafeLookupPrev(rnd, addr) // claim.curr exists for rounds past offset; might or might not exist for rounds before offset
			return
		}
	}

	// curr not modified in memory, so claim.curr is fresh
	// if claim.curr is empty, claim.prev has prev slot
	// else claim.curr has freshest address, so use that to find prev slot
	// once have prev slot, latest update is freshest update
	res.curr = claim.curr
	res.cok = true
	if claim.curr.Address == addr {
		res.prev, res.pok = au.forkSafeLookupPrev(rnd, addr) // claim.curr exists for all mem rounds
		return
	}

	res.prev, res.pok = au.forkSafeLookupPrev(rnd, addr) // claim.curr does not exist for all mem rounds
	return
}

func (au *accountUpdates) forkSafeLookupPrev(rnd basics.Round, addr basics.Address) (slotContext, bool) {
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return slotContext{}, false
	}

	// Check if the account has been updated recently.  Traverse the deltas
	// backwards to ensure that later updates take priority if present.
	firstGuaranteed := offset - au.protos[offset].MaxTxnLife
	if au.protos[offset].MaxTxnLife > offset {
		firstGuaranteed = 0
	}
	for offset > firstGuaranteed {
		offset--
		sd := au.slotdeltas[offset]
		p, err := sd.lookupPrevExists(addr)
		if err == nil {
			return p, true
		}
		p, err = sd.lookupPrevNotExists(addr) // can happen if addr was created after offset
		if err == nil {
			return p, true
		}
	}
	return slotContext{}, false
}

func (au *accountUpdates) lookup(rnd basics.Round, addr basics.Address, withRewards bool) (data basics.AccountData, err error) {
	defer func() {
		if withRewards {
			data, err = au.applyRewards(rnd, data)
		}
	}()

	offset, err := au.roundOffset(rnd)
	if err != nil {
		return
	}

	// Check if this is the most recent round, in which case, we can
	// use a cache of the most recent account state.
	if offset == uint64(len(au.deltas)) {
		macct, ok := au.accounts[addr]
		if ok {
			return macct.data, nil
		}
	} else {
		// Check if the account has been updated recently.  Traverse the deltas
		// backwards to ensure that later updates take priority if present.
		for offset > 0 {
			offset--
			d, ok := au.deltas[offset][addr]
			if ok {
				return d.new, nil
			}
		}
	}

	// No updates of this account in the in-memory deltas; use on-disk DB.
	// The check in roundOffset() made sure the round is exactly the one
	// present in the on-disk DB.  As an optimization, we avoid creating
	// a separate transaction here, and directly use a prepared SQL query
	// against the database.
	return au.accountsq.lookup(addr)
}

type vectorOpenFn struct {
	vparams  *vector.Parameters
	preimg   []crypto.Digest
	position int

	rnd  basics.Round
	slot basics.AccountSlot
}

func (f vectorOpenFn) call() basics.AccountProof {
	vcpf := vector.Open(f.vparams, f.preimg, f.position%int(f.vparams.VectorSize))
	return basics.AccountProof{AccountSlot: f.slot, Proof: vcpf, Position: f.position, Round: f.rnd}
}

// archival
func (au *accountUpdates) accountProof(rnd basics.Round, addr basics.Address) (vectorOpenFn, error) {
	currpf, err := au.open(rnd, addr)
	if err == nil {
		return currpf, nil
	} else if err != errAccountZero {
		return vectorOpenFn{}, err
	}

	prev, err := au.predecessor(rnd, addr)
	if err != nil {
		return vectorOpenFn{}, err
	}
	return au.open(rnd, prev)
}

// archival
func (au *accountUpdates) accountPrevProof(rnd basics.Round, addr basics.Address) (vectorOpenFn, error) {
	prev, err := au.predecessor(rnd, addr)
	if err != nil {
		return vectorOpenFn{}, err
	}
	return au.open(rnd, prev)
}

var errAccountZero = fmt.Errorf("account has zero balance")

func (au *accountUpdates) open(rnd basics.Round, addr basics.Address) (vectorOpenFn, error) {
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return vectorOpenFn{}, err
	}

	// obtain position and slot of addr as of rnd
	slot, pos, err := au.slotOfAddr(rnd, addr)
	if err != nil {
		if err == errLookupContextSlotDeleted {
			err = errAccountZero
		}
		return vectorOpenFn{}, err
	}
	if (slot == basics.AccountSlot{}) {
		return vectorOpenFn{}, errAccountZero
	}

	// fill in preimage using position as of rnd
	vsize := int(au.vparams.VectorSize)
	preimgBot := (pos / vsize) * vsize
	psize := vsize
	dbtop := au.nextSlot[offset]
	if preimgBot+vsize > dbtop {
		psize = dbtop - preimgBot
	}

	preimg := make([]crypto.Digest, vsize)
	for i := 0; i < psize; i++ { // leave [psize, vsize) with empty crypto.Digest
		ppos := preimgBot + i
		if ppos == pos {
			preimg[i] = slotDigest(slot)
			continue
		}

		s, err := au.slot(rnd, ppos)
		if err != nil {
			return vectorOpenFn{}, err
		}

		preimg[i] = slotDigest(s)
	}

	return vectorOpenFn{
		vparams:  au.vparams,
		preimg:   preimg,
		position: pos,
		rnd:      rnd,
		slot:     slot,
	}, nil
}

func (au *accountUpdates) slotOfAddr(rnd basics.Round, addr basics.Address) (s basics.AccountSlot, pos int, err error) {
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return
	}

	for offset > 0 {
		offset--
		sd := au.slotdeltas[offset]
		ok := sd.modified(addr)
		if ok {
			var sc slotContext
			sc, err = sd.lookupContext(addr)
			if err == nil {
				return sc.AccountSlot, sc.position, nil
			} else if err == errLookupContextSlotDeleted {
				return
			}
			panic("lookupContext failed on address in slotdeltas, but address was modified in slotdeltas")
		}
	}
	return au.accountsq.lookupSlotOfAddr(addr)
}

func (au *accountUpdates) slot(rnd basics.Round, pos int) (s basics.AccountSlot, err error) {
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return
	}

	for offset > 0 {
		offset--
		sd := au.slotdeltas[offset]
		s, ok := sd.new[pos]
		if ok {
			return s, nil
		}
	}
	return au.accountsq.lookupSlot(pos)
}

func (au *accountUpdates) predecessor(rnd basics.Round, addr basics.Address) (pred basics.Address, err error) {
	sc, ok := au.forkSafeLookupPrev(rnd, addr)
	if ok {
		return sc.Address, nil
	}

	return au.accountsq.lookupPred(addr)
}

// archival
func (au *accountUpdates) preimage(rnd basics.Round, seq int) (basics.AccountChunk, error) {
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return basics.AccountChunk{}, err
	}

	bottom := seq * int(au.vparams.VectorSize)
	top := bottom + int(au.vparams.VectorSize)
	if top > au.nextSlot[offset] {
		top = au.nextSlot[offset]
	}

	slots := make([]basics.AccountSlot, top-bottom)
	for i := bottom; i < top; i++ {
		s, err := au.slot(rnd, i)
		if err != nil {
			return basics.AccountChunk{}, err
		}
		slots[i-bottom] = s
	}
	return basics.AccountChunk{
		Round: rnd,
		Seq:   seq,
		Slots: slots,
	}, nil
}

func (au *accountUpdates) verify(addr basics.Address, pf basics.UnvalidatedAccountProof) (f vectorVerifyFn, err error) {
	claimZero := pf.Address != addr
	if claimZero {
		if !pf.Surrounds(addr) {
			err = fmt.Errorf("!pf.Prev.Surrounds(addr): ![%v, %v].Surrounds(%v)", pf.Address, pf.Next, addr)
			return
		}
	}

	com, err := au.commitment(pf.Round, pf.Position)
	if err != nil {
		return
	}

	f.vparams = au.vparams
	f.com = com
	f.pf = pf
	f.addr = addr
	return
}

type vectorVerifyFn struct {
	vparams *vector.Parameters
	com     vector.Commitment
	pf      basics.UnvalidatedAccountProof
	addr    basics.Address
}

func (f vectorVerifyFn) call() (okpf basics.AccountProof, data basics.AccountData, err error) {
	okpf, ok := f.pf.Verify(f.vparams, f.com)
	if !ok {
		err = fmt.Errorf("account proof failed to verify")
		return
	}
	if f.pf.Address == f.addr {
		data = f.pf.AccountData
	}
	return
}

func (au *accountUpdates) commitment(rnd basics.Round, position int) (com vector.Commitment, err error) {
	return au.vc(rnd, position/int(au.vparams.VectorSize))
}

type vectorDecommitFn struct {
	vparams  *vector.Parameters
	expected vector.Commitment
	chunk    basics.AccountChunk
}

func (f vectorDecommitFn) call() error {
	vsize := int(f.vparams.VectorSize)
	preimage := make([]crypto.Digest, vsize)
	for i := range preimage {
		preimage[i] = slotDigest(f.chunk.Slots[i])
	}
	com := vector.Commit(f.vparams, preimage)

	if com.ToBytes() != f.expected.ToBytes() {
		return fmt.Errorf("vector decommitment does not match expected value")
	}
	return nil
}

func (au *accountUpdates) decommit(chunk basics.AccountChunk) (vectorDecommitFn, error) {
	vsize := int(au.vparams.VectorSize)
	if len(chunk.Slots) != vsize {
		return vectorDecommitFn{}, fmt.Errorf("len(chunk.Slots) %d != vsize %d", len(chunk.Slots), vsize)
	}
	com, err := au.vc(chunk.Round, chunk.Seq)
	if err != nil {
		return vectorDecommitFn{}, err
	}
	return vectorDecommitFn{vparams: au.vparams, chunk: chunk, expected: com}, nil
}

func (au *accountUpdates) newChunks(from, to basics.Round) (chunks []basics.AccountChunk, maxChunkSeq int, err error) {
	startOffset, err := au.roundOffset(from)
	if err != nil {
		return
	}

	endOffset, err := au.roundOffset(to)
	if err != nil {
		return nil, 0, err
	}

	startNextFreeSlot := au.nextSlot[startOffset]
	endNextFreeSlot := au.nextSlot[endOffset]

	vsize := int(au.vparams.VectorSize)
	lowestChunkBottom := (startNextFreeSlot / vsize) * vsize
	highestChunkTop := (endNextFreeSlot / vsize) * vsize

	for i := lowestChunkBottom; i < highestChunkTop; i += vsize {
		var chunk basics.AccountChunk
		chunk.Seq = i / vsize
		chunk.Round = to

		for j := i; j < i+vsize; j++ {
			s, ok := au.lookupRecentSlot(to, j)
			if !ok {
				return nil, 0, fmt.Errorf("could not find recent new chunk")
			}
			chunk.Slots = append(chunk.Slots, s)
		}
		chunks = append(chunks, chunk)
	}

	maxChunkSeq = (highestChunkTop / vsize) - 1
	return
}

func (au *accountUpdates) updateChunk(chunk basics.AccountChunk, to basics.Round) (basics.AccountChunk, error) {
	_, err := au.roundOffset(chunk.Round)
	if err != nil {
		return basics.AccountChunk{}, fmt.Errorf("chunk too stale: %v", err)
	}

	toOffset, err := au.roundOffset(to)
	if err != nil {
		return basics.AccountChunk{}, fmt.Errorf("chunk too new: %v", err)
	}

	vsize := int(au.vparams.VectorSize)
	nextFreeSlot := au.nextSlot[toOffset]
	if nextFreeSlot == 0 {
		return basics.AccountChunk{}, fmt.Errorf("chunk was deleted")
	}

	highestChunkSeq := (nextFreeSlot - 1) / vsize
	if chunk.Seq > highestChunkSeq {
		return basics.AccountChunk{}, fmt.Errorf("chunk was deleted")
	}

	for i := range chunk.Slots {
		pos := (chunk.Seq * vsize) + i

		s, ok := au.lookupRecentSlot(to, pos)
		if ok {
			chunk.Slots[i] = s
		}
	}

	chunk.Round = to
	return chunk, nil
}

// internal
func (au *accountUpdates) lookupRecentSlot(rnd basics.Round, position int) (basics.AccountSlot, bool) {
	offset := uint64(rnd - au.dbRound)
	for offset > 0 {
		offset--
		s, ok := au.slotdeltas[offset].new[position]
		if ok {
			return s, true
		}
	}
	return basics.AccountSlot{}, false
}

func (au *accountUpdates) xxxAccountContext(rnd basics.Round, addr basics.Address) (accountContext, error) {
	// obtain position and slot of addr as of rnd
	slot, pos, err := au.slotOfAddr(rnd, addr)
	if err != nil || (slot == basics.AccountSlot{}) {
		// if account has zero balance, err = nil
		return accountContext{}, err
	}

	return accountContext{curr: slotContext{AccountSlot: slot, position: pos}}, nil
}

// archival
func (au *accountUpdates) allBalances(rnd basics.Round) (bals map[basics.Address]basics.AccountData, err error) {
	offsetLimit, err := au.roundOffset(rnd)
	if err != nil {
		return
	}

	err = au.dbs.rdb.Atomic(func(tx *sql.Tx) error {
		var err0 error
		bals, err0 = accountsAll(tx)
		return err0
	})
	if err != nil {
		return
	}

	for offset := uint64(0); offset < offsetLimit; offset++ {
		for addr, delta := range au.deltas[offset] {
			bals[addr] = delta.new
		}
	}
	return
}

func (au *accountUpdates) committedUpTo(rnd basics.Round) basics.Round {
	lookback := basics.Round(au.protos[len(au.protos)-1].MaxTxnLife)
	if rnd < lookback {
		return 0
	}

	newBase := rnd - lookback
	if newBase <= au.dbRound {
		// Already forgotten
		return au.dbRound
	}

	if newBase > au.dbRound+basics.Round(len(au.deltas)) {
		au.log.Panicf("committedUpTo: block %d too far in the future, lookback %d, dbRound %d, deltas %d", rnd, lookback, au.dbRound, len(au.deltas))
	}

	// If we recently flushed, wait to aggregate some more blocks.
	flushTime := time.Now()
	if !flushTime.After(au.lastFlushTime.Add(5 * time.Second)) {
		return au.dbRound
	}

	// Keep track of how many changes to each account we flush to the
	// account DB, so that we can drop the corresponding refcounts in
	// au.accounts.
	flushcount := make(map[basics.Address]int)
	offset := uint64(newBase - au.dbRound)
	err := au.dbs.wdb.Atomic(func(tx *sql.Tx) error {
		for i := uint64(0); i < offset; i++ {
			rnd := au.dbRound + basics.Round(i) + 1
			err0 := accountsNewRound(tx, rnd, au.deltas[i], au.slotdeltas[i], au.roundTotals[i+1].RewardsLevel, au.slotResidues[i+1], au.protos[i+1])
			if err0 != nil {
				return fmt.Errorf("accountsNewRound: %v", err0)
			}

			err0 = veccomNewRound(tx, rnd, au.nextSlot[i+1], au.vcdeltas[i], au.protos[i+1])
			if err0 != nil {
				return fmt.Errorf("veccomNewRound: %v", err0)
			}

			for addr := range au.deltas[i] {
				flushcount[addr] = flushcount[addr] + 1
			}
		}
		return nil
	})
	if err != nil {
		au.log.Warnf("unable to advance account snapshot: %v", err)
		return au.dbRound
	}

	// Drop reference counts to modified accounts, and evict them
	// from in-memory cache when no references remain.
	for addr, cnt := range flushcount {
		macct, ok := au.accounts[addr]
		if !ok {
			au.log.Panicf("inconsistency: flushed %d changes to %s, but not in au.accounts", cnt, addr)
		}

		if cnt > macct.ndeltas {
			au.log.Panicf("inconsistency: flushed %d changes to %s, but au.accounts had %d", cnt, addr, macct.ndeltas)
		}

		macct.ndeltas -= cnt
		if macct.ndeltas == 0 {
			delete(au.accounts, addr)
		} else {
			au.accounts[addr] = macct
		}
	}

	au.deltas = au.deltas[offset:]
	au.vcdeltas = au.vcdeltas[offset:]
	au.slotdeltas = au.slotdeltas[offset:]
	au.slotResidues = au.slotResidues[offset:]
	au.nextSlot = au.nextSlot[offset:]
	au.protos = au.protos[offset:]
	au.roundTotals = au.roundTotals[offset:]
	au.dbRound = newBase
	au.lastFlushTime = flushTime
	return au.dbRound
}

func (au *accountUpdates) newBlock(blk bookkeeping.Block, delta stateDelta) {
	proto := config.Consensus[blk.CurrentProtocol]
	rnd := blk.Round()

	if rnd <= au.latest() {
		// Duplicate, ignore.
		return
	}

	if rnd != au.latest()+1 {
		au.log.Panicf("accountUpdates: newBlock %d too far in the future, dbRound %d, deltas %d", rnd, au.dbRound, len(au.deltas))
	}

	au.deltas = append(au.deltas, delta.accts)
	au.vcdeltas = append(au.vcdeltas, delta.veccoms)
	au.slotdeltas = append(au.slotdeltas, delta.slots)
	au.slotResidues = append(au.slotResidues, delta.residue)
	au.nextSlot = append(au.nextSlot, delta.nextFreeSlot())
	au.protos = append(au.protos, proto)

	newTotals := au.roundTotals[len(au.roundTotals)-1]
	// allBefore := newTotals.All()

	// allAfter := newTotals.All()
	// if allBefore != allAfter {
	// 	au.log.Panicf("accountUpdates: sum of money changed from %d to %d", allBefore.Raw, allAfter.Raw)
	// }
	for addr, data := range delta.accts {
		macct := au.accounts[addr]
		macct.ndeltas++
		macct.data = data.new
		au.accounts[addr] = macct
	}
	au.roundTotals = append(au.roundTotals, newTotals)
}

func (au *accountUpdates) residue(rnd basics.Round) (residue slotResidue, err error) {
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return
	}

	residue = au.slotResidues[offset]
	return
}

func (au *accountUpdates) totals(rnd basics.Round) (totals AccountTotals, err error) {
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return
	}

	totals = au.roundTotals[offset]
	return
}

func (au *accountUpdates) parameters() *vector.Parameters {
	return au.vparams
}

func (au *accountUpdates) nextFreeSlot(rnd basics.Round) (int, error) {
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return 0, err
	}
	return au.nextSlot[offset], nil
}

func (au *accountUpdates) vc(rnd basics.Round, index int) (com vector.Commitment, err error) {
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return
	}

	vsize := int(au.vparams.VectorSize)
	maxSlot := au.nextSlot[offset] - 1
	if index > maxSlot/vsize {
		err = fmt.Errorf("vector commitment index %d > max slot vector index %d", index, maxSlot/vsize)
		return
	}

	for offset > 0 {
		offset--
		d, ok := au.vcdeltas[offset][index]
		if ok {
			com = d.new
			return
		}
	}

	// No updates of this commitment in the in-memory vcdeltas; use on-disk DB.
	// As an optimization, we avoid creating a separate transaction here, and
	// directly use a prepared SQL query against the database.
	return au.veccomq.lookup(index)
}

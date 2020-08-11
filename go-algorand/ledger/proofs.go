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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/vector"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
)

type acctProofTracker struct {
	// Connection to the database.
	dbs dbPair

	// Vector commitment parameters.
	vparams *vector.Parameters

	// dbRound is always exactly proofsRound(),
	// cached to avoid SQL queries.
	dbRound basics.Round

	// slotdeltas stores slot updates for every round after dbRound.
	slotdeltas []slotDelta

	// deltas stores slot updates for every round after dbRound.
	deltas []map[basics.Address]accountDelta

	// protos stores consensus parameters dbRound and every
	// round after it; i.e., protos is one longer than deltas.
	protos []config.ConsensusParams

	// proofs stores account proofs dbRound and every round after it,
	// where available.
	proofs []map[basics.Address]basics.AccountProof

	// initProto specifies the initial consensus parameters.
	initProto config.ConsensusParams

	// log copied from ledger
	log logging.Logger
}

func (apt *acctProofTracker) loadFromDisk(l ledgerForTracker) error {
	apt.dbs = l.trackerDB()
	apt.log = l.trackerLog()
	apt.vparams = vector.MakeParameters(apt.initProto.AccountVectorSize)

	var encodedPfs []basics.UnvalidatedAccountProof
	err := apt.dbs.wdb.Atomic(func(tx *sql.Tx) error {
		var err0 error
		err0 = acctProofsInit(tx, apt.initProto)
		if err0 != nil {
			return err0
		}

		apt.dbRound, err0 = acctProofsRound(tx)
		if err0 != nil {
			return err0
		}

		encodedPfs, err0 = acctProofsAll(tx)
		if err0 != nil {
			return err0
		}
		return nil
	})
	if err != nil {
		return err
	}

	var highest basics.Round
	for _, pf := range encodedPfs {
		if pf.Round > highest {
			highest = pf.Round
		}
	}
	for i := apt.dbRound; i <= highest; i++ {
		apt.proofs = append(apt.proofs, make(map[basics.Address]basics.AccountProof))
	}
	for _, pf := range encodedPfs {
		offset := pf.Round - apt.dbRound
		dec, ok := pf.UnsafeDecode(apt.vparams)
		if !ok {
			return fmt.Errorf("could not decode proof: %v", pf)
		}
		apt.proofs[offset][pf.Address] = dec
	}

	hdr, err := l.BlockHdr(apt.dbRound)
	if err != nil {
		return err
	}
	apt.protos = []config.ConsensusParams{config.Consensus[hdr.CurrentProtocol]}

	latest := l.Latest()
	apt.slotdeltas = nil
	apt.deltas = nil
	loaded := apt.dbRound
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

		apt.newBlock(blk, delta)
		loaded = next
	}

	return nil
}

func (apt *acctProofTracker) newBlock(blk bookkeeping.Block, delta stateDelta) {
	proto := config.Consensus[blk.CurrentProtocol]
	rnd := blk.Round()

	if rnd <= apt.latest() {
		// Duplicate, ignore.
		return
	}

	if rnd != apt.latest()+1 {
		apt.log.Panicf("acctProofTracker: newBlock %d too far in the future, dbRound %d, slotdeltas %d", rnd, apt.dbRound, len(apt.slotdeltas))
	}

	apt.deltas = append(apt.deltas, delta.accts)
	apt.slotdeltas = append(apt.slotdeltas, delta.slots)
	apt.protos = append(apt.protos, proto)

	// only update proofs which are tracked in the previous round
	prevOffset, err := apt.roundOffset(rnd - 1)
	if err != nil {
		apt.log.Panicf("acctProofTracker: rnd-1 %d not tracked in offsets", rnd-1)
	}

	if apt.dbRound+basics.Round(len(apt.proofs)) > rnd {
		return
	}
	apt.proofs = append(apt.proofs, make(map[basics.Address]basics.AccountProof))

	for addr := range apt.proofs[prevOffset] {
		apt.log.Infof("bringing proofs for %v from %d up to date", addr, rnd-1)
		apt.updateProofsOfAddr(addr)
	}
}

func (apt *acctProofTracker) updateProofsOfAddr(addr basics.Address) error {
	var lastProofRnd basics.Round
	var ok bool
	for offset := len(apt.proofs) - 1; offset >= 0; offset-- {
		_, ok = apt.proofs[offset][addr]
		if ok {
			lastProofRnd = apt.dbRound + basics.Round(offset)
			break
		}
	}
	if !ok {
		return fmt.Errorf("cannot update proof for %v: address is untracked", addr)
	}

	var err error
	offset := lastProofRnd - apt.dbRound
	pf := apt.proofs[offset][addr]

	if pf.Round != lastProofRnd || pf.Address != addr { // sanity check
		panic("inconsistency in stored proofs")
	}

	for pf.Round < apt.latest() {
		rnd := pf.Round // informational
		pf, err = apt.updateProofStep(pf)
		if err != nil {
			return fmt.Errorf("cannot update proof for %v: %v", addr, err)
		}
		if (pf == basics.AccountProof{}) {
			apt.log.Infof("proof for %v was deleted at round %d", addr, rnd)
			return nil
		}

		err := apt.dbs.wdb.Atomic(func(tx *sql.Tx) error {
			return acctProofsInsert(tx, pf)
		})
		if err != nil {
			return fmt.Errorf("cannot insert proof for %v: %v", addr, err)
		}
		offset = pf.Round - apt.dbRound
		apt.proofs[offset][addr] = pf

		apt.log.Infof("updated proof for %v to round %d", addr, pf.Round)
	}
	return nil
}

// updateProofStep updates the proof by a single round.
// In other words, it computes addr at round pf.Round
// given the proof for addr at round pf.Round-1.
//
// It returns an error if it is unable to compute the next proof.
// This could happen because:
//  - addr was deleted at rnd
//  - addr was moved at rnd to another slot, and the proof for
//    that slot is too stale to update.
func (apt *acctProofTracker) updateProofStep(pf basics.AccountProof) (basics.AccountProof, error) {
	offset := pf.Round - apt.dbRound
	sd := apt.slotdeltas[offset]
	slot, ok := sd.new[pf.Position]
	if !ok || slot.Address == pf.Address {
		return updateSlotProof(apt.vparams, pf, sd), nil
	}
	apt.log.Debugf("addr %v was moved or deleted", pf.Address)

	// addr was either moved or deleted
	newpos := -1
	for pos, slot := range sd.new {
		if slot.Address == pf.Address {
			newpos = pos
			apt.log.Debugf("addr %v was moved to slot %d", pf.Address, newpos)
			break
		}
	}
	if newpos < 0 {
		apt.log.Debugf("addr %v was deleted", pf.Address)
		return basics.AccountProof{}, fmt.Errorf("addr %v was deleted at rnd %d", pf.Address, pf.Round)
	}

	oldaddr := sd.old[newpos].Address
	mvpf := apt.deltas[offset][oldaddr].pf
	if mvpf.Round < apt.dbRound {
		return basics.AccountProof{}, fmt.Errorf("moved proof too stale: mvpf.Round %d < apt.dbRound %d", mvpf.Round, apt.dbRound)
	}

	apt.log.Debugf("bringing moved proof %v up to date", mvpf)
	for mvpf.Round < pf.Round+1 {
		offset = mvpf.Round - apt.dbRound
		sd = apt.slotdeltas[offset]
		mvpf = updateSlotProof(apt.vparams, mvpf, sd)
	}
	return mvpf, nil
}

func (apt *acctProofTracker) committedUpTo(rnd basics.Round) basics.Round {
	lookback := basics.Round(apt.protos[len(apt.protos)-1].MaxTxnLife)
	if rnd < lookback {
		return 0
	}

	newBase := rnd - lookback
	if newBase <= apt.dbRound {
		// Already forgotten
		return apt.dbRound
	}

	if newBase > apt.dbRound+basics.Round(len(apt.slotdeltas)) {
		apt.log.Panicf("committedUpTo: block %d too far in the future, lookback %d, dbRound %d, slotdeltas %d", rnd, lookback, apt.dbRound, len(apt.slotdeltas))
	}

	err := apt.dbs.wdb.Atomic(func(tx *sql.Tx) error {
		return acctProofsNewRound(tx, newBase)
	})
	if err != nil {
		apt.log.Warnf("unable to advance proofs snapshot: %v", err)
		return apt.dbRound
	}

	offset := uint64(newBase - apt.dbRound)

	apt.deltas = apt.deltas[offset:]
	apt.slotdeltas = apt.slotdeltas[offset:]
	apt.proofs = apt.proofs[offset:]
	apt.protos = apt.protos[offset:]
	apt.dbRound = newBase

	return apt.dbRound
}

func (apt *acctProofTracker) close() {}

func (apt *acctProofTracker) accountProof(rnd basics.Round, addr basics.Address) (basics.AccountProof, error) {
	offset, err := apt.roundOffset(rnd)
	if err != nil {
		return basics.AccountProof{}, err
	}

	pf, ok := apt.proofs[offset][addr]
	if !ok {
		return basics.AccountProof{}, fmt.Errorf("addr %v not found at round %v", addr, rnd)
	}
	return pf, nil
}

func (apt *acctProofTracker) roundOffset(rnd basics.Round) (offset uint64, err error) {
	if rnd < apt.dbRound {
		err = fmt.Errorf("round %d before dbRound %d", rnd, apt.dbRound)
		return
	}

	off := uint64(rnd - apt.dbRound)
	if off > uint64(len(apt.slotdeltas)) {
		err = fmt.Errorf("round %d too high: dbRound %d, slotdeltas %d", rnd, apt.dbRound, len(apt.slotdeltas))
		return
	}

	return off, nil
}

func (apt *acctProofTracker) latest() basics.Round {
	return apt.dbRound + basics.Round(len(apt.slotdeltas))
}

func (apt *acctProofTracker) startTracking(pf basics.AccountProof) error {
	offset, err := apt.roundOffset(pf.Round)
	if err != nil {
		return err
	}

	err = apt.dbs.wdb.Atomic(func(tx *sql.Tx) error {
		return acctProofsInsert(tx, pf)
	})
	if err != nil {
		return fmt.Errorf("cannot insert proof for %v: %v", pf.Address, err)
	}
	apt.proofs[offset][pf.Address] = pf
	return apt.updateProofsOfAddr(pf.Address)
}

func (apt *acctProofTracker) stopTracking(addr basics.Address) error {
	err := apt.dbs.wdb.Atomic(func(tx *sql.Tx) error {
		return acctProofsDrop(tx, addr)
	})
	if err != nil {
		return err
	}

	for _, rndpfs := range apt.proofs {
		delete(rndpfs, addr)
	}
	return nil
}

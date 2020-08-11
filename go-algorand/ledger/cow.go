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

// import "fmt"
// import "github.com/algorand/go-algorand/crypto/vector"

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
)

//   ___________________
// < cow = Copy On Write >
//   -------------------
//          \   ^__^
//           \  (oo)\_______
//              (__)\       )\/\
//                  ||----w |
//                  ||     ||

type roundCowParent interface {
	lookup(basics.Address, accountContext) (basics.AccountData, accountContext, error)
	isDup(basics.Round, transactions.Txid) (bool, error)
}

type roundCowState struct {
	veccomView   VectorCommitmentDB
	lookupParent roundCowParent
	commitParent *roundCowState
	proto        config.ConsensusParams
	mods         stateDelta
}

type stateDelta struct {
	// modified accounts
	accts map[basics.Address]accountDelta

	// new Txids for the txtail
	txids map[transactions.Txid]struct{}

	// new block header; read-only
	hdr *bookkeeping.BlockHeader

	// net number of changed accounts
	// > 0 indicates creation
	// < 0 indicates deletion
	netAcctChange int

	// the following are not set until resolveSlotUpdates is called

	// modified slots
	slots slotDelta

	// residual slots
	residue slotResidue

	// modified vector commitments
	veccoms map[int]veccomDelta
}

// modifies cb.mods to have correct values for cb.mods.slots and cb.mods.veccoms
// nextFreeSlot was the next free slot at the conclusion of prev.
func (cb *roundCowState) resolveSlotUpdates(prev basics.Round, nextFreeSlot int, residue slotResidue, tail basics.AccountTail) error {
	var sd slotDelta

	// fmt.Printf("resolveSlotUpdates: passing in nextFreeSlot of %d\n", nextFreeSlot)
	sd.end = nextFreeSlot
	sd.old = make(map[int]basics.AccountSlot)
	sd.new = make(map[int]basics.AccountSlot)
	sd.index = make(map[basics.Address]int)
	sd.nindex = make(map[basics.Address]int)
	sd.modaddr = make(map[basics.Address]bool)
	sd.invnew = make(map[basics.Address]slotContext)
	sd.invnewnext = make(map[basics.Address]slotContext)
	sd.deleted = make(map[basics.Address]bool)
	sd.vsize = int(cb.veccomView.Params().VectorSize)

	residue = sd.batch(cb.mods.accts, residue, tail)

	vd, err := sd.veccoms(prev, nextFreeSlot, cb.veccomView)
	if err != nil {
		return err
	}

	cb.mods.slots = sd
	cb.mods.residue = residue
	cb.mods.veccoms = vd

	// fmt.Println("resolveSlotUpdates: dumping new vector and slot data for prev", prev)
	// fmt.Println()
	// fmt.Println("old slots:")
	// for i, s := range sd.old {
	// 	fmt.Printf(" %d %v\n", i, s)
	// }
	// fmt.Println("new slots:")
	// for i, s := range sd.new {
	// 	fmt.Printf(" %d %v\n", i, s)
	// }

	// fmt.Println()
	// fmt.Println("vector deltas:")
	// for i, d := range vd {
	// 	if (d.old == vector.Commitment{}) {
	// 		fmt.Printf(" %d (o) NIL\n", i)
	// 	} else {
	// 		for j, s := range d.old.Shadow {
	// 			fmt.Printf(" %d (o) %d %v\n", i, j, s)
	// 		}
	// 	}

	// 	if (d.new == vector.Commitment{}) {
	// 		fmt.Printf(" %d (n) NIL\n", i)
	// 	} else {
	// 		for j, s := range d.new.Shadow {
	// 			fmt.Printf(" %d (n) %d %v\n", i, j, s)
	// 		}
	// 	}
	// }

	return nil
}

func (d stateDelta) pendingDeletions() (res int) {
	return -d.netAcctChange
}

func acctChange(old, new basics.AccountData) (res int) {
	if (old == basics.AccountData{}) {
		res++
	}
	if (new == basics.AccountData{}) {
		res--
	}
	return
}

func (d stateDelta) nextFreeSlot() int {
	return d.slots.end
}

func makeRoundCowState(b roundCowParent, vv VectorCommitmentDB, hdr bookkeeping.BlockHeader) *roundCowState {
	return &roundCowState{
		lookupParent: b,
		commitParent: nil,
		veccomView:   vv,
		proto:        config.Consensus[hdr.CurrentProtocol],
		mods: stateDelta{
			accts: make(map[basics.Address]accountDelta),
			txids: make(map[transactions.Txid]struct{}),
			hdr:   &hdr,

			netAcctChange: 0,
		},
	}
}

func (cb *roundCowState) rewardsLevel() uint64 {
	return cb.mods.hdr.RewardsLevel
}

// data and err are fresh, but newctx is stale with respect to the current intermediate state.
func (cb *roundCowState) lookup(addr basics.Address, ctx accountContext) (data basics.AccountData, newctx accountContext, err error) {
	data, newctx, err = cb.lookupParent.lookup(addr, ctx)
	if err != nil {
		return
	}

	d, ok := cb.mods.accts[addr]
	if ok {
		data = d.new
	}
	return
}

func (cb *roundCowState) isDup(firstValid basics.Round, txid transactions.Txid) (bool, error) {
	_, present := cb.mods.txids[txid]
	if present {
		return true, nil
	}

	return cb.lookupParent.isDup(firstValid, txid)
}

// ctx should correspond to the one returned by the previous call to lookup()
// TODO figure out precedence rules for pf (use oldest that can validate?)
func (cb *roundCowState) put(addr basics.Address, old basics.AccountData, new basics.AccountData, ctx accountContext, pf basics.AccountProof) {
	prev, present := cb.mods.accts[addr]
	var d accountDelta
	if present {
		oldChange := acctChange(prev.old, prev.new)
		d = accountDelta{old: prev.old, new: new, ctx: prev.ctx, pf: prev.pf}
		newChange := acctChange(d.old, d.new)
		cb.mods.netAcctChange -= oldChange
		cb.mods.netAcctChange += newChange
	} else {
		// newly initialized: ctx must be correct
		d = accountDelta{old: old, new: new, ctx: ctx, pf: pf}
		cb.mods.netAcctChange += acctChange(d.old, d.new)
	}
	if (d.old != basics.AccountData{}) && (d.new == basics.AccountData{}) {
		// recent update was deletion: ctx must be correct
		d.ctx = ctx
		d.pf = pf
	}

	// TODO any other cases we need to modify d.ctx?

	cb.mods.accts[addr] = d
}

func (cb *roundCowState) addTx(txid transactions.Txid) {
	cb.mods.txids[txid] = struct{}{}
}

func (cb *roundCowState) child() *roundCowState {
	return &roundCowState{
		lookupParent: cb,
		commitParent: cb,
		proto:        cb.proto,
		mods: stateDelta{
			accts: make(map[basics.Address]accountDelta),
			txids: make(map[transactions.Txid]struct{}),
			hdr:   cb.mods.hdr,

			netAcctChange: cb.mods.netAcctChange,
		},
	}
}

func (cb *roundCowState) commitToParent() {
	for addr, delta := range cb.mods.accts {
		prev, present := cb.commitParent.mods.accts[addr]
		if present {
			cb.commitParent.mods.accts[addr] = accountDelta{
				old: prev.old,
				new: delta.new,
				ctx: prev.ctx,
				pf:  prev.pf,
			}
			if (delta.new == basics.AccountData{}) {
				cb.commitParent.mods.accts[addr] = accountDelta{
					old: prev.old,
					new: delta.new,
					ctx: delta.ctx,
					pf:  delta.pf,
				}
			}
		} else {
			cb.commitParent.mods.accts[addr] = delta
		}
	}

	for txid := range cb.mods.txids {
		cb.commitParent.mods.txids[txid] = struct{}{}
	}
	cb.commitParent.mods.netAcctChange = cb.mods.netAcctChange
}

func (cb *roundCowState) modifiedAccounts() []basics.Address {
	var res []basics.Address
	for addr := range cb.mods.accts {
		res = append(res, addr)
	}
	return res
}

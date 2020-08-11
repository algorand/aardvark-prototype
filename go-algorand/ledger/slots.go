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
	"fmt"
	"sort"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/vector"
	"github.com/algorand/go-algorand/data/basics"
)

type slotContext struct {
	basics.AccountSlot
	position int
}

func (sc slotContext) String() string {
	return fmt.Sprintf("{position: %v, AccountSlot: %v}", sc.position, sc.AccountSlot)
}

type accountContext struct {
	curr slotContext
	prev slotContext
}

func (ac accountContext) String() string {
	return fmt.Sprintf("{curr: %v, prev: %v}", ac.curr, ac.prev)
}

func asContext(addr basics.Address, pf basics.AccountProof) (ctx accountContext) {
	if addr == pf.Address {
		ctx.curr.AccountSlot = pf.AccountSlot
		ctx.curr.position = pf.Position
	} else {
		ctx.prev.AccountSlot = pf.AccountSlot
		ctx.prev.position = pf.Position
	}
	return
}

func (x *slotDelta) position(a basics.Address) (p int, ok bool) {
	p, ok = x.index[a]
	return
}

func (x *slotDelta) value(pos int) (s basics.AccountSlot, ok bool) {
	s, ok = x.new[pos]
	return
}

func (x *slotDelta) lookup(a basics.Address) (ctx slotContext, err error) {
	pos, ok := x.index[a]
	if !ok {
		err = fmt.Errorf("x.index[%v] not found", a)
		return slotContext{}, err
	}
	if s, ok := x.new[pos]; ok {
		return slotContext{AccountSlot: s, position: pos}, nil
	}
	err = fmt.Errorf("x.new[%v] not found", pos)
	return slotContext{}, err
}

// for external use
func (x *slotDelta) modified(addr basics.Address) bool {
	return x.modaddr[addr]
}

var errLookupContextSlotDeleted = fmt.Errorf("lookupContext: account slot was deleted")

// for external use
func (x *slotDelta) lookupContext(addr basics.Address) (ctx slotContext, err error) {
	sc, ok := x.invnew[addr]
	if ok {
		return sc, nil
	}
	ok = x.deleted[addr]
	if ok {
		return slotContext{}, errLookupContextSlotDeleted
	}
	return slotContext{}, fmt.Errorf("lookupContext: %v not found", addr)
}

type errPrevNotFound basics.Address

func (err errPrevNotFound) Error() string {
	return fmt.Sprintf("lookupPrevExists: %v not found", basics.Address(err))
}

type errPrevGapNotFound basics.Address

func (err errPrevGapNotFound) Error() string {
	return fmt.Sprintf("lookupPrevNotExists: %v not found", basics.Address(err))
}

// for external use
func (x *slotDelta) lookupPrevExists(a basics.Address) (ctx slotContext, err error) {
	sc, ok := x.invnewnext[a]
	if !ok {
		return slotContext{}, errPrevNotFound(a)
	}
	return sc, nil
}

// for external use
func (x *slotDelta) lookupPrevNotExists(a basics.Address) (ctx slotContext, err error) {
	return x.gapInfo.search(a)
}

func (x *slotDelta) nlookup(a basics.Address) (ctx slotContext, err error) {
	pos, ok := x.nindex[a]
	if !ok {
		err = fmt.Errorf("x.nindex[%v] not found", a)
		return slotContext{}, err
	}
	if s, ok := x.new[pos]; ok {
		return slotContext{AccountSlot: s, position: pos}, nil
	}
	err = fmt.Errorf("x.new[%v] not found", pos)
	return slotContext{}, err
}

func (x *slotDelta) prev(a basics.Address, claim slotContext) (res slotContext, err error) {
	if x.old[claim.position] == x.new[claim.position] {
		res = claim
		if !claim.AccountSlot.Surrounds(a) {
			return slotContext{}, fmt.Errorf("claim account slot at %d %v does not surround address %v", claim.position, claim.AccountSlot, a)
		}
		return
	}

	for pos, s := range x.new {
		if s.Surrounds(a) {
			return slotContext{position: pos, AccountSlot: s}, nil
		}
	}

	return slotContext{}, errPrevGapNotFound(a)
}

func (x *slotDelta) prevDel(a basics.Address, ctx accountContext) (res slotContext, err error) {
	res = ctx.prev
	if x.old[res.position] != x.new[res.position] {
		// prev position was modified
		res, err = x.nlookup(ctx.curr.Address)
		for res.AccountSlot.Next.Less(a) { // TODO use Surrounds
			if !res.AccountSlot.Address.Less(res.AccountSlot.Next) && (res.AccountSlot.Address.Less(a) || !res.AccountSlot.Next.Less(a)) {
				return
			}

			res, err = x.lookup(res.AccountSlot.Next)
			if err != nil {
				return
			}
		}
		return
	}
	return
}

func (x *slotDelta) write(pos int, old, new basics.AccountSlot) {
	if _, ok := x.old[pos]; !ok {
		x.old[pos] = old
		x.new[pos] = old
	}

	// fmt.Println("write", pos, ":", old, "->", new)

	if x.new[pos] != old {
		panic(fmt.Errorf("x.new[%v] != old: %v != %v", pos, x.new[pos], old))
	}
	x.new[pos] = new
	x.invnew[new.Address] = slotContext{position: pos, AccountSlot: new}
	x.invnewnext[new.Next] = slotContext{position: pos, AccountSlot: new}
}

func (x *slotDelta) append(s basics.AccountSlot, holes []int) ([]int, basics.AccountSlot, bool) {
	if len(holes) > 0 {
		last := holes[len(holes)-1]
		holes = holes[:len(holes)-1]
		x.write(last, basics.AccountSlot{}, s)
		return holes, basics.AccountSlot{}, false
	}

	x.old[x.end] = basics.AccountSlot{}
	x.new[x.end] = s
	x.invnew[s.Address] = slotContext{position: x.end, AccountSlot: s}
	x.invnewnext[s.Next] = slotContext{position: x.end, AccountSlot: s}
	// fmt.Println("appending slot", x.end, "value", s)
	x.end++
	return holes, s, true
}

func (x *slotDelta) truncate() {
	x.end--
	if _, ok := x.old[x.end]; !ok {
		panic("cannot truncate tail: cannot read tail")
	}
	// fmt.Println("truncating slot", x.end)
	x.new[x.end] = basics.AccountSlot{}
}

// a is in the gap of ctx.prev
func (x *slotDelta) create(a basics.Address, d basics.AccountData, ctx accountContext, holes []int) ([]int, basics.AccountSlot, bool) {
	x.modaddr[a] = true
	s := basics.AccountSlot{Address: a, AccountData: d, Next: a}
	if x.end != 0 {
		pc, err := x.prev(a, ctx.prev)
		if err != nil {
			// fmt.Printf("prev error on %v: dumping slot contents\n", a)
			// fmt.Println("old slots:")
			// for i, s := range x.old {
			// 	fmt.Printf(" %d %v\n", i, s)
			// }
			// fmt.Println("new slots:")
			// for i, s := range x.new {
			// 	fmt.Printf(" %d %v\n", i, s)
			// }
			// fmt.Println("passed-in ctx was", ctx.prev)

			panic(err)
		}

		x.modaddr[pc.Address] = true

		p0, pos := pc.AccountSlot, pc.position
		s.Next = p0.Next
		p := p0
		p.Next = s.Address
		x.write(pos, p0, p)
		x.nindex[p.Next] = pos
	}

	if len(holes) > 0 {
		last := holes[len(holes)-1]
		x.nindex[s.Next] = last
		x.index[a] = last
	} else {
		x.nindex[s.Next] = x.end
		x.index[a] = x.end
	}
	return x.append(s, holes)
}

func (x *slotDelta) modify(old accountContext, d basics.AccountData) {
	x.modaddr[old.curr.Address] = true

	s0 := old.curr.AccountSlot
	if s, ok := x.new[old.curr.position]; ok { // might need to be address lookup later...?
		// old modified
		s0 = s
	}
	s := s0
	s.AccountData = d
	x.write(old.curr.position, s0, s)

	x.index[s.Address] = old.curr.position
	x.nindex[s.Next] = old.curr.position
}

func (x *slotDelta) delete(ctx accountContext, tailslot basics.AccountSlot, holes []int) []int {
	x.modaddr[ctx.curr.Address] = true
	x.deleted[ctx.curr.Address] = true
	delete(x.invnew, ctx.curr.Address)
	delete(x.invnewnext, ctx.curr.Address)

	pos, ok := x.position(ctx.curr.Address)
	if !ok {
		pos = ctx.curr.position
	}
	curr, ok := x.value(pos)
	if !ok {
		curr = ctx.curr.AccountSlot
	}

	// overwrite prev
	if curr.Next != curr.Address {
		pc, err := x.prevDel(curr.Address, ctx)
		if err != nil {
			panic(err)
		}

		x.modaddr[pc.Address] = true

		p0, pos0 := pc.AccountSlot, pc.position
		p := p0
		p.Next = curr.Next
		x.write(pos0, p0, p)
		x.nindex[p.Next] = pos0
	}

	// can we use tailslot?
	if (tailslot == basics.AccountSlot{}) {
		// no.
		// can we use holes?
		if len(holes) == x.vsize {
			// no, so hope that the tail is enough to move into holes
			holes = x.applyTail(holes)
		}
		// holes now has enough space
		holes = append(holes, pos)
		x.write(pos, curr, basics.AccountSlot{})
		x.index[ctx.curr.Address] = -1
		x.nindex[ctx.curr.Address] = -1
		return holes
	}

	// yes; it's a loose slot. use it to delete
	newtailslot, ok := x.value(x.end - 1)
	if !ok {
		panic("could not fetch loose slot")
		// newtailslot = tailslot
	}
	x.modaddr[newtailslot.Address] = true

	if x.end-1 != pos {
		x.write(pos, curr, newtailslot)
	}

	// truncate
	x.truncate()
	if x.end != pos { // x.end changes as a result of truncate
		x.index[newtailslot.Address] = pos
		x.nindex[newtailslot.Next] = pos
	}
	x.index[ctx.curr.Address] = -1
	x.nindex[ctx.curr.Address] = -1
	return holes
}

func (x *slotDelta) applyTail(holes []int) []int {
	sort.Ints(holes)

	// fmt.Println("applying tail with holes", holes)
	// defer fmt.Println("done applying tail with holes", holes)

	for _, pos := range holes {
		if pos >= x.end {
			return nil
		}

		// overwrite current
		newtailslot, ok := x.value(x.end - 1)
		if !ok {
			panic("out of tail")
		}
		for (newtailslot == basics.AccountSlot{}) {
			// this tail slot was already deleted; skip it
			x.end--
			if pos >= x.end {
				return nil
			}
			newtailslot, ok = x.value(x.end - 1)
			if !ok {
				panic("out of tail")
			}
		}

		if x.end-1 != pos {
			x.write(pos, basics.AccountSlot{}, newtailslot)
		}

		// truncate
		x.truncate()
		if x.end != pos { // x.end changes as a result of truncate
			x.index[newtailslot.Address] = pos
			x.nindex[newtailslot.Next] = pos
			x.modaddr[newtailslot.Address] = true
		}
	}
	return nil
}

type slotResidue struct {
	Positive []basics.AccountSlot
	Negative []int // of position
}

func (r slotResidue) clone() (new slotResidue) {
	for _, s := range r.Positive {
		new.Positive = append(new.Positive, s)
	}
	for _, s := range r.Negative {
		new.Negative = append(new.Negative, s)
	}
	return
}

// tail is sorted in increasing position order
func (x *slotDelta) batch(mods map[basics.Address]accountDelta, residue slotResidue, accttail basics.AccountTail) slotResidue {
	// canonical order: do modify, then creates, then deletes in address order
	var addrs addrList
	for addr := range mods {
		addrs = append(addrs, addr)
	}
	sort.Sort(addrs)

	holes := residue.Negative
	newslots := residue.Positive

	lastVector := (x.end / x.vsize) * x.vsize
	tail := accttail.Slots()
	firstTail := lastVector - len(tail)
	for i := 0; i < len(tail); i++ {
		// fmt.Printf("tail set %d -> %v\n", firstTail+i, tail[i])

		x.old[firstTail+i] = tail[i]
		x.new[firstTail+i] = tail[i]
		// TODO set invnew and invnewnext?
	}
	for i := 0; i < len(newslots); i++ {
		// fmt.Printf("newslot set %d -> %v\n", lastVector+i, newslots[i])

		x.old[lastVector+i] = newslots[i]
		x.new[lastVector+i] = newslots[i]
		// TODO set invnew and invnewnext?
	}

	for _, addr := range addrs {
		delta := mods[addr]
		if (delta.old != basics.AccountData{} && delta.new != basics.AccountData{}) {
			x.modify(delta.ctx, delta.new)
		}
	}
	for _, addr := range addrs {
		delta := mods[addr]
		if (delta.old == basics.AccountData{} && delta.new != basics.AccountData{}) {
			var newslot basics.AccountSlot
			var ok bool
			holes, newslot, ok = x.create(addr, delta.new, delta.ctx, holes)
			if ok {
				newslots = append(newslots, newslot)
			}
		}
	}
	for _, addr := range addrs {
		delta := mods[addr]
		if (delta.old != basics.AccountData{} && delta.new == basics.AccountData{}) {
			var tailslot basics.AccountSlot
			if len(newslots) > 0 {
				tailslot = newslots[len(newslots)-1]
				newslots = newslots[:len(newslots)-1]
			} else {
				tailslot = basics.AccountSlot{}
			}
			holes = x.delete(delta.ctx, tailslot, holes)
		}
	}

	x.gapInfo = makeGapInfo(x.new)

	newslots = nil
	lastVector = (x.end / x.vsize) * x.vsize
	for i := lastVector; i < x.end; i++ {
		newslots = append(newslots, x.new[i])
	}
	return slotResidue{Positive: newslots, Negative: holes}
}

func validateSlotTail(vv VectorCommitmentDB, prev basics.Round, accttail basics.AccountTail, nextFreeSlot int) error {
	vparams := vv.Params()
	vsize := int(vparams.VectorSize)

	lastFullVector := (nextFreeSlot / vsize) * vsize
	tailBase := lastFullVector - accttail.Size()

	tail := accttail.Slots()
	for i := 0; i < accttail.Size(); i += vsize {
		preimg := make([]crypto.Digest, vsize)
		for j := 0; j < vsize; j++ {
			preimg[j] = slotDigest(tail[i+j])
		}
		expected := vector.Commit(vparams, preimg)
		expbytes := expected.ToBytes()

		k := (tailBase + i) / vsize
		com, err := vv.Get(prev, k)
		if err != nil {
			return fmt.Errorf("validateSlotTail: could not get commitment seq %d: %v", k, err)
		}
		combytes := com.ToBytes()

		if expbytes != combytes {
			return fmt.Errorf("validateSlotTail: expbytes %v != combytes %v (%d)", expbytes, combytes, i)
		}
	}

	return nil
}

// handles empty AccountSlots correctly
func slotDigest(s basics.AccountSlot) crypto.Digest {
	if (s == basics.AccountSlot{}) {
		return crypto.Digest{}
	}
	return crypto.HashObj(s)
}

func updateSlotProof(vparams *vector.Parameters, pf basics.AccountProof, sd slotDelta) basics.AccountProof {
	vsize := int(vparams.VectorSize)
	bottom := (pf.Position / vsize) * vsize
	top := bottom + vsize
	for pos := range sd.old {
		if pos >= bottom && pos < top {
			oldval := slotDigest(sd.old[pos])
			newval := slotDigest(sd.new[pos])
			if oldval != newval {
				pf.Proof = pf.Proof.Update(vparams, pos%vsize, oldval, newval)
				if pos == pf.Position {
					if sd.old[pos] != pf.AccountSlot {
						panic("bad old slot value")
					}
					pf.AccountSlot = sd.new[pos]
				}
			}
		}
	}
	pf.Round++
	return pf
}

func slotDeletionsRemaining(vparams *vector.Parameters, tail basics.AccountTail, residue slotResidue) int {
	allowed := int(vparams.VectorSize) // we are allowed to buffer up to -(vector size) deletions
	allowed += tail.Size()             // each item in the tail satisfies one deletion
	allowed += len(residue.Positive)   // each positive residual slot satisifes one deletion
	allowed -= len(residue.Negative)   // each negative residual slot costs one deletion
	return allowed
}

type veccomCow struct {
	VectorCommitmentDB

	delta map[int]veccomDelta
	end   int
	rnd   basics.Round // round for which to look up vector commitments
}

// nextFreeSlot was the next free slot at the conclusion of prev.
func (x *slotDelta) veccoms(prev basics.Round, nextFreeSlot int, v VectorCommitmentDB) (map[int]veccomDelta, error) {
	// in order: append, modify, delete
	u := new(veccomCow)
	u.delta = make(map[int]veccomDelta)
	u.rnd = prev // do lookups from the past round
	u.end = nextFreeSlot
	u.VectorCommitmentDB = v

	for pos := nextFreeSlot; pos < x.end; pos++ {
		err := u.append(x.new[pos])
		if err != nil {
			return nil, err
		}
	}
	for pos := range x.old {
		oldExists := (x.old[pos] != basics.AccountSlot{})
		newExists := (x.new[pos] != basics.AccountSlot{})

		modified := oldExists && newExists
		deferredClear := oldExists && !newExists && pos < x.end
		deferredNew := !oldExists && newExists && pos < nextFreeSlot

		if modified || deferredClear || deferredNew {
			err := u.write(pos, x.old[pos], x.new[pos])
			if err != nil {
				return nil, err
			}
		}
	}

	// TODO can x.end be assumed to always be at a vector boundary?
	// if so, can we simply drop the entire commitment?
	for pos := nextFreeSlot; pos > x.end; pos-- {
		err := u.truncate(x.old[pos-1])
		if err != nil {
			return nil, err
		}
	}
	return u.delta, nil
}

func (u *veccomCow) get(rnd basics.Round, i int) (vector.Commitment, error) {
	d, ok := u.delta[i]
	if ok {
		return d.new, nil
	}

	vc, err := u.Get(u.rnd, i)
	if err != nil {
		return vector.Commitment{}, err
	}
	u.delta[i] = veccomDelta{old: vc}
	return vc, nil
}

func (u *veccomCow) append(s basics.AccountSlot) error {
	vparams := u.Params()
	vsize := int(vparams.VectorSize)
	k := u.end / vsize

	var newcom vector.Commitment
	if k*vsize == u.end {
		newcom = vector.Commit1(vparams, slotDigest(s))
	} else {
		oldcom, err := u.get(u.rnd, k)
		if err != nil {
			return err
		}
		newcom = oldcom.Update(vparams, u.end%vsize, crypto.Digest{}, slotDigest(s))
	}

	// TODO clean this up
	vd := u.delta[k]
	vd.new = newcom
	u.delta[k] = vd

	u.end++
	return nil
}

func (u *veccomCow) write(i int, sold, s basics.AccountSlot) error {
	vparams := u.Params()
	vsize := int(vparams.VectorSize)
	oldcom, err := u.get(u.rnd, i/vsize)
	if err != nil {
		return err
	}
	newcom := oldcom.Update(vparams, i%vsize, slotDigest(sold), slotDigest(s))

	// TODO clean this up
	k := i / vsize
	vd := u.delta[k]
	vd.new = newcom
	u.delta[k] = vd

	return nil
}

func (u *veccomCow) truncate(last basics.AccountSlot) error {
	vparams := u.Params()
	vsize := int(vparams.VectorSize)

	i := (u.end - 1) % vsize // 1 -> 0 % 5 = 0; 7 -> 6 % 5 = 1; 5 -> 4 % 5 = 4
	k := (u.end - 1) / vsize // 1 -> 0 / 5 = 0; 7 -> 6 / 5 = 1; 5 -> 4 / 5 = 0
	oldcom, err := u.get(u.rnd, k)
	if err != nil {
		return err
	}
	var newcom vector.Commitment
	if u.end%vsize == 1 {
		newcom = vector.Commitment{}
	} else {
		newcom = oldcom.Update(vparams, i, slotDigest(last), crypto.Digest{})
	}

	// TODO clean this up
	vd := u.delta[k]
	vd.new = newcom
	u.delta[k] = vd

	u.end--
	return nil
}

type slotDelta struct {
	old map[int]basics.AccountSlot
	new map[int]basics.AccountSlot
	end int

	vsize int // const; size of vector

	// -1 to delete
	index  map[basics.Address]int
	nindex map[basics.Address]int

	modaddr    map[basics.Address]bool
	invnew     map[basics.Address]slotContext
	invnewnext map[basics.Address]slotContext
	deleted    map[basics.Address]bool
	gapInfo
}

// sorted list of slotContext corresponding to slotDelta.new
type gapInfo []slotContext

func makeGapInfo(new map[int]basics.AccountSlot) (info gapInfo) {
	for pos, s := range new {
		if s != (basics.AccountSlot{}) {
			info = append(info, slotContext{position: pos, AccountSlot: s})
		}
	}

	sort.Sort(info)
	return info
}

func (info gapInfo) search(a basics.Address) (ctx slotContext, err error) {
	if len(info) == 0 {
		return slotContext{}, errPrevGapNotFound(a)
	}

	matches := func(i int) bool {
		return a.Less(info[i].Address)
	}
	// n is first address greater than insert target
	n := sort.Search(len(info), matches)
	if n == 0 {
		n = len(info) // a is minimal; must be in wraparound
	}
	n-- // want last address less than insert target

	// fmt.Printf("search: checking surrounds for slot with addr %v, next %v over %v: result %v\n", info[n].Address, info[n].Next, a, info[n].AccountSlot.Surrounds(a))
	if info[n].AccountSlot.Surrounds(a) {
		return info[n], nil
	}
	return slotContext{}, errPrevGapNotFound(a)
}

func (info gapInfo) Len() int {
	return len(info)
}

func (info gapInfo) Less(i, j int) bool {
	return info[i].Address.Less(info[j].Address)
}

func (info gapInfo) Swap(i, j int) {
	temp := info[i]
	info[i] = info[j]
	info[j] = temp
}

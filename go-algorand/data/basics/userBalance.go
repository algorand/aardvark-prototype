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

package basics

import (
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/vector"
	"github.com/algorand/go-algorand/protocol"
)

// Status is the delegation status of an account's MicroAlgos
type Status byte

const (
	// Offline indicates that the associated account is delegated.
	Offline Status = iota
	// Online indicates that the associated account used as part of the delegation pool.
	Online
	// NotParticipating indicates that the associated account is neither a delegator nor a delegate. Currently it is reserved for the incentive pool.
	NotParticipating
)

func (s Status) String() string {
	switch s {
	case Offline:
		return "Offline"
	case Online:
		return "Online"
	case NotParticipating:
		return "Not Participating"
	}
	return ""
}

// AccountData contains the data associated with a given address.
//
// This includes the account balance, delegation keys, delegation status, and a custom note.
type AccountData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Status     Status     `codec:"onl"`
	MicroAlgos MicroAlgos `codec:"algo"`

	// // RewardsBase is used to implement rewards.
	// // This is not meaningful for accounts with Status=NotParticipating.
	// //
	// // Every block assigns some amount of rewards (algos) to every
	// // participating account.  The amount is the product of how much
	// // block.RewardsLevel increased from the previous block and
	// // how many whole config.Protocol.RewardUnit algos this
	// // account holds.
	// //
	// // For performance reasons, we do not want to walk over every
	// // account to apply these rewards to AccountData.MicroAlgos.  Instead,
	// // we defer applying the rewards until some other transaction
	// // touches that participating account, and at that point, apply all
	// // of the rewards to the account's AccountData.MicroAlgos.
	// //
	// // For correctness, we need to be able to determine how many
	// // total algos are present in the system, including deferred
	// // rewards (deferred in the sense that they have not been
	// // reflected in the account's AccountData.MicroAlgos, as described
	// // above).  To compute this total efficiently, we avoid
	// // compounding rewards (i.e., no rewards on rewards) until
	// // they are applied to AccountData.MicroAlgos.
	// //
	// // Mechanically, RewardsBase stores the block.RewardsLevel
	// // whose rewards are already reflected in AccountData.MicroAlgos.
	// // If the account is Status=Offline or Status=Online, its
	// // effective balance (if a transaction were to be issued
	// // against this account) may be higher, as computed by
	// // AccountData.Money().  That function calls
	// // AccountData.WithUpdatedRewards() to apply the deferred
	// // rewards to AccountData.MicroAlgos.
	// RewardsBase uint64 `codec:"ebase"`

	// // RewardedMicroAlgos is used to track how many algos were given
	// // to this account since the account was first created.
	// //
	// // This field is updated along with RewardBase; note that
	// // it won't answer the question "how many algos did I make in
	// // the past week".
	// RewardedMicroAlgos MicroAlgos `codec:"ern"`

	// VoteID      crypto.OneTimeSignatureVerifier `codec:"vote"`
	// SelectionID crypto.VRFVerifier              `codec:"sel"`

	// VoteFirstValid  Round  `codec:"voteFst"`
	// VoteLastValid   Round  `codec:"voteLst"`
	// VoteKeyDilution uint64 `codec:"voteKD"`
}

// AccountDetail encapsulates meaningful details about a given account, for external consumption
type AccountDetail struct {
	Address Address
	Algos   MicroAlgos
	Status  Status
}

// SupplyDetail encapsulates meaningful details about the ledger's current token supply
type SupplyDetail struct {
	Round       Round
	TotalMoney  MicroAlgos
	OnlineMoney MicroAlgos
}

// BalanceDetail encapsulates meaningful details about the current balances of the ledger, for external consumption
type BalanceDetail struct {
	Round       Round
	TotalMoney  MicroAlgos
	OnlineMoney MicroAlgos
	Accounts    []AccountDetail
}

// MakeAccountData returns a UserToken
func MakeAccountData(status Status, algos MicroAlgos) AccountData {
	return AccountData{MicroAlgos: algos}
}

// Money returns the amount of MicroAlgos associated with the user's account
func (u AccountData) Money(proto config.ConsensusParams, rewardsLevel uint64) (money MicroAlgos, rewards MicroAlgos) {
	e := u.WithUpdatedRewards(proto, rewardsLevel)
	return e.MicroAlgos, e.MicroAlgos
}

// WithUpdatedRewards returns an updated number of algos in an AccountData
// to reflect rewards up to some rewards level.
func (u AccountData) WithUpdatedRewards(proto config.ConsensusParams, rewardsLevel uint64) AccountData {
	// if u.Status != NotParticipating {
	// 	var ot OverflowTracker
	// 	rewardsUnits := u.MicroAlgos.RewardUnits(proto)
	// 	rewardsDelta := ot.Sub(rewardsLevel, u.RewardsBase)
	// 	rewards := MicroAlgos{Raw: ot.Mul(rewardsUnits, rewardsDelta)}
	// 	u.MicroAlgos = ot.AddA(u.MicroAlgos, rewards)
	// 	if ot.Overflowed {
	// 		logging.Base().Panicf("AccountData.WithUpdatedRewards(): overflowed account balance when applying rewards %v + %d*(%d-%d)", u.MicroAlgos, rewardsUnits, rewardsLevel, u.RewardsBase)
	// 	}
	// 	u.RewardsBase = rewardsLevel
	// 	// The total reward over the lifetime of the account could exceed a 64-bit value. As a result
	// 	// this rewardAlgos counter could potentially roll over.
	// 	u.RewardedMicroAlgos = MicroAlgos{Raw: (u.RewardedMicroAlgos.Raw + rewards.Raw)}
	// }

	return u
}

// VotingStake returns the amount of MicroAlgos associated with the user's account
// for the purpose of participating in the Algorand protocol.  It assumes the
// caller has already updated rewards appropriately using WithUpdatedRewards().
func (u AccountData) VotingStake() MicroAlgos {
	// if u.Status != Online {
	// 	return MicroAlgos{Raw: 0}
	// }

	return u.MicroAlgos
}

// KeyDilution returns the key dilution for this account,
// returning the default key dilution if not explicitly specified.
func (u AccountData) KeyDilution(proto config.ConsensusParams) uint64 {
	// if u.VoteKeyDilution != 0 {
	// 	return u.VoteKeyDilution
	// }

	return proto.DefaultKeyDilution
}

// BalanceRecord pairs an account's address with its associated data.
type BalanceRecord struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Addr Address `codec:"addr"`

	AccountData
}

// ToBeHashed implements the crypto.Hashable interface
func (u BalanceRecord) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.BalanceRecord, protocol.Encode(u)
}

// An AccountSlot is the representation of an account as it is committed
// to persistent storage.
type AccountSlot struct {
	_struct     struct{} `codec:",omitempty,omitemptyarray"`
	Address     `codec:"a"`
	AccountData `codec:"d"`

	// the next largest address in Address.Less order.
	Next Address `codec:"n"`
}

func (s AccountSlot) String() string {
	return fmt.Sprintf("{Address: %v, AccountData: %v, Next: %v}", s.Address, s.AccountData, s.Next)
}

// Surrounds returns true if the given address is (exclusively)
// _contained_ in the interval (s.Address, s.Next).
//
// An address a is _contained_ in an interval (x, y) if
//  - x < a < y or
//  - y <= x and either a < y or x < a.
func (s AccountSlot) Surrounds(addr Address) bool {
	if s.Address.Less(s.Next) {
		return s.Address.Less(addr) && addr.Less(s.Next)
	}
	return s.Next.Less(s.Address) && (addr.Less(s.Next) || s.Address.Less(addr))
}

// ToBeHashed implements the crypto.Hashable interface
// TODO replace this with slotDigest, which handles empty slots correctly.
func (s AccountSlot) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.AccountVectorSlot, protocol.Encode(s)
}

// An AccountProof is an AccountSlot along with a cryptographic
// proof of its correctness against some vector.Commitment, identified
// by the account's position.
type AccountProof struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	AccountSlot
	Round        `codec:"r"`
	vector.Proof `codec:"pf"`
	Position     int `codec:"pos"` // TODO uint?
}

// An UnvalidatedAccountProof is an AccountSlot which has not been
// validated.
type UnvalidatedAccountProof struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	AccountSlot
	Round                   `codec:"r"`
	vector.UnvalidatedProof `codec:"pf"`
	Position                int `codec:"pos"` // TODO uint?
}

func (pf AccountProof) String() string {
	return fmt.Sprintf("{Round: %v, Position: %v, AccountSlot: %v, Proof: %v}", pf.Round, pf.Position, pf.AccountSlot, pf.Proof)
}

func (pf UnvalidatedAccountProof) String() string {
	return fmt.Sprintf("{Round: %v, Position: %v, AccountSlot: %v, Proof: %v}", pf.Round, pf.Position, pf.AccountSlot, pf.UnvalidatedProof)
}

// Verify returns true if and only if the given vector commitment
// authenticates the given account slot.
func (pf UnvalidatedAccountProof) Verify(vparams *vector.Parameters, com vector.Commitment) (AccountProof, bool) {
	testpf, ok := pf.UnvalidatedProof.Verify(vparams, crypto.HashObj(pf.AccountSlot), com)
	if ok {
		return AccountProof{AccountSlot: pf.AccountSlot, Round: pf.Round, Proof: testpf, Position: pf.Position}, true
	}
	return AccountProof{}, false
}

// UnsafeDecode extracts a decoded AccountProof from a given
// UnvalidatedProof.
//
// This function is *unsafe*: it should only be called on
// UnvalidatedAccountProofs which have already been validated
// (via Verify).
func (pf UnvalidatedAccountProof) UnsafeDecode(vparams *vector.Parameters) (AccountProof, bool) {
	testpf, ok := pf.UnvalidatedProof.UnsafeDecode(vparams)
	if ok {
		return AccountProof{AccountSlot: pf.AccountSlot, Round: pf.Round, Proof: testpf, Position: pf.Position}, true
	}
	return AccountProof{}, false
}

// Unvalidated converts a AccountProof to an UnvalidatedAccountProof.
func (pf AccountProof) Unvalidated() UnvalidatedAccountProof {
	return UnvalidatedAccountProof{
		AccountSlot:      pf.AccountSlot,
		Round:            pf.Round,
		UnvalidatedProof: pf.Proof.Unvalidated(),
		Position:         pf.Position,
	}
}

// An AccountChunk is a chunk of account slots committed to as a vector.
// It is identified by a sequence number and a round.
type AccountChunk struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	Round   `codec:"rnd"`
	Seq     int           `codec:"seq"`
	Slots   []AccountSlot `codec:"slots"`
}

type AccountTail struct {
	_struct struct{}      `codec:",omitempty,omitemptyarray"`
	Entries []AccountSlot `codec:"t"`
}

func (t AccountTail) Size() int {
	return len(t.Entries)
}

func (t AccountTail) DropFirstVector(params *vector.Parameters) AccountTail {
	t.Entries = t.Entries[params.VectorSize:]
	return t
}

func (t AccountTail) Slots() []AccountSlot {
	return t.Entries
}

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

package transactions

import (
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/vector"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// Txid is a hash used to uniquely identify individual transactions
type Txid crypto.Digest

// String converts txid to a pretty-printable string
func (txid Txid) String() string {
	return fmt.Sprintf("%v", crypto.Digest(txid))
}

// UnmarshalText initializes the Address from an array of bytes.
func (txid *Txid) UnmarshalText(text []byte) error {
	d, err := crypto.DigestFromString(string(text))
	*txid = Txid(d)
	return err
}

// SpecialAddresses holds addresses with nonstandard properties.
type SpecialAddresses struct {
	FeeSink     basics.Address
	RewardsPool basics.Address
}

// Balances allow to move MicroAlgos from one address to another and to update balance records, or to access and modify individual balance records
// After a call to Put (or Move), future calls to Get or Move will reflect the updated balance record(s)
type Balances interface {
	// Get looks up the balance record for an address
	// If the account is known to be empty, then err should be nil and the returned balance record should have the given address and empty AccountData
	// A non-nil error means the lookup is impossible (e.g., if the database doesn't have necessary state anymore)
	Get(basics.Address, basics.AccountProof) (basics.BalanceRecord, error)

	Put(basics.BalanceRecord, basics.AccountProof) error
	Clear(addr basics.Address, curr, prev basics.AccountProof) error

	// Move MicroAlgos from one account to another, doing all necessary overflow checking (convenience method)
	// TODO: Does this need to be part of the balances interface, or can it just be implemented here as a function that calls Put and Get?
	Move(src, dst basics.Address, srcPf, dstPf basics.AccountProof, amount basics.MicroAlgos, srcRewards *basics.MicroAlgos, dstRewards *basics.MicroAlgos) error

	// Balances correspond to a Round, which mean that they also correspond
	// to a ConsensusParams.  This returns those parameters.
	ConsensusParams() config.ConsensusParams
}

// An Archive answers queries for AccountProofs for a given Address at a given Round.
type Archive interface {
	LookupProof(basics.Round, basics.Address) (basics.AccountProof, error)

	// LookupPrevProof is like LookupProof except it returns the proof of the address's predecessor.
	LookupPrevProof(basics.Round, basics.Address) (basics.AccountProof, error)
}

// A VectorCommitmentDB answers queries for vector commitments for a given Address at a given Round and index.
type VectorCommitmentDB interface {
	Params() *vector.Parameters
	Get(rnd basics.Round, n int) (vector.Commitment, error)
}

// Header captures the fields common to every transaction type.
type Header struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sender     basics.Address `codec:"snd"`
	FirstValid basics.Round   `codec:"fv"`
	LastValid  basics.Round   `codec:"lv"`
}

// Transaction describes a transaction that can appear in a block.
type Transaction struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Type of transaction
	Type protocol.TxType `codec:"type"`

	// Common fields for all types of transactions
	Header

	// NewValue, if specified, is the value written by Modify or Create
	NewValue basics.AccountData

	// Fields for different types of transactions
	// KeyregTxnFields
	// PaymentTxnFields

	Nonce [32]byte

	// The transaction's Txid is computed when we decode,
	// and cached here, to avoid needlessly recomputing it.
	cachedTxid Txid

	// The valid flag indicates if this transaction was
	// correctly decoded.
	valid bool
}

// ToBeHashed implements the crypto.Hashable interface.
func (tx Transaction) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Transaction, protocol.Encode(tx)
}

func (tx *Transaction) computeID() Txid {
	return Txid(crypto.HashObj(tx))
}

// InitCaches initializes caches inside of Transaction.
func (tx *Transaction) InitCaches() {
	if !tx.valid {
		tx.cachedTxid = tx.computeID()
		tx.valid = true
	}
}

// ResetCaches clears caches inside of Transaction, if the Transaction was modified.
func (tx *Transaction) ResetCaches() {
	tx.valid = false
}

// ID returns the Txid (i.e., hash) of the transaction.
// For efficiency this is precomputed when the Transaction is created.
func (tx Transaction) ID() Txid {
	if tx.valid {
		return tx.cachedTxid
	}
	return tx.computeID()
}

// Sign signs a transaction using a given Account's secrets.
func (tx Transaction) Sign(secrets *crypto.SignatureSecrets) SignedTxn {
	sig := secrets.Sign(tx)

	s := SignedTxn{
		Txn: tx,
		Sig: sig,
	}
	s.InitCaches()
	return s
}

// Src returns the address that posted the transaction.
// This is the account that pays the associated Fee.
func (tx Header) Src() basics.Address {
	return tx.Sender
}

// Alive checks to see if the transaction is still alive (can be applied) at the specified Round.
func (tx Header) Alive(tc TxnContext) error {
	// Check round validity
	round := tc.Round()
	if round < tx.FirstValid || round > tx.LastValid {
		return TxnDeadError{
			Round:      round,
			FirstValid: tx.FirstValid,
			LastValid:  tx.LastValid,
		}
	}

	return nil
}

// MatchAddress checks if the transaction touches a given address.
func (tx Transaction) MatchAddress(addr basics.Address, spec SpecialAddresses, proto config.ConsensusParams) bool {
	for _, candidate := range tx.RelevantAddrs(spec, proto) {
		if addr == candidate {
			return true
		}
	}
	return false
}

// WellFormed checks that the transaction looks reasonable on its own (but not necessarily valid against the actual ledger). It does not check signatures.
func (tx Transaction) WellFormed(spec SpecialAddresses, proto config.ConsensusParams) error {
	switch tx.Type {
	case protocol.Modify, protocol.Create:
		if tx.NewValue == (basics.AccountData{}) {
			return fmt.Errorf("%s new value should not be empty", tx.Type)
		}
	case protocol.Delete:
		if tx.NewValue != (basics.AccountData{}) {
			return fmt.Errorf("Delete new value should be empty but is %v", tx.NewValue)
		}
	default:
		return fmt.Errorf("unknown tx type %v", tx.Type)
	}

	if tx.LastValid < tx.FirstValid {
		return fmt.Errorf("transaction invalid range (%v--%v)", tx.FirstValid, tx.LastValid)
	}
	if tx.LastValid-tx.FirstValid > basics.Round(proto.MaxTxnLife) {
		return fmt.Errorf("transaction window size excessive (%v--%v)", tx.FirstValid, tx.LastValid)
	}
	return nil
}

// First returns the first round this transaction is valid
func (tx Header) First() basics.Round {
	return tx.FirstValid
}

// Last returns the first round this transaction is valid
func (tx Header) Last() basics.Round {
	return tx.LastValid
}

// RelevantAddrs returns the addresses whose balance records this transaction will need to access.
// The header's default is to return just the sender and the fee sink.
func (tx Transaction) RelevantAddrs(spec SpecialAddresses, proto config.ConsensusParams) []basics.Address {
	addrs := []basics.Address{tx.Sender}

	// switch tx.Type {
	// case protocol.PaymentTx:
	// 	addrs = append(addrs, tx.PaymentTxnFields.Receiver)
	// 	if tx.PaymentTxnFields.CloseRemainderTo != (basics.Address{}) {
	// 		addrs = append(addrs, tx.PaymentTxnFields.CloseRemainderTo)
	// 	}
	// }

	return addrs
}

func randAccountProof(pf *basics.AccountProof) {
	// TODO
}

// Prove returns the latest TransactionProof for this transaction given an Archive to query.
func (tx Transaction) Prove(orcl Archive, spec SpecialAddresses) (pf TransactionProof, err error) {
	if tx.Type == protocol.Delete {
		clspf, err := orcl.LookupProof(tx.FirstValid.SubSaturate(1), tx.Sender)
		if err != nil {
			panic(err)
		}

		prevpf, err := orcl.LookupPrevProof(tx.FirstValid.SubSaturate(1), tx.Sender)
		if err != nil {
			panic(err)
		}

		pf.Close = clspf
		pf.ClosePrev = prevpf

		if pf.Close.Address != tx.Sender {
			if pf.Close.AccountSlot.Surrounds(tx.Sender) {
				return TransactionProof{}, errAlreadyDeleted(tx.Sender)
			}

			return TransactionProof{}, fmt.Errorf("pf.Close.Address != tx.Sender: %v != %v", pf.Close.Address, tx.Sender)
		}
		if pf.ClosePrev.Next != tx.Sender {
			return TransactionProof{}, fmt.Errorf("pf.ClosePrev.Next != tx.Sender: %v != %v", pf.ClosePrev.Next, tx.Sender)
		}
	} else {
		sndpf, err := orcl.LookupProof(tx.FirstValid.SubSaturate(1), tx.Sender)
		if err != nil {
			panic(err)
		}
		pf.Sender = sndpf

		if tx.Type == protocol.Modify {
			if pf.Sender.Address != tx.Sender {
				return TransactionProof{}, fmt.Errorf("pf.Sender.Address != tx.Sender: %v != %v", pf.Sender.Address, tx.Sender)
			}
		} else {
			if !pf.Sender.AccountSlot.Surrounds(tx.Sender) {
				return TransactionProof{}, fmt.Errorf("!pf.Sender.AccountSlot.Surrounds(tx.Sender); s=%v, tx.Sender=%v", pf.Sender.AccountSlot, tx.Sender)
			}
		}
	}
	return
}

type errAlreadyDeleted basics.Address

func (err errAlreadyDeleted) Error() string {
	return fmt.Sprintf("%s already deleted", basics.Address(err))
}

func IsAlreadyDeleted(err error) bool {
	_, ok := err.(errAlreadyDeleted)
	return ok
}

// ValidateProof returns an error if the given TransactionProof is an
// invalid proof of the Transaction's modified AccountData.
func (tx Transaction) ValidateProof(vcdb VectorCommitmentDB, spec SpecialAddresses, pf UnvalidatedTransactionProof) (okpf TransactionProof, err error) {
	var oksnd, okcls, okprv basics.AccountProof

	if tx.Type == protocol.Delete {
		if pf.Close.Address != tx.Sender {
			return TransactionProof{}, fmt.Errorf("pf.Close.Address != tx.Sender: %v != %v", pf.Close.Address, tx.Sender)
		}
		if pf.ClosePrev.Next != tx.Sender {
			return TransactionProof{}, fmt.Errorf("pf.ClosePrev.Next != tx.Sender: %v != %v", pf.ClosePrev.Next, tx.Sender)
		}

		okcls, err = verifyTransactionSlot(pf.Close, tx.FirstValid.SubSaturate(1), vcdb)
		if err != nil {
			return
		}
		okprv, err = verifyTransactionSlot(pf.ClosePrev, tx.FirstValid.SubSaturate(1), vcdb)
		if err != nil {
			return
		}
	} else {
		if tx.Type == protocol.Modify {
			if pf.Sender.Address != tx.Sender {
				return TransactionProof{}, fmt.Errorf("pf.Sender.Address != tx.Sender: %v != %v", pf.Sender.Address, tx.Sender)
			}
		} else {
			if !pf.Sender.AccountSlot.Surrounds(tx.Sender) {
				return TransactionProof{}, fmt.Errorf("!pf.Sender.AccountSlot.Surrounds(tx.Sender); s=%v, tx.Sender=%v", pf.Sender.AccountSlot, tx.Sender)
			}
		}

		oksnd, err = verifyTransactionSlot(pf.Sender, tx.FirstValid.SubSaturate(1), vcdb)
		if err != nil {
			return
		}
	}

	okpf.Sender = oksnd
	okpf.Close = okcls
	okpf.ClosePrev = okprv
	return
}

func verifyTransactionSlot(pf basics.UnvalidatedAccountProof, rnd basics.Round, vcdb VectorCommitmentDB) (basics.AccountProof, error) {
	params := vcdb.Params()
	com, err := vcdb.Get(rnd, pf.Position/int(params.VectorSize))
	if err != nil {
		return basics.AccountProof{}, err
	}

	testpf, ok := pf.Verify(params, com)
	if !ok {
		return basics.AccountProof{}, fmt.Errorf("proof failed to verify against commitment @%d: %v", pf.Position/int(params.VectorSize), com.ToBytes())
	}
	return testpf, nil
}

func (tx Transaction) unsafeDecodeProof(vcdb VectorCommitmentDB, pf UnvalidatedTransactionProof) (okpf TransactionProof, err error) {
	var oksnd, okcls, okprv basics.AccountProof

	if tx.Type == protocol.Delete {
		okcls, err = unsafeDecodeTransactionSlot(pf.Close, vcdb)
		if err != nil {
			return
		}
		okprv, err = unsafeDecodeTransactionSlot(pf.ClosePrev, vcdb)
		if err != nil {
			return
		}
	} else {
		oksnd, err = unsafeDecodeTransactionSlot(pf.Sender, vcdb)
		if err != nil {
			return
		}
	}

	okpf.Sender = oksnd
	okpf.Close = okcls
	okpf.ClosePrev = okprv
	return
}

func unsafeDecodeTransactionSlot(pf basics.UnvalidatedAccountProof, vcdb VectorCommitmentDB) (basics.AccountProof, error) {
	params := vcdb.Params()
	okpf, ok := pf.UnsafeDecode(params)
	if !ok {
		return basics.AccountProof{}, fmt.Errorf("failed to decode account proof")
	}
	return okpf, nil
}

// Apply changes the balances according to this transaction.
func (tx Transaction) Apply(balances Balances, pf TransactionProof, spec SpecialAddresses) (err error) {
	switch tx.Type {
	case protocol.Modify, protocol.Create:
		record := basics.BalanceRecord{
			Addr:        tx.Sender,
			AccountData: tx.NewValue,
		}
		err = balances.Put(record, pf.Sender)
	case protocol.Delete:
		err = balances.Clear(tx.Sender, pf.Close, pf.ClosePrev)
	default:
		err = fmt.Errorf("Unknown transaction type %v", tx.Type)
	}

	return
}

// TxnContext describes the context in which a transaction can appear
// (pretty much, a block, but we don't have the definition of a block
// here, since that would be a circular dependency).  This is used to
// decide if a transaction is alive or not.
type TxnContext interface {
	Round() basics.Round
	ConsensusProtocol() config.ConsensusParams
	GenesisID() string
	GenesisHash() crypto.Digest
}

// ExplicitTxnContext is a struct that implements TxnContext with
// explicit fields for everything.
type ExplicitTxnContext struct {
	ExplicitRound basics.Round
	Proto         config.ConsensusParams
	GenID         string
	GenHash       crypto.Digest
}

// Round implements the TxnContext interface
func (tc ExplicitTxnContext) Round() basics.Round {
	return tc.ExplicitRound
}

// ConsensusProtocol implements the TxnContext interface
func (tc ExplicitTxnContext) ConsensusProtocol() config.ConsensusParams {
	return tc.Proto
}

// GenesisID implements the TxnContext interface
func (tc ExplicitTxnContext) GenesisID() string {
	return tc.GenID
}

// GenesisHash implements the TxnContext interface
func (tc ExplicitTxnContext) GenesisHash() crypto.Digest {
	return tc.GenHash
}

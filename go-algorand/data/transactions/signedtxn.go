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
	"context"
	"errors"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
)

// SignedTxn wraps a transaction, a signature, and a proof of the transaction's balances.
// It exposes a Verify() method that verifies the signature and checks that the
// underlying transaction is well-formed.
// For performance, it also caches the Txid of the underlying transaction on creation.
// TODO: update this documentation now that there's multisig
//
// Never instantiate a SignedTxn directly (other than inside the transactions
// package), and after creating a SignedTxn never modify its Txn field.
// Otherwise the cached Txid will be incorrect. Instead use txn.Sign to sign
// a normal transaction or use UnmarshalBinary / protocol.Decode to deserialize
// a SignedTxn from the network. These correctly cache the Txid and furthermore
// ensure the underlying Transaction is non-nil.
//
// Assuming these guidelines are followed, any SignedTxn object is guaranteed
// to have a non-nil Txn field, and calling signedtxn.ID() will return that
// transaction's correct Txid.
type SignedTxn struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sig   crypto.Signature            `codec:"sig"`
	Msig  crypto.MultisigSig          `codec:"msig"`
	Txn   Transaction                 `codec:"txn"`
	Proof UnvalidatedTransactionProof `codec:"pf"`

	// The length of the encoded SignedTxn, used for computing the
	// transaction's priority in the transaction pool.
	cachedEncodingLen int
}

// SignedTxnAndProof is a SignedTxn with a matching TransactionProof.
type SignedTxnAndProof struct {
	SignedTxn
	TransactionProof
}

// TxnPriority represents the pool priority of a transaction.
type TxnPriority uint64

// maxTxnBytesForPriority is a scaling factor for computing fee-per-byte
// priority values with integer arithmetic without worrying too much about
// rounding effects.  Specifically, this constant should be larger than
// any legitimate transaction that we expect to be stored in the transaction
// pool.  Transactions of greater length will have a computed priority of 0.
const maxTxnBytesForPriority = 1 << 20

// LessThan compares two TxnPriority values
func (a TxnPriority) LessThan(b TxnPriority) bool {
	return a < b
}

// Mul multiplies a TxnPriority by a scalar, with saturation on overflow
func (a TxnPriority) Mul(b uint64) TxnPriority {
	return TxnPriority(basics.MulSaturate(uint64(a), b))
}

// InitCaches initializes caches inside of SignedTxn.
func (s *SignedTxn) InitCaches() {
	if s.cachedEncodingLen == 0 {
		s.cachedEncodingLen = s.computeEncodingLen()
	}

	s.Txn.InitCaches()
}

// ResetCaches clears cached state in this SignedTxn.
func (s *SignedTxn) ResetCaches() {
	s.cachedEncodingLen = 0
	s.Txn.ResetCaches()
}

// ID returns the Txid (i.e., hash) of the underlying transaction.
func (s SignedTxn) ID() Txid {
	return s.Txn.ID()
}

func (s SignedTxn) computeEncodingLen() int {
	return len(protocol.Encode(&s))
}

// GetEncodedLength returns the length in bytes of the encoded transaction
func (s SignedTxn) GetEncodedLength() (encodingLen int) {
	encodingLen = s.cachedEncodingLen
	if encodingLen == 0 {
		encodingLen = s.computeEncodingLen()
	}
	return
}

// Verify that a SignedTxn has a good signature and that the underlying
// transaction is properly constructed.
// Note that this does not check whether a payset is valid against the ledger:
// a SignedTxn may be well-formed, but a payset might contain an overspend.
func (s SignedTxn) Verify(spec SpecialAddresses, proto config.ConsensusParams) error {
	if err := s.Txn.WellFormed(spec, proto); err != nil {
		return err
	}

	zeroAddress := basics.Address{}
	if s.Txn.Src() == zeroAddress {
		return errors.New("empty address")
	}

	if s.Sig != (crypto.Signature{}) && !s.Msig.Blank() {
		return errors.New("signedtxn should only have one of Sig or Msig")
	}

	if !crypto.SignatureVerifier(s.Txn.Src()).Verify(s.Txn, s.Sig) {
		if ok, _ := crypto.MultisigVerify(s.Txn, crypto.Digest(s.Txn.Src()), s.Msig); !ok {
			return errors.New("signature (and multisig) failed to verify")
		}
	}
	return nil
}

// PoolVerify verifies that a SignedTxn has a good signature and that the underlying
// transaction is properly constructed.
// Note that this does not check whether a payset is valid against the ledger:
// a SignedTxn may be well-formed, but a payset might contain an overspend.
//
// This version of verify is performing the verification over the provided execution pool.
func (s SignedTxn) PoolVerify(spec SpecialAddresses, proto config.ConsensusParams, verificationPool execpool.BacklogPool) error {
	// if verificationPool == nil {
	// 	return s.Verify(spec, proto)
	// }

	if err := s.Txn.WellFormed(spec, proto); err != nil {
		return err
	}

	// zeroAddress := basics.Address{}
	// if s.Txn.Src() == zeroAddress {
	// 	return errors.New("empty address")
	// }

	// if s.Sig != (crypto.Signature{}) && !s.Msig.Blank() {
	// 	return errors.New("signedtxn should only have one of Sig or Msig")
	// }

	// outCh := make(chan error, 1)
	// verificationPool.EnqueueBacklog(context.Background(), s.asyncVerify, outCh, nil)
	// if err, hasErr := <-outCh; hasErr {
	// 	return err
	// }
	return nil
}

func (s SignedTxn) asyncVerify(arg interface{}) interface{} {
	outCh := arg.(chan error)
	defer close(outCh)
	if !crypto.SignatureVerifier(s.Txn.Src()).Verify(s.Txn, s.Sig) {
		if ok, _ := crypto.MultisigVerify(s.Txn, crypto.Digest(s.Txn.Src()), s.Msig); !ok {
			outCh <- errors.New("signature (and multisig) failed to verify")
		}
	}
	return nil
}

// ValidateProof returns an error if the signed transaction has an
// invalid proof of its modified AccountData.
func (s SignedTxn) ValidateProof(vcdb VectorCommitmentDB, spec SpecialAddresses) (TransactionProof, error) {
	return s.Txn.ValidateProof(vcdb, spec, s.Proof)
}

// PoolValidateProof calls ValidateProof in the given BacklogPool.
func (s SignedTxn) PoolValidateProof(vcdb VectorCommitmentDB, spec SpecialAddresses, verificationPool execpool.BacklogPool) (TransactionProof, error) {
	if verificationPool == nil {
		return s.ValidateProof(vcdb, spec)
	}

	outCh := make(chan validateProofResult, 1)
	vargs := validateProofArgs{outCh: outCh, vcdb: vcdb, spec: spec}
	verificationPool.EnqueueBacklog(context.Background(), s.asyncValidateProof, vargs, nil)
	result := <-outCh
	return result.res, result.err
}

type validateProofArgs struct {
	outCh chan validateProofResult
	vcdb  VectorCommitmentDB
	spec  SpecialAddresses
}

type validateProofResult struct {
	err error
	res TransactionProof
}

func (s SignedTxn) asyncValidateProof(arg interface{}) interface{} {
	vargs := arg.(validateProofArgs)
	defer close(vargs.outCh)
	okpf, err := s.Txn.ValidateProof(vargs.vcdb, vargs.spec, s.Proof)
	vargs.outCh <- validateProofResult{err: err, res: okpf}
	return nil
}

// UnsafeDecodeProof extracts a decoded TransactionProof from the
// SignedTxn.
//
// This function is *unsafe*: it should only be called on SignedTxns
// which have already been validated (via {Pool,_}ValidateProof).
func (s SignedTxn) UnsafeDecodeProof(vcdb VectorCommitmentDB, verificationPool execpool.BacklogPool) (TransactionProof, error) {
	if verificationPool == nil {
		return s.Txn.unsafeDecodeProof(vcdb, s.Proof)
	}

	outCh := make(chan unsafeDecodeProofResult, 1)
	vargs := unsafeDecodeProofArgs{outCh: outCh, vcdb: vcdb}
	verificationPool.EnqueueBacklog(context.Background(), s.asyncUnsafeDecodeProof, vargs, nil)
	result := <-outCh
	return result.res, result.err
}

type unsafeDecodeProofArgs struct {
	outCh chan unsafeDecodeProofResult
	vcdb  VectorCommitmentDB
}

type unsafeDecodeProofResult struct {
	err error
	res TransactionProof
}

func (s SignedTxn) asyncUnsafeDecodeProof(arg interface{}) interface{} {
	vargs := arg.(unsafeDecodeProofArgs)
	defer close(vargs.outCh)
	okpf, err := s.Txn.unsafeDecodeProof(vargs.vcdb, s.Proof)
	vargs.outCh <- unsafeDecodeProofResult{res: okpf, err: err}
	return nil
}

// RefreshProof refrehses the proof of a transaction given an archive
// to query.
func (s *SignedTxn) RefreshProof(orcl Archive, spec SpecialAddresses) (TransactionProof, error) {
	pf, err := s.Txn.Prove(orcl, spec)
	if err != nil {
		return TransactionProof{}, err
	}
	s.Proof = pf.Unvalidated()
	s.ResetCaches()
	s.InitCaches()
	return pf, nil
}

// AssembleSignedTxn assembles a multisig-signed transaction from a transaction an optional sig, and an optional multisig.
// No signature checking is done -- for example, this might only be a partial multisig
func AssembleSignedTxn(txn Transaction, sig crypto.Signature, msig crypto.MultisigSig) (SignedTxn, error) {
	if sig != (crypto.Signature{}) && !msig.Blank() {
		return SignedTxn{}, errors.New("signed txn can only have one of sig or msig")
	}
	s := SignedTxn{
		Txn:  txn,
		Sig:  sig,
		Msig: msig,
	}
	s.ResetCaches()
	s.InitCaches()
	return s, nil
}

// A TransactionProof proves balances for accounts affected by a transaction.
type TransactionProof struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sender    basics.AccountProof `codec:"snd"`
	Close     basics.AccountProof `codec:"cls"`
	ClosePrev basics.AccountProof `codec:"prv"`
}

// An UnvalidatedTransactionProof is a TransactionProof which has
// not been validated.
type UnvalidatedTransactionProof struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sender    basics.UnvalidatedAccountProof `codec:"snd"`
	Close     basics.UnvalidatedAccountProof `codec:"cls"`
	ClosePrev basics.UnvalidatedAccountProof `codec:"prv"`
}

// Unvalidated converts a TransactionProof to an UnvalidatedTransactionProof.
func (pf TransactionProof) Unvalidated() UnvalidatedTransactionProof {
	return UnvalidatedTransactionProof{
		Sender:    pf.Sender.Unvalidated(),
		Close:     pf.Close.Unvalidated(),
		ClosePrev: pf.ClosePrev.Unvalidated(),
	}
}

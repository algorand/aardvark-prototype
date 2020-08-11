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

package vector

import (
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	veccom "github.com/algorand/veccom-rust"
)

// Parameters are the public parameters used to setup the
// BLS12-381 elliptic-curve pairings used in vector commitments.
type Parameters struct {
	VectorSize uint // the vector size these parameters are good for

	prover   *veccom.Prover
	verifier *veccom.Verifier
}

// MakeParameters is used to generate new parameters for a given
// vector size.
//
// It uses a zero seed.
//
// This function should be removed once public parameter generation
// is executed.
func MakeParameters(comSize uint) *Parameters {
	if comSize == 0 {
		panic("vector.MakeParameters: comSize = 0")
	}

	var seed [32]uint8                             // TODO seed is unset
	p, v := veccom.ParamGen(seed[:], int(comSize)) // TODO cast should be unnecessary?
	return &Parameters{VectorSize: comSize, prover: p, verifier: v}
}

// A Commitment commits to a vector of Digests.
type Commitment veccom.Commitment

// A Proof proves the validity of some data against a Commitment.
type Proof veccom.Proof

// An UnvalidatedProof is a Proof which has not yet been validated.
type UnvalidatedProof struct {
	G1    [48]byte
	Index int
}

// Commit1 is a convenience function that calls Commit with the first
// element set to the given Digest.
func Commit1(p *Parameters, d crypto.Digest) Commitment {
	slots := make([]crypto.Digest, p.VectorSize)
	slots[0] = d
	return Commit(p, slots)
}

// Commit commits to a vector of Digests given some public parameters.
//
// Precondition: p.VectorSize = len(d)
func Commit(p *Parameters, d []crypto.Digest) Commitment {
	if uint(len(d)) != p.VectorSize { // guarantees that caller cannot pass in short slice
		panic(fmt.Errorf("vector.Commit: len(d) != p.VectorSize: %v != %v", len(d), p.VectorSize))
	}

	x := make([][]byte, p.VectorSize)
	for i := range d {
		x[i] = d[i][:]
	}

	return Commitment(p.prover.Commit(x))
}

// Open produces a proof associated with a vector of Digests at some
// given index.
//
// Precondition: p.VectorSize = len(d)
// Precondition: p.VectorSize > i
func Open(p *Parameters, d []crypto.Digest, i int) Proof {
	if uint(len(d)) != p.VectorSize { // guarantees that caller cannot pass in short slice
		panic(fmt.Errorf("vector.Commit: len(d) != p.VectorSize: %v != %v", len(d), p.VectorSize))
	}
	if uint(i) >= p.VectorSize { // TODO check necessary given libveccom?
		panic(fmt.Errorf("vector.Open: i >= p.VectorSize: %v > %v", i, p.VectorSize))
	}

	x := make([][]byte, p.VectorSize)
	for i := range d {
		x[i] = d[i][:]
	}

	return Proof(p.prover.Prove(x, i))
}

// Verify verifies a proof of a Digest against the given commitment.
func (pf UnvalidatedProof) Verify(p *Parameters, d crypto.Digest, com Commitment) (Proof, bool) {
	g1, err := veccom.BytesToG1(pf.G1)
	if err != nil {
		return Proof{}, false
	}

	if pf.Index < 0 || uint(pf.Index) >= p.VectorSize {
		return Proof{}, false
	}

	testpf := veccom.Proof{G1: g1, Index: pf.Index}

	ok := p.verifier.Verify(veccom.Commitment(com), testpf, d[:])
	if !ok {
		return Proof{}, false
	}
	return Proof(testpf), true
}

// UnsafeDecode extracts a decoded Proof from an UnvalidatedProof.
//
// This function is *unsafe*: it should only be called on Proofs
// which have already been validated (via Verify).
func (pf UnvalidatedProof) UnsafeDecode(p *Parameters) (Proof, bool) {
	g1, err := veccom.BytesToG1(pf.G1)
	if err != nil {
		return Proof{}, false
	}

	return Proof{G1: g1, Index: pf.Index}, true
}

// Unvalidated converts a Proof to an UnvalidatedProof.
func (pf Proof) Unvalidated() (u UnvalidatedProof) {
	if pf.G1 != nil {
		u.G1 = pf.G1.ToBytes()
	}

	u.Index = pf.Index
	return u
}

// Update updates this proof given that the vector at index i has
// some old Digest which is overwritten by some new Digest.
func (pf Proof) Update(p *Parameters, i int, old, new crypto.Digest) Proof {
	if uint(i) >= p.VectorSize { // TODO check necessary given libveccom?
		panic(fmt.Errorf("vector.Proof.Update: i >= p.VectorSize: %v > %v", i, p.VectorSize))
	}

	if old == new {
		panic(fmt.Errorf("vector.Proof.update: old = new: %v = %v", old, new))
	}

	if i != pf.Index {
		return Proof(p.prover.ProofUpdate(veccom.Proof(pf), i, old[:], new[:]))
	}
	return pf
}

// Update updates this commitment given that the vector at index i has
// some old Digest which is overwritten by some new Digest.
func (c Commitment) Update(p *Parameters, i int, old, new crypto.Digest) Commitment {
	if uint(i) >= p.VectorSize { // TODO check necessary given libveccom?
		panic(fmt.Errorf("vector.Commitment.Update: i >= p.VectorSize: %v > %v", i, p.VectorSize))
	}

	return Commitment(p.prover.CommitUpdate(veccom.Commitment(c), i, old[:], new[:]))
}

// ToBytes serializes a commitment to bytes.
func (c Commitment) ToBytes() [48]byte {
	return veccom.Commitment(c).G1.ToBytes()
}

// CommitmentFromBytes deserializes a commitment from bytes.
func CommitmentFromBytes(buf [48]byte) Commitment {
	g1, err := veccom.BytesToG1(buf)
	if err != nil {
		panic(err)
	}
	return Commitment(veccom.Commitment{G1: g1})
}

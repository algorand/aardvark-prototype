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

package node

import (
	"encoding/base64"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

type netPrioResponse struct {
	Nonce string
}

type netPrioResponseSigned struct {
	// Round    basics.Round
	Response netPrioResponse
	Proof    basics.UnvalidatedAccountProof
	Sig      crypto.OneTimeSignature
}

func (npr netPrioResponse) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.NetPrioResponse, protocol.Encode(npr)
}

// NewPrioChallenge implements the network.NetPrioScheme interface
func (node *AlgorandFullNode) NewPrioChallenge() string {
	var rand [32]byte
	crypto.RandBytes(rand[:])
	return base64.StdEncoding.EncodeToString(rand[:])
}

// MakePrioResponse implements the network.NetPrioScheme interface
func (node *AlgorandFullNode) MakePrioResponse(challenge string) []byte {
	if !node.config.AnnounceParticipationKey {
		return nil
	}

	rs := netPrioResponseSigned{
		Response: netPrioResponse{
			Nonce: challenge,
		},
	}

	// Find the participation key that has the highest weight in the
	// latest round.
	var maxWeight uint64
	var maxPart account.Participation
	var maxProof basics.AccountProof

	latest := node.ledger.LastRound()
	proto, err := node.ledger.ConsensusParams(latest)
	if err != nil {
		return nil
	}

	voteRound := latest
	for _, part := range node.accountManager.Keys(voteRound) {
		weight := part.AccountProof.MicroAlgos.ToUint64()
		if weight > maxWeight {
			maxPart = part.Participation
			maxWeight = weight
			maxProof = part.AccountProof
		}
	}

	if maxWeight == 0 {
		return nil
	}

	signer := maxPart.VotingSigner()
	ephID := basics.OneTimeIDForRound(voteRound, signer.KeyDilution(proto))

	rs.Proof = maxProof.Unvalidated()
	rs.Sig = signer.Sign(ephID, rs.Response)

	return protocol.Encode(rs)
}

// VerifyPrioResponse implements the network.NetPrioScheme interface
func (node *AlgorandFullNode) VerifyPrioResponse(challenge string, response []byte) (addr basics.Address, err error) {
	var rs netPrioResponseSigned
	err = protocol.Decode(response, &rs)
	if err != nil {
		return
	}

	if rs.Response.Nonce != challenge {
		err = fmt.Errorf("challenge/response mismatch")
		return
	}

	proto, err := node.ledger.ConsensusParams(rs.Proof.Round)
	if err != nil {
		return
	}

	pf, err := node.ledger.VerifyAccountProof(rs.Proof)
	if err != nil {
		return
	}
	data := pf.AccountData

	ephID := basics.OneTimeIDForRound(pf.Round, data.KeyDilution(proto))
	if !data.VoteID.Verify(ephID, rs.Response, rs.Sig) {
		err = fmt.Errorf("signature verification failure")
		return
	}

	addr = rs.Proof.Address
	return
}

// GetPrioWeight implements the network.NetPrioScheme interface
func (node *AlgorandFullNode) GetPrioWeight(addr basics.Address) uint64 {
	latest := node.ledger.LastRound()
	data, err := node.ledger.Lookup(latest, addr)
	if err != nil {
		return 0
	}

	return data.MicroAlgos.ToUint64()
}

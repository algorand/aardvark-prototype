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

package rpcs

import (
	"context"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

// AccountService serves requests for account proofs.
type AccountService struct {
	ledger    *ledger.Ledger
	genesisID string
	reqs      chan network.IncomingMessage
	stop      chan struct{}
}

const maxConcurrentAccountRequests = 1000 // TODO move to config.Local
const maxConcurrentRequestsProcessed = 16 // TODO make GOMAXPROCS?

// AccountServiceBlockPath is the path to register AccountService as a handler for when using gorilla/mux
// e.g. .Handle(AccountServiceBlockPath, &as)
// const AccountServiceBlockPath = "/v{version:[0-9.]+}/{genesisID}/account/{round:[0-9a-z]+}" TODO

func RegisterAccountService(config config.Local, ledger *ledger.Ledger, registrar Registrar) *AccountService {
	service := &AccountService{ledger: ledger}
	// registrar.RegisterHTTPHandler(AccountServiceBlockPath, service)
	// c := make(chan network.IncomingMessage, config.MaxConcurrentAccountRequests)
	c := make(chan network.IncomingMessage, maxConcurrentAccountRequests)

	handlers := []network.TaggedMessageHandler{
		{Tag: protocol.UniAccountReqTag, MessageHandler: network.HandlerFunc(service.processIncomingMessage)},
		{Tag: protocol.UniDecommitReqTag, MessageHandler: network.HandlerFunc(service.processIncomingMessage)},
	}

	registrar.RegisterHandlers(handlers)
	service.reqs = c
	service.stop = make(chan struct{})

	return service
}

// Start listening to account requests over ws.
func (as *AccountService) Start() {
	for i := 0; i < maxConcurrentRequestsProcessed; i++ {
		go as.listenForAccountReq(as.reqs, as.stop)
	}
}

// Stop listening to account requests over ws.
func (as *AccountService) Stop() {
	close(as.stop)
}

func (as *AccountService) processIncomingMessage(msg network.IncomingMessage) (n network.OutgoingMessage) {
	// don't block - just stick in a slightly buffered channel if possible
	select {
	case as.reqs <- msg:
	default:
	}
	// don't return outgoing message, we just unicast instead
	return
}

// listenForAccountReq handles account requests.
func (as *AccountService) listenForAccountReq(reqs <-chan network.IncomingMessage, stop chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for {
		select {
		case reqMsg := <-reqs:
			switch reqMsg.Tag {
			case protocol.UniAccountReqTag:
				as.handleAccountReq(ctx, reqMsg)
			case protocol.UniDecommitReqTag:
				as.handleDecommitReq(ctx, reqMsg)
			default:
				logging.Base().Errorf("AccountService received bad tag from peer: %v", reqMsg.Tag)
			}
		case <-stop:
			return
		}
	}
}

// wsGetAccountRequest is a msgpack message requesting an account proof
type wsGetAccountRequest struct {
	ID      uint64         `json:"id"` // random request ID
	Round   basics.Round   `json:"round"`
	Address basics.Address `json:"addr"`
	Prev    bool           `json:"prev"`
}

// wsGetAccountOut is a msgpack message delivered on responding to a account (not rpc-based though)
type wsGetAccountOut struct {
	ID           uint64         `json:"id"` // must match request ID
	Round        basics.Round   `json:"round"`
	Address      basics.Address `json:"addr"`
	Prev         bool           `json:"prev"`
	NoRetry      bool           `json:"noretry"` // this is a hint for the client to stop sending requests to this server
	Error        string         `json:"error"`
	AccountBytes []byte         `json:"accountbytes"`
}

// wsGetDecommitmentRequest is a msgpack message requesting an account decommitment
type wsGetDecommitmentRequest struct {
	ID    uint64       `json:"id"` // random request ID
	Round basics.Round `json:"round"`
	Seq   int          `json:"seq"`
}

// wsGetDecommitmentOut is a msgpack message delivered on responding to an account decommitment request (not rpc-based though)
type wsGetDecommitmentOut struct {
	ID            uint64       `json:"id"` // must match request ID
	Round         basics.Round `json:"round"`
	Seq           int          `json:"seq"`
	NoRetry       bool         `json:"noretry"` // this is a hint for the client to stop sending requests to this server
	Error         string       `json:"error"`
	PreimageBytes []byte       `json:"tailbytes"`
}

// a blocking function for handling an account request
func (as *AccountService) handleAccountReq(ctx context.Context, reqMsg network.IncomingMessage) {
	res := new(wsGetAccountOut)
	defer as.sendAccountRes(ctx, reqMsg.Sender.(network.UnicastPeer), reqMsg.Tag, res)

	var req wsGetAccountRequest
	err := protocol.Decode(reqMsg.Data, &req)
	if err != nil {
		logging.Base().Warnf("Error decoding account request: %v", err)
		res.Error = err.Error()
		return
	}

	res.ID = req.ID
	res.Round = req.Round
	res.Address = req.Address
	res.Prev = req.Prev
	encodedBlob, err := as.encodedAccountProof(req.Round, req.Address, req.Prev)
	if err != nil {
		res.Error = err.Error()
		if err == ledger.ErrNotArchival {
			res.NoRetry = true
		}
		return
	}
	res.AccountBytes = encodedBlob
	return
}

// a blocking function for handling a decommitment request
func (as *AccountService) handleDecommitReq(ctx context.Context, reqMsg network.IncomingMessage) {
	res := new(wsGetDecommitmentOut)
	defer as.sendDecommitRes(ctx, reqMsg.Sender.(network.UnicastPeer), reqMsg.Tag, res)

	var req wsGetDecommitmentRequest
	err := protocol.Decode(reqMsg.Data, &req)
	if err != nil {
		logging.Base().Warnf("Error decoding decommitment request: %v", err)
		res.Error = err.Error()
		return
	}

	res.ID = req.ID
	res.Round = req.Round
	res.Seq = req.Seq
	encodedBlob, err := as.encodedDecommitment(req.Round, req.Seq)
	if err != nil {
		res.Error = err.Error()
		if err == ledger.ErrNotArchival {
			res.NoRetry = true
		}
		return
	}
	res.PreimageBytes = encodedBlob
	return
}

func (as *AccountService) sendAccountRes(ctx context.Context, target network.UnicastPeer, reqTag protocol.Tag, outMsg *wsGetAccountOut) {
	t := reqTag.Complement()
	logging.Base().Infof("serving proof for account to peer: %v, round %v. addr %v. prev %v. outcome: %v.", target.GetAddress(), outMsg.Round, outMsg.Address, outMsg.Prev, outMsg.Error)
	err := target.Unicast(ctx, protocol.Encode(outMsg), t)
	if err != nil {
		logging.Base().Infof("failed to respond to account req", err)
	}
}

func (as *AccountService) sendDecommitRes(ctx context.Context, target network.UnicastPeer, reqTag protocol.Tag, outMsg *wsGetDecommitmentOut) {
	t := reqTag.Complement()
	logging.Base().Infof("serving decommitment to peer: %v, round %v. seq %v. outcome: %v.", target.GetAddress(), outMsg.Round, outMsg.Seq, outMsg.Error)
	err := target.Unicast(ctx, protocol.Encode(outMsg), t)
	if err != nil {
		logging.Base().Infof("failed to respond to account req", err)
	}
}

// TODO if query is one round early, may want to wait for min(5s, next round) before returning

func (as *AccountService) encodedAccountProof(rnd basics.Round, addr basics.Address, prev bool) ([]byte, error) {
	proc := as.ledger.LookupProof
	if prev {
		proc = as.ledger.LookupPrevProof
	}

	pf, err := proc(rnd, addr)
	if err != nil {
		return nil, err
	}
	return protocol.Encode(pf.Unvalidated()), nil
}

func (as *AccountService) encodedDecommitment(rnd basics.Round, seq int) ([]byte, error) {
	chunk, err := as.ledger.Preimage(rnd, seq)
	if err != nil {
		return nil, err
	}
	return protocol.Encode(chunk), nil
}

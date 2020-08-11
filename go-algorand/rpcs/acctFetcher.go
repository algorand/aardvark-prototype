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
	"fmt"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

// TODO move to config.Local
const (
	minTimeBetweenAccountFetcherPeerRefresh  = 10 * time.Second
	maxConcurrentAccountFetchRequests        = 1000
	maxConcurrentAccountDecommitmentRequests = 10 // one entire block of close transactions
)

var tooManyConcurrentAccountFetchRequests = fmt.Errorf("number of fetch requests exceeds maximum number of concurrent requests")
var tooManyConcurrentAccountDecommitmentRequests = fmt.Errorf("number of decommitment requests exceeds maximum number of concurrent requests")

var ErrAccountFetcherOutOfPeers = fmt.Errorf("ran out of peers to fetch account from; try again")

// An AccountFetcher queries peers for the proof of an account.
type AccountFetcher interface {
	// FetchAccount attempts to retrieve a proof of an account for
	// the given round and address.
	//
	// FetchAccount blocks, returning early if ctx is cancelled.
	//
	// In addition to performing validation, validateAccountProof
	// must return an error if the given unvalidated account proof
	// does not match the expected round and address.
	FetchAccount(ctx context.Context, rnd basics.Round, addr basics.Address, validateAccountProof func(basics.Round, basics.Address, basics.UnvalidatedAccountProof) (basics.AccountProof, error)) (basics.AccountProof, error)

	// FetchPrevAccount is like FetchAccount but for the address
	// preceding addr.  In other words, it tries to retrieve the
	// proof pf for which pf.Next = addr.
	FetchPrevAccount(ctx context.Context, rnd basics.Round, addr basics.Address, validatePrevAccountProof func(basics.Round, basics.Address, basics.UnvalidatedAccountProof) (basics.AccountProof, error)) (basics.AccountProof, error)

	// FetchDecommitment attempts to retrieve a vector decommitment
	// for the kth vector in the vector database.
	FetchDecommitment(ctx context.Context, rnd basics.Round, k int, validateDecommitment func(basics.AccountChunk) error) (basics.AccountChunk, error)

	Close()
}

type wsAccountFetcher struct {
	stop chan struct{}
	mu   deadlock.Mutex

	net network.GossipNode
	fs  *WsAccountFetcherService

	nextPeerID uint64
	peers      map[uint64]network.UnicastPeer
}

// MakeAccountFetcher makes an AccountFetcher around the provided GossipNode and WsAccountFetcherService.
func MakeAccountFetcher(net network.GossipNode, fs *WsAccountFetcherService) AccountFetcher {
	f := &wsAccountFetcher{
		stop:  make(chan struct{}),
		net:   net,
		fs:    fs,
		peers: make(map[uint64]network.UnicastPeer),
	}
	f.refreshPeers()
	go f.maintainPeers()
	return f
}

// FetchAccount attempts to retrieve a proof of an account for the given round and address.
//
// See AccountFetcher.
func (f *wsAccountFetcher) FetchAccount(ctx context.Context, rnd basics.Round, addr basics.Address, validateAccountProof func(basics.Round, basics.Address, basics.UnvalidatedAccountProof) (basics.AccountProof, error)) (basics.AccountProof, error) {
	logging.Base().Infof("Issuing FetchAccount RPC for %v at round %d", addr, rnd)
	return f.fetchAccount(ctx, rnd, addr, false, validateAccountProof)
}

// FetchPrevAccount attempts to retrieve the previous proof of an account for the given round and address.
//
// See AccountFetcher.
func (f *wsAccountFetcher) FetchPrevAccount(ctx context.Context, rnd basics.Round, addr basics.Address, validatePrevAccountProof func(basics.Round, basics.Address, basics.UnvalidatedAccountProof) (basics.AccountProof, error)) (basics.AccountProof, error) {
	logging.Base().Infof("Issuing FetchPrevAccount RPC for %v at round %d", addr, rnd)
	return f.fetchAccount(ctx, rnd, addr, true, validatePrevAccountProof)
}

func (f *wsAccountFetcher) fetchAccount(ctx context.Context, rnd basics.Round, addr basics.Address, prev bool, validate func(basics.Round, basics.Address, basics.UnvalidatedAccountProof) (basics.AccountProof, error)) (basics.AccountProof, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	req := wsGetAccountRequest{
		Round:   rnd,
		Address: addr,
		Prev:    prev,
	}
	peers := f.peers // f.peers may be modified concurrently during loop iteration
	for id, peer := range peers {
		ch := make(chan wsGetAccountOut, 1)
		issuedReq, err := f.fs.issueAccountFetchRequest(ctx, peer, req, ch)

		if err != nil {
			if err == tooManyConcurrentAccountFetchRequests {
				return basics.AccountProof{}, err
			}
			// TODO if error is round too early, might want to wait 5s and retry

			logging.Base().Infof("failed to issue fetch account proof request to peer %v: %v", peer.GetAddress(), err)
			f.dropPeer(id, false)
			continue
		}

		f.mu.Unlock()

		ctxDone := false
		var resp wsGetAccountOut
		select {
		case resp = <-ch:
		case <-ctx.Done():
			ctxDone = true
		}
		f.fs.doneWithFetchRequest(issuedReq)

		f.mu.Lock()

		if ctxDone {
			return basics.AccountProof{}, fmt.Errorf("returning early: context done: %v", ctx.Err())
		}

		if resp.Error != "" {
			logging.Base().Infof("failed to fetch account proof from peer %v: %v", peer.GetAddress(), resp.Error)
			if resp.NoRetry {
				f.dropPeer(id, false)
			}
			continue
		}

		enc := resp.AccountBytes
		var unvalidated basics.UnvalidatedAccountProof
		err = protocol.Decode(enc, &unvalidated)
		if err != nil {
			logging.Base().Warnf("failed to decode unvalidated account proof bytes from peer %v: %v", peer.GetAddress(), err)
			f.dropPeer(id, true)
			continue
		}

		f.mu.Unlock()
		pf, err := validate(rnd, addr, unvalidated)
		f.mu.Lock()

		if err != nil {
			logging.Base().Warnf("failed to validate account proof (%d, %v) from peer %v: %v (proof was %v)", rnd, addr, peer.GetAddress(), err, unvalidated)
			f.dropPeer(id, true)
			continue
		}

		return pf, nil
	}

	return basics.AccountProof{}, ErrAccountFetcherOutOfPeers
}

func (f *wsAccountFetcher) FetchDecommitment(ctx context.Context, rnd basics.Round, k int, validate func(basics.AccountChunk) error) (basics.AccountChunk, error) {
	logging.Base().Infof("Issuing FetchDecommitment RPC for vc %d at round %d", k, rnd)

	f.mu.Lock()
	defer f.mu.Unlock()

	req := wsGetDecommitmentRequest{
		Round: rnd,
		Seq:   k,
	}
	peers := f.peers
	for id, peer := range peers { // f.peers may be modified concurrently during loop iteration
		ch := make(chan wsGetDecommitmentOut, 1)
		issuedReq, err := f.fs.issueAccountDecommitmentRequest(ctx, peer, req, ch)

		if err != nil {
			if err == tooManyConcurrentAccountDecommitmentRequests {
				return basics.AccountChunk{}, err
			}
		}

		f.mu.Unlock()

		ctxDone := false
		var resp wsGetDecommitmentOut
		select {
		case resp = <-ch:
		case <-ctx.Done():
			ctxDone = true
		}
		f.fs.doneWithDecommitmentRequest(issuedReq)

		f.mu.Lock()

		if ctxDone {
			return basics.AccountChunk{}, fmt.Errorf("returning early: context done: %v", ctx.Err())
		}

		if resp.Error != "" {
			logging.Base().Infof("failed to fetch account decommitment from peer %v: %v", peer.GetAddress(), resp.Error)
			if resp.NoRetry {
				f.dropPeer(id, false)
			}
			continue
		}

		enc := resp.PreimageBytes
		var decommit basics.AccountChunk
		err = protocol.Decode(enc, &decommit)
		if err != nil {
			logging.Base().Warnf("failed to decode account decommitment bytes from peer %v: %v", peer.GetAddress(), err)
			f.dropPeer(id, true)
			continue
		}

		f.mu.Unlock()
		err = validate(decommit)
		f.mu.Lock()

		if err != nil {
			logging.Base().Warnf("failed to validate account decommitment from peer %v: %v", peer.GetAddress(), err)
			f.dropPeer(id, true)
			continue
		}

		return decommit, nil
	}
	return basics.AccountChunk{}, ErrAccountFetcherOutOfPeers
}

// Close the wsAccountFetcher.
func (f *wsAccountFetcher) Close() {
	close(f.stop)
}

func (f *wsAccountFetcher) maintainPeers() {
	for {
		select {
		case <-f.stop:
			return
		case <-time.After(minTimeBetweenAccountFetcherPeerRefresh):
			f.mu.Lock()
			if len(f.peers) == 0 {
				f.refreshPeers()
			}
			f.mu.Unlock()
		}
	}
}

func (f *wsAccountFetcher) refreshPeers() {
	peers := f.net.GetPeers(network.PeersConnectedIn)
	for _, peer := range peers {
		if peer, ok := peer.(network.UnicastPeer); ok {
			f.peers[f.nextPeerID] = peer
			f.nextPeerID++
		}
	}

	// TODO replace this when HTTP account fetch is implemented
	peers = f.net.GetPeers(network.PeersConnectedOut)
	for _, peer := range peers {
		if peer, ok := peer.(network.UnicastPeer); ok {
			f.peers[f.nextPeerID] = peer
			f.nextPeerID++
		}
	}
}

func (f *wsAccountFetcher) dropPeer(id uint64, disconnect bool) {
	delete(f.peers, id)
	if disconnect {
		f.net.Disconnect(f.peers[id])
	}
}

// WsAccountFetcherService is a service that performs client-side
// bookkeeping for remote AccountServices.
type WsAccountFetcherService struct {
	mu           deadlock.Mutex
	fetchReqs    map[wsGetAccountRequest]chan<- wsGetAccountOut
	decommitReqs map[wsGetDecommitmentRequest]chan<- wsGetDecommitmentOut
}

// RegisterWsAccountFetcherService creates a WsAccountFetcherService and registers it for RPC with the provided Registrar.
func RegisterWsAccountFetcherService(config config.Local, registrar Registrar) *WsAccountFetcherService {
	service := &WsAccountFetcherService{
		fetchReqs:    make(map[wsGetAccountRequest]chan<- wsGetAccountOut),
		decommitReqs: make(map[wsGetDecommitmentRequest]chan<- wsGetDecommitmentOut),
	}

	handlers := []network.TaggedMessageHandler{
		{Tag: protocol.UniAccountResTag, MessageHandler: network.HandlerFunc(service.processIncomingMessage)},
		{Tag: protocol.UniDecommitResTag, MessageHandler: network.HandlerFunc(service.processIncomingMessage)},
	}
	registrar.RegisterHandlers(handlers)

	return service
}

func (fs *WsAccountFetcherService) processIncomingMessage(msg network.IncomingMessage) (n network.OutgoingMessage) {
	switch msg.Tag {
	case protocol.UniAccountResTag:
		return fs.handleGetAccountRes(msg)
	case protocol.UniDecommitResTag:
		return fs.handleGetDecommitRes(msg)
	default:
		logging.Base().Errorf("WsAccountFetcherService received bad tag from peer: %v", msg.Tag)
	}
	return
}

func (fs *WsAccountFetcherService) handleGetAccountRes(msg network.IncomingMessage) (n network.OutgoingMessage) {
	var res wsGetAccountOut
	err := protocol.Decode(msg.Data, &res)
	if err != nil {
		logging.Base().Warnf("received malformed account proof response from peer: %v", msg.Sender)
		n.Action = network.Disconnect
		return
	}

	fs.mu.Lock()
	req := wsGetAccountRequest{ID: res.ID, Round: res.Round, Address: res.Address, Prev: res.Prev}
	out, ok := fs.fetchReqs[req]
	delete(fs.fetchReqs, req)
	fs.mu.Unlock()

	if !ok {
		logging.Base().Infof("received unsolicited account proof response from peer (key %v): (error: %s)", req, res.Error)
		// logging.Base().Infof("received unsolicited account proof response from peer (key %v): (error: %s): %v", req, res.Error, msg.Sender)
		// TODO this can be triggered if the response arrives late
		// if so, we should not disconnect but instead ignore
		// n.Action = network.Disconnect
		return
	}

	out <- res
	close(out)
	return
}

func (fs *WsAccountFetcherService) handleGetDecommitRes(msg network.IncomingMessage) (n network.OutgoingMessage) {
	var res wsGetDecommitmentOut
	err := protocol.Decode(msg.Data, &res)
	if err != nil {
		logging.Base().Warnf("received malformed decommitment response from peer: %v", msg.Sender)
		n.Action = network.Disconnect
		return
	}

	fs.mu.Lock()
	req := wsGetDecommitmentRequest{ID: res.ID, Round: res.Round, Seq: res.Seq}
	out, ok := fs.decommitReqs[req]
	delete(fs.decommitReqs, req)
	fs.mu.Unlock()

	if !ok {
		logging.Base().Infof("received unsolicited account proof response from peer (key %v): (error: %s)", req, res.Error)
		// logging.Base().Infof("received unsolicited decommitment response from peer (key %v): (error: %s): %v", req, res.Error, msg.Sender)
		// TODO this can be triggered if the response arrives late
		// if so, we should not disconnect but instead ignore
		// n.Action = network.Disconnect
		return
	}

	out <- res
	close(out)
	return
}

// out should be an open channel.
// out must be buffered with at least one spare capacity.
//
// If no error is returned, one message is written to out, and then
// out is closed.  Once the caller no longer cares about the request,
// it must clean up by calling doneWithFetchRequest on the returned
// wsGetAccountRequest.
func (fs *WsAccountFetcherService) issueAccountFetchRequest(ctx context.Context, peer network.UnicastPeer, req wsGetAccountRequest, out chan<- wsGetAccountOut) (wsGetAccountRequest, error) {
	fs.mu.Lock()

	if len(fs.fetchReqs) >= maxConcurrentAccountFetchRequests {
		fs.mu.Unlock()
		return wsGetAccountRequest{}, tooManyConcurrentAccountFetchRequests
	}

	req.ID = crypto.RandUint64()
	fs.fetchReqs[req] = out
	fs.mu.Unlock()

	logging.Base().Infof("requesting proof for account from peer (%d): %v, round %v. addr %v. prev %v.", req.ID, peer.GetAddress(), req.Round, req.Address, req.Prev)
	err := peer.Unicast(ctx, protocol.Encode(req), protocol.UniAccountReqTag)
	if err != nil {
		fs.mu.Lock()
		delete(fs.fetchReqs, req)
		fs.mu.Unlock()
		return wsGetAccountRequest{}, err
	}

	return req, nil
}

// out should be an open channel.
// out must be buffered with at least one spare capacity.
//
// If no error is returned, one message is written to out, and then
// out is closed.  Once the caller no longer cares about the request,
// it must clean up by calling doneWithDecommitmentRequest on the returned
// wsGetDecommitmentRequest.
func (fs *WsAccountFetcherService) issueAccountDecommitmentRequest(ctx context.Context, peer network.UnicastPeer, req wsGetDecommitmentRequest, out chan<- wsGetDecommitmentOut) (wsGetDecommitmentRequest, error) {
	fs.mu.Lock()

	if len(fs.decommitReqs) >= maxConcurrentAccountDecommitmentRequests {
		fs.mu.Unlock()
		return wsGetDecommitmentRequest{}, tooManyConcurrentAccountDecommitmentRequests
	}

	req.ID = crypto.RandUint64()
	fs.decommitReqs[req] = out
	fs.mu.Unlock()

	logging.Base().Infof("requesting tail decommitment from peer (%d): %v, round %v. seq %v.", req.ID, peer.GetAddress(), req.Round, req.Seq)
	err := peer.Unicast(ctx, protocol.Encode(req), protocol.UniDecommitReqTag)
	if err != nil {
		fs.mu.Lock()
		delete(fs.decommitReqs, req)
		fs.mu.Unlock()
		return wsGetDecommitmentRequest{}, err
	}

	return req, nil
}

func (fs *WsAccountFetcherService) doneWithFetchRequest(req wsGetAccountRequest) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	delete(fs.fetchReqs, req)
}

func (fs *WsAccountFetcherService) doneWithDecommitmentRequest(req wsGetDecommitmentRequest) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	delete(fs.decommitReqs, req)
}

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

package data

import (
	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
)

type ProofDB interface {
	LookupProof(basics.Round, basics.Address) (basics.AccountProof, error)
}

// AccountManager loads and manages accounts for the node
type AccountManager struct {
	mu deadlock.Mutex

	partIntervals map[account.ParticipationInterval]account.Participation

	proofs ProofDB

	xxxRewardsPool basics.Address
	xxxFeeSink     basics.Address

	// Map to keep track of accounts for which we've sent
	// AccountRegistered telemetry events
	registeredAccounts map[string]bool

	log logging.Logger
}

// MakeAccountManager creates a new AccountManager with a custom logger and account proof store.
func MakeAccountManager(log logging.Logger, proofs ProofDB) *AccountManager {
	manager := &AccountManager{}
	manager.log = log
	manager.proofs = proofs
	manager.partIntervals = make(map[account.ParticipationInterval]account.Participation)
	manager.registeredAccounts = make(map[string]bool)

	return manager
}

// Keys returns a slice of participation keys active in a given round along with their proofs.
func (manager *AccountManager) Keys(rnd basics.Round) (out []account.ParticipationData) {
	if (manager.xxxRewardsPool != basics.Address{}) {
		// put RewardsPool into the ProofDB cache
		_, err := manager.proofs.LookupProof(rnd, manager.xxxRewardsPool)
		if err != nil {
			manager.log.Infof("failed to look up proof of addr %v at round %d: %v", manager.xxxRewardsPool, rnd, err)
		}
	}
	if (manager.xxxFeeSink != basics.Address{}) {
		// put FeeSink into the ProofDB cache
		_, err := manager.proofs.LookupProof(rnd, manager.xxxFeeSink)
		if err != nil {
			manager.log.Infof("failed to look up proof of addr %v at round %d: %v", manager.xxxFeeSink, rnd, err)
		}
	}

	for _, part := range manager.keys(rnd) {
		pf, err := manager.proofs.LookupProof(rnd, part.Parent) // TODO must fetch keys in background if archive takes too long to respond; otherwise, potential livelock
		if err != nil {
			manager.log.Infof("failed to look up proof of addr %v at round %d: %v", part.Parent, rnd, err)
			continue
		}
		out = append(out, account.ParticipationData{Participation: part, AccountProof: pf})
	}
	return
}

func (manager *AccountManager) keys(rnd basics.Round) (parts []account.Participation) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	for _, part := range manager.partIntervals {
		if rnd < part.FirstValid || rnd > part.LastValid {
			continue
		}
		parts = append(parts, part)
	}
	return
}

// HasLiveKeys returns true if we have any Participation
// keys valid for the specified round range (inclusive)
func (manager *AccountManager) HasLiveKeys(from, to basics.Round) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	for _, part := range manager.partIntervals {
		if part.OverlapsInterval(from, to) {
			return true
		}
	}
	return false
}

// AddParticipation adds a new account.Participation to be managed.
// The return value indicates if the key has been added (true) or
// if this is a duplicate key (false).
func (manager *AccountManager) AddParticipation(participation account.Participation) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	address := participation.Address()

	first, last := participation.ValidInterval()
	interval := account.ParticipationInterval{
		Address:    address,
		FirstValid: first,
		LastValid:  last,
	}

	// Check if we already have participation keys for this address in this interval
	_, alreadyPresent := manager.partIntervals[interval]
	if alreadyPresent {
		return false
	}

	manager.partIntervals[interval] = participation

	addressString := address.String()
	manager.log.EventWithDetails(telemetryspec.Accounts, telemetryspec.PartKeyRegisteredEvent, telemetryspec.PartKeyRegisteredEventDetails{
		Address:    addressString,
		FirstValid: uint64(first),
		LastValid:  uint64(last),
	})

	_, has := manager.registeredAccounts[addressString]
	if !has {
		manager.registeredAccounts[addressString] = true

		manager.log.EventWithDetails(telemetryspec.Accounts, telemetryspec.AccountRegisteredEvent, telemetryspec.AccountRegisteredEventDetails{
			Address: addressString,
		})
	}

	return true
}

// XXXsetSpecialAddresses TODO remove
func (manager *AccountManager) XXXsetSpecialAddresses(pool, sink basics.Address) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	manager.xxxRewardsPool = pool
	manager.xxxFeeSink = sink
}

// DeleteOldKeys deletes all accounts' ephemeral keys strictly older than the
// current round.
func (manager *AccountManager) DeleteOldKeys(current basics.Round, proto config.ConsensusParams) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	for _, part := range manager.partIntervals {
		err := part.DeleteOldKeys(current, proto)
		if err != nil {
			first, last := part.ValidInterval()
			logging.Base().Warnf("AccountManager.DeleteOldKeys(%d): key for %s (%d-%d): %v",
				current, part.Address().String(), first, last, err)
		}
	}
}

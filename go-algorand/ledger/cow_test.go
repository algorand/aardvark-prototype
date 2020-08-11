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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
)

type mockLedger struct {
	balanceMap map[basics.Address]basics.AccountData
}

func makeMockLedger(balanceMap map[basics.Address]basics.AccountData) *mockLedger {
	return &mockLedger{balanceMap: balanceMap}
}

func (ml *mockLedger) lookup(addr basics.Address, ctx accountContext) (basics.AccountData, accountContext, error) {
	return ml.balanceMap[addr], ctx, nil
}

func (ml *mockLedger) isDup(firstValid basics.Round, txn transactions.Txid) (bool, error) {
	return false, nil
}

func checkCow(t *testing.T, cow *roundCowState, accts map[basics.Address]basics.AccountData) {
	for addr, data := range accts {
		d, _, err := cow.lookup(addr, accountContext{})
		require.NoError(t, err)
		require.Equal(t, d, data)
	}

	d, _, err := cow.lookup(randomAddress(), accountContext{})
	require.NoError(t, err)
	require.Equal(t, d, basics.AccountData{}, accountContext{})
}

func applyUpdates(cow *roundCowState, updates map[basics.Address]accountDelta) {
	for addr, delta := range updates {
		cow.put(addr, delta.old, delta.new, accountContext{}, basics.AccountProof{})
	}
}

func TestCowBalance(t *testing.T) {
	accts0 := randomAccounts(20)
	ml := makeMockLedger(accts0)

	c0 := makeRoundCowState(ml, nil, bookkeeping.BlockHeader{})
	checkCow(t, c0, accts0)

	c1 := c0.child()
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts0)

	updates1, accts1, _ := randomDeltas(10, accts0, 0)
	applyUpdates(c1, updates1)
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts1)

	c2 := c1.child()
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts1)
	checkCow(t, c2, accts1)

	updates2, accts2, _ := randomDeltas(10, accts1, 0)
	applyUpdates(c2, updates2)
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts1)
	checkCow(t, c2, accts2)

	c2.commitToParent()
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts2)

	c1.commitToParent()
	checkCow(t, c0, accts2)
}

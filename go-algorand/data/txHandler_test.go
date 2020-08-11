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
	"fmt"
	"github.com/algorand/go-algorand/components/mocks"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/pools"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
)

func BenchmarkTxHandlerProcessDecoded(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()
	const numRounds = 10
	const numUsers = 100
	log := logging.TestingLog(b)
	secrets := make([]*crypto.SignatureSecrets, numUsers)
	addresses := make([]basics.Address, numUsers)

	genesis := make(map[basics.Address]basics.AccountData)
	for i := 0; i < numUsers; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
		genesis[addr] = basics.AccountData{
			Status:     basics.Online,
			MicroAlgos: basics.MicroAlgos{Raw: 10000000000000},
		}
	}
	require.Equal(b, len(genesis), numUsers)
	genBal := MakeGenesisBalances(genesis, poolAddr, sinkAddr)
	ledgerName := fmt.Sprintf("%s-mem-%d", b.Name(), b.N)
	ledger, err := LoadLedger(log, ledgerName, true, protocol.ConsensusCurrentVersion, genBal, "", crypto.Digest{}, nil)
	require.NoError(b, err)

	l := ledger

	const txPoolSize = 20000
	tp := pools.MakeTransactionPool(l.Ledger, txPoolSize, false, nil) // TODO exec pool
	signedTransactions := make([]transactions.SignedTxn, 0, b.N)
	for i := 0; i < b.N/numUsers; i++ {
		for u := 0; u < numUsers; u++ {
			// generate transactions
			tx := transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Sender:     addresses[u],
					Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
					FirstValid: 0,
					LastValid:  basics.Round(proto.MaxTxnLife),
					Note:       make([]byte, 2),
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: addresses[(u+1)%numUsers],
					Amount:   basics.MicroAlgos{Raw: mockBalancesMinBalance + (rand.Uint64() % 10000)},
				},
			}
			signedTx := tx.Sign(secrets[u])
			signedTransactions = append(signedTransactions, signedTx)
		}
	}
	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	txHandler := MakeTxHandler(tp, l, &mocks.MockNetwork{}, "", crypto.Digest{}, backlogPool)
	b.StartTimer()
	for _, signedTxn := range signedTransactions {
		txHandler.processDecoded(signedTxn)
	}
}
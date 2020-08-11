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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
)

var testPoolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var testSinkAddr = basics.Address{0x2c, 0x2a, 0x6c, 0xe9, 0xa9, 0xa7, 0xc2, 0x8c, 0x22, 0x95, 0xfd, 0x32, 0x4f, 0x77, 0xa5, 0x4, 0x8b, 0x42, 0xc2, 0xb7, 0xa8, 0x54, 0x84, 0xb6, 0x80, 0xb1, 0xe1, 0x3d, 0x59, 0x9b, 0xeb, 0x36}
var minFee basics.MicroAlgos

func init() {
	params := config.Consensus[protocol.ConsensusCurrentVersion]
	minFee = basics.MicroAlgos{Raw: params.MinTxnFee}
}

func TestBlockEvaluator(t *testing.T) {
	blks, accts, addrs, keys := genesis(10)

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	l, err := OpenLedger(logging.Base(), dbName, true, blks, accts, blks[0].BlockHeader.GenesisHash)
	require.NoError(t, err)

	lastBlock := blks[len(blks)-1]
	proto := config.Consensus[lastBlock.CurrentProtocol]
	newBlock := bookkeeping.MakeBlock(lastBlock.BlockHeader)
	var totalRewardUnits uint64
	for _, acctdata := range accts {
		totalRewardUnits += acctdata.MicroAlgos.RewardUnits(proto)
	}
	newBlock.RewardsState = lastBlock.NextRewardsState(lastBlock.Round()+1, proto, accts[testPoolAddr].MicroAlgos, totalRewardUnits)

	eval, err := l.StartEvaluator(newBlock.BlockHeader, basics.AccountTail{}, nil, backlogPool) // TODO at some point, test close transactions
	require.NoError(t, err)

	txn := transactions.Transaction{
		Type: protocol.Delete,
		Header: transactions.Header{
			Sender:     addrs[0],
			FirstValid: newBlock.Round(),
			LastValid:  newBlock.Round(),
		},
		// PaymentTxnFields: transactions.PaymentTxnFields{
		// 	Receiver: addrs[1],
		// 	Amount:   basics.MicroAlgos{Raw: 100},
		// },
	}

	// Zero signature should fail
	st := transactions.SignedTxn{
		Txn: txn,
	}
	err = eval.Transaction(st, transactions.TransactionProof{})
	require.Error(t, err)

	// Random signature should fail
	crypto.RandBytes(st.Sig[:])
	err = eval.Transaction(st, transactions.TransactionProof{})
	require.Error(t, err)

	// Correct signature should work
	st = txn.Sign(keys[0])
	pf, err := txn.Prove(l, transactions.SpecialAddresses{FeeSink: testSinkAddr, RewardsPool: testPoolAddr})
	require.NoError(t, err)
	st.Proof = pf.Unvalidated()
	err = eval.Transaction(st, transactions.TransactionProof{})
	require.NoError(t, err)

	selfTxn := transactions.Transaction{
		Type: protocol.Delete,
		Header: transactions.Header{
			Sender:     addrs[2],
			FirstValid: newBlock.Round(),
			LastValid:  newBlock.Round(),
		},
		// PaymentTxnFields: transactions.PaymentTxnFields{
		// 	Receiver: addrs[2],
		// 	Amount:   basics.MicroAlgos{Raw: 100},
		// },
	}
	st = selfTxn.Sign(keys[2])
	pf, err = selfTxn.Prove(l, transactions.SpecialAddresses{FeeSink: testSinkAddr, RewardsPool: testPoolAddr})
	require.NoError(t, err)
	st.Proof = pf.Unvalidated()
	err = eval.Transaction(st, transactions.TransactionProof{})
	require.NoError(t, err)

	validatedBlock, err := eval.GenerateBlock()
	require.NoError(t, err)

	// bal0 := accts[addrs[0]]
	// bal1 := accts[addrs[1]]
	bal2 := accts[addrs[2]]

	l.AddValidatedBlock(*validatedBlock, agreement.Certificate{})

	// bal0new, err := l.Lookup(newBlock.Round(), addrs[0])
	// require.NoError(t, err)
	// bal1new, err := l.Lookup(newBlock.Round(), addrs[1])
	// require.NoError(t, err)
	bal2new, err := l.Lookup(newBlock.Round(), addrs[2])
	require.NoError(t, err)

	// require.Equal(t, bal0new.MicroAlgos.Raw, bal0.MicroAlgos.Raw-100)
	// require.Equal(t, bal1new.MicroAlgos.Raw, bal1.MicroAlgos.Raw+100)
	require.Equal(t, bal2new.MicroAlgos.Raw, bal2.MicroAlgos.Raw)
}

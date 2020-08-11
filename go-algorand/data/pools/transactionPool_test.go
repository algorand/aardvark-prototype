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

package pools

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

var proto = config.Consensus[protocol.ConsensusCurrentVersion]

func keypair() *crypto.SignatureSecrets {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	s := crypto.GenerateSignatureSecrets(seed)
	return s
}

type TestingT interface {
	Errorf(format string, args ...interface{})
	FailNow()
	Name() string
}

var minBalance = config.Consensus[protocol.ConsensusCurrentVersion].MinBalance
var minFee = config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee

var pool basics.Address

func init() {
	crypto.RandBytes(pool[:])
}

func makeMockLedger(t TestingT, initAccounts map[basics.Address]basics.AccountData) *ledger.Ledger {
	var hash crypto.Digest
	crypto.RandBytes(hash[:])

	proto := protocol.ConsensusCurrentVersion
	params := config.Consensus[proto]

	var poolData basics.AccountData
	poolData.MicroAlgos.Raw = 1 << 32
	initAccounts[pool] = poolData

	initBlock := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			TxnRoot:     transactions.Payset{}.Commit(params.PaysetCommitFlat),
			GenesisID:   "pooltest",
			GenesisHash: hash,
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: proto,
			},
			RewardsState: bookkeeping.RewardsState{
				FeeSink:     pool,
				RewardsPool: pool,
			},
		},
	}
	initBlocks := []bookkeeping.Block{initBlock}

	fn := fmt.Sprintf("/tmp/%s.%d.sqlite3", t.Name(), crypto.RandUint64())
	l, err := ledger.OpenLedger(logging.Base(), fn, true, initBlocks, initAccounts, hash)
	require.NoError(t, err)
	return l
}

func newBlockEvaluator(t TestingT, l *ledger.Ledger) *ledger.BlockEvaluator {
	latest := l.Latest()
	prev, err := l.BlockHdr(latest)
	require.NoError(t, err)

	next := bookkeeping.MakeBlock(prev)
	eval, err := l.StartEvaluator(next.BlockHeader, basics.AccountTail{}, &alwaysVerifiedPool{}, nil) // TODO replace with real tail to support close txs
	require.NoError(t, err)

	return eval
}

func initAcc(initBalances map[basics.Address]uint64) map[basics.Address]basics.AccountData {
	res := make(map[basics.Address]basics.AccountData)
	for addr, bal := range initBalances {
		var data basics.AccountData
		data.MicroAlgos.Raw = bal
		res[addr] = data
	}
	return res
}

func initAccFixed(initAddrs []basics.Address, bal uint64) map[basics.Address]basics.AccountData {
	res := make(map[basics.Address]basics.AccountData)
	for _, addr := range initAddrs {
		var data basics.AccountData
		data.MicroAlgos.Raw = bal
		res[addr] = data
	}
	return res
}

const testPoolSize = 1000

func signAndProveTx(t testing.TB, ledger *ledger.Ledger, tx transactions.Transaction, secret *crypto.SignatureSecrets) (transactions.SignedTxn, transactions.TransactionProof) {
	var err error
	signedTx := tx.Sign(secret)
	pf, err := tx.Prove(ledger, transactions.SpecialAddresses{FeeSink: pool, RewardsPool: pool})
	require.NoError(t, err)
	signedTx.Proof = pf.Unvalidated()
	return signedTx, pf
}

func TestMinBalanceOK(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*minBalance + proto.MinTxnFee
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	transactionPool := MakeTransactionPool(ledger, testPoolSize, false, nil)

	// sender goes below min
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  1,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: minBalance},
		},
	}

	signedTx, pf := signAndProveTx(t, ledger, tx, secrets[0])
	require.NoError(t, transactionPool.Remember(signedTx, pf))
}

func TestSenderGoesBelowMinBalance(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*minBalance + proto.MinTxnFee
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	transactionPool := MakeTransactionPool(ledger, testPoolSize, false, nil)

	// sender goes below min
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee + 1},
			FirstValid:  1,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: minBalance},
		},
	}
	signedTx, pf := signAndProveTx(t, ledger, tx, secrets[0])
	require.Error(t, transactionPool.Remember(signedTx, pf))
}

func TestCloseAccount(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 3*minBalance + 2*proto.MinTxnFee
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	transactionPool := MakeTransactionPool(ledger, testPoolSize, false, nil)

	// sender goes below min
	closeTx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  1,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         addresses[1],
			Amount:           basics.MicroAlgos{Raw: minBalance},
			CloseRemainderTo: addresses[2],
		},
	}
	signedTx, pf := signAndProveTx(t, ledger, closeTx, secrets[0])
	require.NoError(t, transactionPool.Remember(signedTx, pf))

	// sender goes below min
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  1,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: minBalance},
		},
	}
	signedTx2, pf2 := signAndProveTx(t, ledger, tx, secrets[0])
	require.Error(t, transactionPool.Remember(signedTx2, pf2))
}

func TestCloseAccountWhileTxIsPending(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*minBalance + 2*proto.MinTxnFee - 1
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	transactionPool := MakeTransactionPool(ledger, testPoolSize, false, nil)

	// sender goes below min
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  1,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: minBalance},
		},
	}
	signedTx, pf := signAndProveTx(t, ledger, tx, secrets[0])
	require.NoError(t, transactionPool.Remember(signedTx, pf))

	// sender goes below min
	closeTx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  1,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         addresses[1],
			Amount:           basics.MicroAlgos{Raw: minBalance},
			CloseRemainderTo: addresses[2],
		},
	}
	signedCloseTx, closePf := signAndProveTx(t, ledger, closeTx, secrets[0])
	require.Error(t, transactionPool.Remember(signedCloseTx, closePf))
}

func TestClosingAccountBelowMinBalance(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*minBalance - 1 + proto.MinTxnFee
	limitedAccounts[addresses[2]] = 0
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	transactionPool := MakeTransactionPool(ledger, testPoolSize, false, nil)

	// sender goes below min
	closeTx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  1,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         addresses[1],
			Amount:           basics.MicroAlgos{Raw: minBalance},
			CloseRemainderTo: addresses[2],
		},
	}
	signedTx, pf := signAndProveTx(t, ledger, closeTx, secrets[0])
	require.Error(t, transactionPool.Remember(signedTx, pf))
}

func TestRecipientGoesBelowMinBalance(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[1]] = 0
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	transactionPool := MakeTransactionPool(ledger, testPoolSize, false, nil)

	// sender goes below min
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  1,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: minBalance - 1},
		},
	}
	signedTx, pf := signAndProveTx(t, ledger, tx, secrets[0])
	require.Error(t, transactionPool.Remember(signedTx, pf))
}

func TestRememberForget(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	ledger := makeMockLedger(t, initAccFixed(addresses, 1<<32))
	transactionPool := MakeTransactionPool(ledger, testPoolSize, false, nil)

	eval := newBlockEvaluator(t, ledger)

	for i, sender := range addresses {
		for j, receiver := range addresses {
			if sender != receiver {
				tx := transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender:      sender,
						Fee:         basics.MicroAlgos{Raw: uint64(rand.Int()%10000) + proto.MinTxnFee},
						FirstValid:  1,
						LastValid:   basics.Round(proto.MaxTxnLife),
						Note:        make([]byte, 2),
						GenesisHash: ledger.GenesisHash(),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver: receiver,
						Amount:   basics.MicroAlgos{Raw: 1},
					},
				}
				tx.Note[0] = byte(i)
				tx.Note[1] = byte(j)
				signedTx, pf := signAndProveTx(t, ledger, tx, secrets[i])
				transactionPool.Remember(signedTx, pf)
				err := eval.Transaction(signedTx, nil, pf)
				require.NoError(t, err)
			}
		}
	}

	pending := transactionPool.Pending()
	numberOfTxns := numOfAccounts*numOfAccounts - numOfAccounts
	require.Len(t, pending, numberOfTxns)

	blk, err := eval.GenerateBlock()
	require.NoError(t, err)

	err = ledger.AddValidatedBlock(*blk, agreement.Certificate{})
	require.NoError(t, err)
	transactionPool.OnNewBlock(blk.Block())

	pending = transactionPool.Pending()
	require.Len(t, pending, 0)
}

//	Test that clean up works
func TestCleanUp(t *testing.T) {
	numOfAccounts := 10
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	ledger := makeMockLedger(t, initAccFixed(addresses, 1<<32))
	transactionPool := MakeTransactionPool(ledger, testPoolSize, false, nil)

	issuedTransactions := 0
	for i, sender := range addresses {
		for j, receiver := range addresses {
			if sender != receiver {
				tx := transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender:      sender,
						Fee:         basics.MicroAlgos{Raw: uint64(rand.Int()%10000) + proto.MinTxnFee},
						FirstValid:  1,
						LastValid:   5,
						Note:        make([]byte, 2),
						GenesisHash: ledger.GenesisHash(),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver: receiver,
						Amount:   basics.MicroAlgos{Raw: 1},
					},
				}
				tx.Note[0] = byte(i)
				tx.Note[1] = byte(j)
				signedTx, pf := signAndProveTx(t, ledger, tx, secrets[i])
				require.NoError(t, transactionPool.Remember(signedTx, pf))
				issuedTransactions++
			}
		}
	}

	for ledger.Latest() < 6 {
		eval := newBlockEvaluator(t, ledger)
		blk, err := eval.GenerateBlock()
		require.NoError(t, err)

		err = ledger.AddValidatedBlock(*blk, agreement.Certificate{})
		require.NoError(t, err)

		transactionPool.OnNewBlock(blk.Block())
	}

	pending := transactionPool.Pending()
	require.Zero(t, len(pending))
	require.Zero(t, transactionPool.NumExpired(4))
	require.Equal(t, issuedTransactions, transactionPool.NumExpired(5))

	for ledger.Latest() < 6+basics.Round(expiredHistory*proto.MaxTxnLife) {
		eval := newBlockEvaluator(t, ledger)
		blk, err := eval.GenerateBlock()
		require.NoError(t, err)

		err = ledger.AddValidatedBlock(*blk, agreement.Certificate{})
		require.NoError(t, err)

		transactionPool.OnNewBlock(blk.Block())
		require.Zero(t, transactionPool.NumExpired(blk.Block().Round()))
	}
	require.Len(t, transactionPool.expiredTxCount, int(expiredHistory*proto.MaxTxnLife))
}

func TestFixOverflowOnNewBlock(t *testing.T) {
	numOfAccounts := 10
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	ledger := makeMockLedger(t, initAccFixed(addresses, 1<<32))
	transactionPool := MakeTransactionPool(ledger, testPoolSize, false, nil)

	overSpender := addresses[0]
	var overSpenderAmount uint64
	savedTransactions := 0
	for i, sender := range addresses {
		amount := uint64(0)
		for _, receiver := range addresses {
			if sender != receiver {
				tx := transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender:      sender,
						Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee + amount},
						FirstValid:  1,
						LastValid:   10,
						Note:        make([]byte, 0),
						GenesisHash: ledger.GenesisHash(),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver: receiver,
						Amount:   basics.MicroAlgos{Raw: 0},
					},
				}
				amount++

				if sender == overSpender {
					overSpenderAmount += tx.Fee.Raw
				}

				signedTx, pf := signAndProveTx(t, ledger, tx, secrets[i])
				require.NoError(t, transactionPool.Remember(signedTx, pf))
				savedTransactions++
			}
		}
	}
	pending := transactionPool.Pending()
	require.Len(t, pending, savedTransactions)

	secret := keypair()
	recv := basics.Address(secret.SignatureVerifier)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      overSpender,
			Fee:         basics.MicroAlgos{Raw: 1<<32 - proto.MinBalance - overSpenderAmount + proto.MinTxnFee},
			FirstValid:  1,
			LastValid:   10,
			Note:        []byte{1},
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: recv,
			Amount:   basics.MicroAlgos{Raw: 0},
		},
	}
	signedTx, pf := signAndProveTx(t, ledger, tx, secrets[0])

	blockEval := newBlockEvaluator(t, ledger)
	err := blockEval.Transaction(signedTx, nil, pf)
	require.NoError(t, err)

	// simulate this transaction was applied
	block, err := blockEval.GenerateBlock()
	require.NoError(t, err)

	err = ledger.AddValidatedBlock(*block, agreement.Certificate{})
	require.NoError(t, err)

	transactionPool.OnNewBlock(block.Block())

	pending = transactionPool.Pending()
	// only one transaction is missing
	require.Len(t, pending, savedTransactions-1)
}

func TestOverspender(t *testing.T) {
	numOfAccounts := 2
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	overSpender := addresses[0]
	ledger := makeMockLedger(t, initAcc(map[basics.Address]uint64{overSpender: proto.MinTxnFee - 1}))
	transactionPool := MakeTransactionPool(ledger, testPoolSize, false, nil)

	receiver := addresses[1]
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      overSpender,
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee + 1},
			FirstValid:  1,
			LastValid:   10,
			Note:        make([]byte, 0),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 0},
		},
	}
	signedTx, pf := signAndProveTx(t, ledger, tx, secrets[0])

	// consume the transaction of allowed limit
	require.Error(t, transactionPool.Remember(signedTx, pf))

	// min transaction
	minTx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      overSpender,
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  1,
			LastValid:   10,
			Note:        make([]byte, 0),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 0},
		},
	}
	signedMinTx, minPf := signAndProveTx(t, ledger, minTx, secrets[0])
	require.Error(t, transactionPool.Remember(signedMinTx, minPf))
}

func TestRemove(t *testing.T) {
	numOfAccounts := 2
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	ledger := makeMockLedger(t, initAccFixed(addresses, 1<<32))
	transactionPool := MakeTransactionPool(ledger, testPoolSize, false, nil)

	sender := addresses[0]
	receiver := addresses[1]
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee + 1},
			FirstValid:  1,
			LastValid:   10,
			Note:        []byte{0},
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 0},
		},
	}
	signedTx, pf := signAndProveTx(t, ledger, tx, secrets[0])
	require.NoError(t, transactionPool.Remember(signedTx, pf))
	require.Equal(t, transactionPool.Pending(), []transactions.SignedTxnAndProof{{SignedTxn: signedTx, TransactionProof: pf}})
}

func BenchmarkTransactionPoolRemember(b *testing.B) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	ledger := makeMockLedger(b, initAccFixed(addresses, 1<<32))
	transactionPool := MakeTransactionPool(ledger, b.N, false, nil)
	signedTransactions := make([]transactions.SignedTxn, 0, b.N)
	transactionProofs := make([]transactions.TransactionProof, 0, b.N)
	for i, sender := range addresses {
		for j := 0; j < b.N/len(addresses); j++ {
			var receiver basics.Address
			crypto.RandBytes(receiver[:])
			tx := transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Sender:      sender,
					Fee:         basics.MicroAlgos{Raw: uint64(rand.Int()%10000) + proto.MinTxnFee},
					FirstValid:  1,
					LastValid:   basics.Round(proto.MaxTxnLife),
					Note:        make([]byte, 2),
					GenesisHash: ledger.GenesisHash(),
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: receiver,
					Amount:   basics.MicroAlgos{Raw: proto.MinBalance},
				},
			}
			tx.Note = make([]byte, 8, 8)
			crypto.RandBytes(tx.Note)
			signedTx, pf := signAndProveTx(b, ledger, tx, secrets[i])
			signedTransactions = append(signedTransactions, signedTx)
			transactionProofs = append(transactionProofs, pf)
			err := transactionPool.Remember(signedTx, pf)
			require.NoError(b, err)
		}
	}
	b.StopTimer()
	b.ResetTimer()
	ledger = makeMockLedger(b, initAccFixed(addresses, 1<<32))
	transactionPool = MakeTransactionPool(ledger, b.N, false, nil)

	b.StartTimer()
	for i := range signedTransactions {
		transactionPool.Remember(signedTransactions[i], transactionProofs[i])
	}
}

func BenchmarkTransactionPoolPending(b *testing.B) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	sub := func(b *testing.B, benchPoolSize int) {
		b.StopTimer()
		b.ResetTimer()

		ledger := makeMockLedger(b, initAccFixed(addresses, 1<<32))
		transactionPool := MakeTransactionPool(ledger, benchPoolSize, false, nil)
		var block bookkeeping.Block
		block.Payset = make(transactions.Payset, 0)

		for i, sender := range addresses {
			for j := 0; j < benchPoolSize/len(addresses); j++ {
				var receiver basics.Address
				crypto.RandBytes(receiver[:])
				tx := transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender:      sender,
						Fee:         basics.MicroAlgos{Raw: uint64(rand.Int()%10000) + proto.MinTxnFee},
						FirstValid:  1,
						LastValid:   basics.Round(proto.MaxTxnLife),
						Note:        make([]byte, 2),
						GenesisHash: ledger.GenesisHash(),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver: receiver,
						Amount:   basics.MicroAlgos{Raw: proto.MinBalance},
					},
				}
				tx.Note = make([]byte, 8, 8)
				crypto.RandBytes(tx.Note)
				signedTx, pf := signAndProveTx(b, ledger, tx, secrets[i])
				err := transactionPool.Remember(signedTx, pf)
				require.NoError(b, err)
			}
		}

		b.StartTimer()
		for i := 0; i < b.N; i++ {
			transactionPool.Pending()
		}
	}
	subs := []int{1000, 5000, 10000, 25000, 50000}
	for _, bps := range subs {
		b.Run(fmt.Sprintf("Pending-%d", bps), func(b *testing.B) {
			sub(b, bps)
		})
	}
}

func BenchmarkTransactionPoolSteadyState(b *testing.B) {
	poolSize := 100000

	fmt.Printf("BenchmarkTransactionPoolSteadyState: N=%d\n", b.N)

	numOfAccounts := 100
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	l := makeMockLedger(b, initAccFixed(addresses, 1<<32))
	transactionPool := MakeTransactionPool(l, poolSize, false, nil)

	var signedTransactions []transactions.SignedTxn
	for i := 0; i < b.N; i++ {
		var receiver basics.Address
		crypto.RandBytes(receiver[:])
		tx := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      addresses[i%numOfAccounts],
				Fee:         basics.MicroAlgos{Raw: uint64(rand.Int()%10000) + proto.MinTxnFee},
				FirstValid:  1,
				LastValid:   basics.Round(proto.MaxTxnLife),
				GenesisHash: l.GenesisHash(),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: receiver,
				Amount:   basics.MicroAlgos{Raw: proto.MinBalance},
			},
		}
		tx.Note = make([]byte, 8, 8)
		crypto.RandBytes(tx.Note)

		signedTx, err := transactions.AssembleSignedTxn(tx, crypto.Signature{}, crypto.MultisigSig{})
		require.NoError(b, err)
		signedTransactions = append(signedTransactions, signedTx)
	}

	b.StopTimer()
	b.ResetTimer()
	b.StartTimer()

	poolTxnQueue := signedTransactions
	var ledgerTxnQueue []transactions.SignedTxn

	for len(poolTxnQueue) > 0 || len(ledgerTxnQueue) > 0 {
		// Fill up txpool
		for len(poolTxnQueue) > 0 {
			stx := poolTxnQueue[0]
			err := transactionPool.Remember(stx, transactions.TransactionProof{})
			if err == nil {
				poolTxnQueue = poolTxnQueue[1:]
				ledgerTxnQueue = append(ledgerTxnQueue, stx)
				continue
			}
			if strings.Contains(err.Error(), "transaction pool is full") {
				break
			}
			require.NoError(b, err)
		}

		// Commit a block
		eval := newBlockEvaluator(b, l)
		for len(ledgerTxnQueue) > 0 {
			stx := ledgerTxnQueue[0]
			err := eval.Transaction(stx, nil, transactions.TransactionProof{})
			if err == ledger.ErrNoSpace {
				break
			}
			require.NoError(b, err)
			ledgerTxnQueue = ledgerTxnQueue[1:]
		}

		blk, err := eval.GenerateBlock()
		require.NoError(b, err)

		err = l.AddValidatedBlock(*blk, agreement.Certificate{})
		require.NoError(b, err)

		transactionPool.OnNewBlock(blk.Block())

		fmt.Printf("BenchmarkTransactionPoolSteadyState: committed block %d\n", blk.Block().Round())
	}
}

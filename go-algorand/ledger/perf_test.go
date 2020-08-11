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
	"context"
	"fmt"
	"io/ioutil"
	"math/rand"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/algorand/go-deadlock"

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

func genesis(naccts int) ([]bookkeeping.Block, map[basics.Address]basics.AccountData, []basics.Address, []*crypto.SignatureSecrets) {
	blk := bookkeeping.Block{}
	blk.CurrentProtocol = protocol.ConsensusCurrentVersion
	blk.BlockHeader.GenesisID = "test"
	blk.FeeSink = testSinkAddr
	blk.RewardsPool = testPoolAddr
	crypto.RandBytes(blk.BlockHeader.GenesisHash[:])

	blks := []bookkeeping.Block{blk}
	addrs := []basics.Address{}
	keys := []*crypto.SignatureSecrets{}
	accts := make(map[basics.Address]basics.AccountData)

	for i := 0; i < naccts; i++ {
		var seed crypto.Seed
		crypto.RandBytes(seed[:])
		key := crypto.GenerateSignatureSecrets(seed)
		addr := basics.Address(key.SignatureVerifier)

		keys = append(keys, key)
		addrs = append(addrs, addr)

		adata := basics.AccountData{}
		adata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000 / uint64(naccts)
		accts[addr] = adata
	}

	// pooldata := basics.AccountData{}
	// pooldata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	// pooldata.Status = basics.NotParticipating
	// accts[testPoolAddr] = pooldata

	// sinkdata := basics.AccountData{}
	// sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	// sinkdata.Status = basics.NotParticipating
	// accts[testSinkAddr] = sinkdata

	return blks, accts, addrs, keys
}

const startingAddrs = 1000000

// const startingAddrs = 100000

// const startingAddrs = 10000

// const startingAddrs = 10

// const numBlocksHistory = 1005
// const numBlocksWorkload = 1000
// const txnsPerBlock = 100

const numBlocksHistory = 12
const numBlocksWorkload = 10
const txnsPerBlock = 10000

// const txnsPerBlock = 500

func generateTxn(l *Ledger, genaddrs []basics.Address, tt protocol.TxType, hint int) transactions.Transaction {
	rnd := l.Latest() + 1
	fv := rnd.SubSaturate(basics.Round(rand.Intn(10)))
	lv := basics.Round(rnd + basics.Round(rand.Intn(int(10-rnd+fv))))
	snd := rand.Uint64() % uint64(len(genaddrs))

	var nonce [32]byte
	n, err := rand.Read(nonce[:])
	if n != 32 {
		panic("rand read != 32")
	}
	if err != nil {
		panic(err)
	}

	tx := transactions.Transaction{
		Type: tt,
		Header: transactions.Header{
			Sender:     genaddrs[snd],
			FirstValid: fv,
			LastValid:  lv,
		},
		Nonce: nonce,
	}

	if tt != protocol.Delete {
		v := basics.MakeAccountData(basics.Online, basics.MicroAlgos{rand.Uint64()})
		tx.NewValue = v
	}
	if tt == protocol.Create {
		var k basics.Address
		n, err := rand.Read(k[:])
		if n != 32 {
			panic("rand read != 32")
		}
		if err != nil {
			panic(err)
		}
		tx.Sender = k
	}
	if tt == protocol.Delete {
		tx.Sender = genaddrs[hint]
	}

	return tx
}

type ReferenceTxnVerifier struct {
	mu sync.RWMutex

	vcdb VectorCommitmentDB

	verificationPool execpool.BacklogPool

	cache map[transactions.Txid]transactions.SignedTxnAndProof
}

func (v *ReferenceTxnVerifier) Verify(stxn transactions.SignedTxn) error {
	pf, err := stxn.PoolValidateProof(v.vcdb, transactions.SpecialAddresses{}, v.verificationPool)
	if err == nil {
		v.mu.Lock()
		defer v.mu.Unlock()

		v.cache[stxn.ID()] = transactions.SignedTxnAndProof{
			SignedTxn:        stxn,
			TransactionProof: pf,
		}
	}
	return err
}

func (v *ReferenceTxnVerifier) Verified(stxn transactions.SignedTxn) (transactions.TransactionProof, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	entry, ok := v.cache[stxn.ID()]
	if !ok {
		return transactions.TransactionProof{}, false
	}

	pendingSigTxn := entry.SignedTxn
	if pendingSigTxn.Proof == stxn.Proof {
		return entry.TransactionProof, true
	}
	return transactions.TransactionProof{}, false
}

type initData struct {
	Block0   bookkeeping.Block
	Accounts map[basics.Address]basics.AccountData
}

type runData []bookkeeping.Block

const initfile = "workload-init"
const workloadfile = "workload"
const workloadname = "workload"

type testGenReq struct {
	dump chan transactions.SignedTxnAndProof
	hint int
}

var workloadkinds = []protocol.TxType{protocol.Modify, protocol.Create, protocol.Delete}
// var workloadkinds = []protocol.TxType{protocol.Delete}

func TestWorkloadGen(t *testing.T) {
	for _, tt := range workloadkinds {
		testWorkloadGenSeries(t, tt)
	}
}

func testWorkloadGenSeries(t *testing.T, tt protocol.TxType) {
	deadlock.Opts.Disable = true

	rand.Seed(1)
	perm := rand.Perm(startingAddrs)

	rand.Seed(0)
	var genaddrs [startingAddrs]basics.Address
	for i := range genaddrs {
		n, err := rand.Read(genaddrs[i][:])
		if n != 32 {
			panic("rand read != 32")
		}
		if err != nil {
			panic(err)
		}
	}

	initAccounts := make(map[basics.Address]basics.AccountData, startingAddrs)
	for i := range genaddrs {
		// Give each account quite a bit more balance than MinFee or MinBalance
		initAccounts[genaddrs[i]] = basics.MakeAccountData(basics.Online, basics.MicroAlgos{Raw: uint64((i + 100) * 100000)})
	}

	params := config.Consensus[protocol.ConsensusCurrentVersion]
	params.MaxTxnLife = 10
	var emptyPayset transactions.Payset
	blk0 := bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{
		GenesisID:   t.Name(),
		GenesisHash: crypto.Hash([]byte(workloadname)),
		Round:       0,
		TxnRoot:     emptyPayset.Commit(params.PaysetCommitFlat),
	}}
	blk0.CurrentProtocol = protocol.ConsensusCurrentVersion
	initBlocks := []bookkeeping.Block{blk0}

	fmt.Println(len(initAccounts))

	idata := initData{
		Block0:   blk0,
		Accounts: initAccounts,
	}
	raw := protocol.Encode(idata)
	err := ioutil.WriteFile(fmt.Sprintf("%s-%s", initfile, tt), raw, 0600)
	if err != nil {
		panic(err)
	}

	lVal, err := OpenLedger(logging.Base(), fmt.Sprintf("%s-%s-val", t.Name(), tt), true, initBlocks, initAccounts, crypto.Hash([]byte(workloadname)))
	if err != nil {
		panic(err)
	}

	cpus := runtime.NumCPU()
	backlogPool := execpool.MakeBacklog(nil, cpus*2, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	hblks := make([]*ValidatedBlock, numBlocksHistory)
	wblks := make([]*ValidatedBlock, numBlocksWorkload)
	hblks[0] = nil // TODO this is actually blk0
	inconf := make([]chan struct{}, numBlocksHistory+numBlocksWorkload)
	queries := make([]chan testGenReq, numBlocksHistory+numBlocksWorkload)
	for i := range inconf {
		inconf[i] = make(chan struct{})
		queries[i] = make(chan testGenReq, cpus)
	}

	for i := 0; i < cpus; i++ {
		go func(i int) {
			lGen, err := OpenLedger(logging.Base(), fmt.Sprintf("%s-%s-gen-%d", t.Name(), tt, i), true, initBlocks, initAccounts, crypto.Hash([]byte(workloadname)))
			if err != nil {
				panic(err)
			}

			for j := 1; j < numBlocksHistory+numBlocksWorkload; {
				signal := inconf[j]
				query := queries[j]
				select {
				case <-signal:
					var blk *ValidatedBlock
					if j >= len(hblks) {
						blk = wblks[j-len(hblks)]
					} else {
						blk = hblks[j]
					}
					err := lGen.AddValidatedBlock(*blk, agreement.Certificate{})
					if err != nil {
						panic(err)
					}
					j++
				case req := <-query:
					// TODO set depending on history
					txn := generateTxn(lGen, genaddrs[:], tt, perm[req.hint])
					pf, err := txn.Prove(lGen, transactions.SpecialAddresses{})
					if err != nil {
						panic(err)
					}

					stxn := transactions.SignedTxnAndProof{
						SignedTxn: transactions.SignedTxn{
							Txn:   txn,
							Proof: pf.Unvalidated(),
						},
						TransactionProof: pf,
					}

					req.dump <- stxn
				}
			}
		}(i)
	}

	allBlocks := make([]bookkeeping.Block, numBlocksHistory+numBlocksWorkload)

	v := new(ReferenceTxnVerifier)
	v.vcdb = lVal.VectorCommitments()
	v.verificationPool = backlogPool
	v.cache = make(map[transactions.Txid]transactions.SignedTxnAndProof)

	hdr := blk0.BlockHeader
	txns := make(chan transactions.SignedTxnAndProof, cpus)
	for i := 1; i < numBlocksHistory+numBlocksWorkload; i++ {
		fmt.Printf("blk-%d\n", i)

		_, seq, err := lVal.NewChunks(lVal.Latest(), lVal.Latest())
		if err != nil {
			panic(err)
		}
		chunk, err := lVal.Preimage(lVal.Latest(), seq)
		if err != nil {
			panic(err)
		}
		slots := chunk.Slots
		for len(slots) < txnsPerBlock && seq > 0 {
			seq--
			chunk, err := lVal.Preimage(lVal.Latest(), seq)
			if err != nil {
				panic(err)
			}
			slots = append(chunk.Slots, slots...)
		}
		fmt.Printf("%+v\n", len(slots))
		tail := basics.AccountTail{Entries: slots}

		blk := bookkeeping.MakeBlock(hdr)
		eval, err := lVal.StartEvaluator(blk.BlockHeader, tail, v, backlogPool)
		if err != nil {
			panic(err)
		}

		go func() {
			for j := 0; j < txnsPerBlock; j++ {
				queries[i] <- testGenReq{
					dump: txns,
					hint: i*txnsPerBlock + j,
				}
			}
		}()

		for j := 0; j < txnsPerBlock; j++ {
			stxn := <-txns
			v.cache[stxn.ID()] = stxn
			err := eval.Transaction(stxn.SignedTxn, stxn.TransactionProof)
			if err != nil {
				fmt.Println(err)
				continue
			}
		}

		vblk, err := eval.GenerateBlock()
		if err != nil {
			panic(err)
		}

		err = lVal.AddValidatedBlock(*vblk, agreement.Certificate{})
		if err != nil {
			panic(err)
		}

		if i >= len(hblks) {
			wblks[i-len(hblks)] = vblk
		} else {
			hblks[i] = vblk
		}
		close(inconf[i])

		allBlocks[i] = vblk.blk

		hdr = vblk.blk.BlockHeader
	}

	rdata := runData(allBlocks)
	raw = protocol.Encode(rdata)
	err = ioutil.WriteFile(fmt.Sprintf("%s-%s", workloadfile, tt), raw, 0600)
	if err != nil {
		panic(err)
	}
}

func TestTimeWorkload(t *testing.T) {
	for _, tt := range workloadkinds {
		testTimeWorkloadSeries(t, tt)
	}
}

var iter = 0

func testTimeWorkloadSeries(t *testing.T, tt protocol.TxType) {
	iter++

	var idata initData
	raw, err := ioutil.ReadFile(fmt.Sprintf("%s-%s", initfile, tt))
	if err != nil {
		panic(err)
	}
	err = protocol.Decode(raw, &idata)
	if err != nil {
		panic(err)
	}

	initBlocks := []bookkeeping.Block{idata.Block0}
	lVal, err := OpenLedger(logging.Base(), fmt.Sprintf("%s-%s-val-%d", t.Name(), tt, iter), true, initBlocks, idata.Accounts, crypto.Hash([]byte(workloadname)))
	if err != nil {
		panic(err)
	}

	var rdata runData
	raw, err = ioutil.ReadFile(fmt.Sprintf("%s-%s", workloadfile, tt))
	if err != nil {
		panic(err)
	}
	err = protocol.Decode(raw, &rdata)
	if err != nil {
		panic(err)
	}

	cpus := runtime.NumCPU()
	backlogPool := execpool.MakeBacklog(nil, cpus*2, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	v := new(ReferenceTxnVerifier)
	v.vcdb = lVal.VectorCommitments()
	v.verificationPool = backlogPool
	v.cache = make(map[transactions.Txid]transactions.SignedTxnAndProof)

	for i := 1; i < numBlocksHistory; i++ {
		blk := rdata[i]

		for _, stxn := range blk.Payset {
			pf, err := stxn.UnsafeDecodeProof(v.vcdb, backlogPool)
			if err != nil {
				panic(err)
			}
			v.cache[stxn.ID()] = transactions.SignedTxnAndProof{
				SignedTxn:        stxn,
				TransactionProof: pf,
			}
		}

		vb, err := lVal.Validate(context.Background(), blk, v, backlogPool)
		if err != nil {
			panic(err)
		}
		err = lVal.AddValidatedBlock(*vb, agreement.Certificate{})
		if err != nil {
			panic(err)
		}
	}

	t0 := time.Now()
	for i := 0; i < numBlocksWorkload; i++ {
		blk := rdata[i+numBlocksHistory]

		v := new(ReferenceTxnVerifier)
		v.vcdb = lVal.VectorCommitments()
		v.verificationPool = backlogPool
		v.cache = make(map[transactions.Txid]transactions.SignedTxnAndProof)

		out := make(chan struct{}, cpus*2)
		in := make(chan transactions.SignedTxn, cpus*2)
		for i := 0; i < cpus; i++ {
			go func() {
				for stxn := range in {
					err := v.Verify(stxn)
					if err != nil {
						panic(err)
					}
					out <- struct{}{}
				}
			}()
		}
		go func() {
			for _, txn := range blk.Payset {
				in <- txn
			}
		}()
		for range blk.Payset {
			<-out
		}

		vb, err := lVal.Validate(context.Background(), blk, v, backlogPool)
		if err != nil {
			fmt.Println(err)
			continue
			// panic(err)
		}
		err = lVal.AddValidatedBlock(*vb, agreement.Certificate{})
		if err != nil {
			fmt.Println(err)
			continue
			// panic(err)
		}
	}
	fmt.Println(tt, "time:", time.Now().Sub(t0))
}

func TestTimeArchive(t *testing.T) {
	for _, tt := range workloadkinds {
		testTimeLookupProof(t, tt)
	}
}

func testTimeLookupProof(t *testing.T, tt protocol.TxType) {
	iter++

	var idata initData
	raw, err := ioutil.ReadFile(fmt.Sprintf("%s-%s", initfile, tt))
	if err != nil {
		panic(err)
	}
	err = protocol.Decode(raw, &idata)
	if err != nil {
		panic(err)
	}

	initBlocks := []bookkeeping.Block{idata.Block0}
	lArc, err := OpenLedger(logging.Base(), fmt.Sprintf("%s-%s-arc-%d", t.Name(), tt, iter), true, initBlocks, idata.Accounts, crypto.Hash([]byte(workloadname)))
	if err != nil {
		panic(err)
	}

	var rdata runData
	raw, err = ioutil.ReadFile(fmt.Sprintf("%s-%s", workloadfile, tt))
	if err != nil {
		panic(err)
	}
	err = protocol.Decode(raw, &rdata)
	if err != nil {
		panic(err)
	}

	cpus := runtime.NumCPU()
	backlogPool := execpool.MakeBacklog(nil, cpus*2, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	v := new(ReferenceTxnVerifier)
	v.vcdb = lArc.VectorCommitments()
	v.verificationPool = backlogPool
	v.cache = make(map[transactions.Txid]transactions.SignedTxnAndProof)

	for i := 1; i < numBlocksHistory; i++ {
		blk := rdata[i]

		for _, stxn := range blk.Payset {
			pf, err := stxn.UnsafeDecodeProof(v.vcdb, backlogPool)
			if err != nil {
				panic(err)
			}
			v.cache[stxn.ID()] = transactions.SignedTxnAndProof{
				SignedTxn:        stxn,
				TransactionProof: pf,
			}
		}

		vb, err := lArc.Validate(context.Background(), blk, v, backlogPool)
		if err != nil {
			panic(err)
		}
		err = lArc.AddValidatedBlock(*vb, agreement.Certificate{})
		if err != nil {
			panic(err)
		}
	}

	blk := rdata[numBlocksHistory]

	v = new(ReferenceTxnVerifier)
	v.vcdb = lArc.VectorCommitments()
	v.verificationPool = backlogPool
	v.cache = make(map[transactions.Txid]transactions.SignedTxnAndProof)

	t0 := time.Now()
	for _, stxn := range blk.Payset {
		txn := stxn.Txn
		_, err := txn.Prove(lArc, transactions.SpecialAddresses{})
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("archive", tt, "time:", time.Now().Sub(t0))
}


// func BenchmarkManyAccounts(b *testing.B) {
// 	deadlock.Opts.Disable = true

// 	b.StopTimer()

// 	blks, accts, addrs, _ := genesis(1)
// 	addr := addrs[0]

// 	dbName := fmt.Sprintf("%s.%d", b.Name(), crypto.RandUint64())
// 	l, err := OpenLedger(logging.Base(), dbName, true, blks, accts, crypto.Digest{})
// 	require.NoError(b, err)

// 	blk := blks[len(blks)-1]
// 	for i := 0; i < b.N; i++ {
// 		blk = bookkeeping.MakeBlock(blk.BlockHeader)

// 		proto, ok := config.Consensus[blk.CurrentProtocol]
// 		require.True(b, ok)

// 		var txbytes int
// 		for {
// 			var st transactions.SignedTxn
// 			crypto.RandBytes(st.Sig[:])
// 			st.Txn.Type = protocol.PaymentTx
// 			st.Txn.Sender = addr
// 			st.Txn.Fee = basics.MicroAlgos{Raw: 1}
// 			st.Txn.Amount = basics.MicroAlgos{Raw: 1}
// 			crypto.RandBytes(st.Txn.Receiver[:])

// 			txib, err := blk.EncodeSignedTxn(st, transactions.ApplyData{})
// 			require.NoError(b, err)

// 			txlen := len(protocol.Encode(txib))
// 			if txbytes+txlen > proto.MaxTxnBytesPerBlock {
// 				break
// 			}

// 			txbytes += txlen
// 			blk.Payset = append(blk.Payset, txib)
// 		}

// 		var c agreement.Certificate
// 		b.StartTimer()
// 		err := l.AddBlock(blk, c)
// 		b.StopTimer()
// 		require.NoError(b, err)
// 	}
// }

// func BenchmarkValidate(b *testing.B) {
// 	b.StopTimer()

// 	blks, accts, addrs, keys := genesis(10000)

// 	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
// 	defer backlogPool.Shutdown()

// 	dbName := fmt.Sprintf("%s.%d", b.Name(), crypto.RandUint64())
// 	l, err := OpenLedger(logging.Base(), dbName, true, blks, accts, crypto.Digest{})
// 	require.NoError(b, err)

// 	blk := blks[len(blks)-1]
// 	for i := 0; i < b.N; i++ {
// 		newblk := bookkeeping.MakeBlock(blk.BlockHeader)

// 		proto, ok := config.Consensus[newblk.CurrentProtocol]
// 		require.True(b, ok)

// 		var txbytes int
// 		for i := 0; i < 10000; i++ {
// 			t := transactions.Transaction{
// 				Type: protocol.PaymentTx,
// 				Header: transactions.Header{
// 					Sender:     addrs[i],
// 					Fee:        basics.MicroAlgos{Raw: 1},
// 					FirstValid: newblk.Round(),
// 					LastValid:  newblk.Round(),
// 				},
// 				PaymentTxnFields: transactions.PaymentTxnFields{
// 					Amount: basics.MicroAlgos{Raw: 1},
// 				},
// 			}
// 			crypto.RandBytes(t.Receiver[:])
// 			st := t.Sign(keys[i])

// 			txib, err := newblk.EncodeSignedTxn(st, transactions.ApplyData{})
// 			require.NoError(b, err)

// 			txlen := len(protocol.Encode(txib))
// 			if txbytes+txlen > proto.MaxTxnBytesPerBlock {
// 				break
// 			}

// 			txbytes += txlen
// 			newblk.Payset = append(newblk.Payset, txib)
// 		}

// 		newblk.BlockHeader.TxnRoot = newblk.Payset.Commit(false)

// 		b.StartTimer()
// 		_, err = l.Validate(context.Background(), newblk, nil, backlogPool)
// 		b.StopTimer()
// 		require.NoError(b, err)
// 	}
// }

func benchInit(ledgerName string, t testing.TB) ([]basics.Address, *Ledger) {
	// a := require.New(t)

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

	params := config.Consensus[protocol.ConsensusCurrentVersion]

	rand.Seed(0)
	// var zeroSeed crypto.Seed
	var genaddrs [startingAddrs]basics.Address
	for i := range genaddrs {
		// seed := zeroSeed
		// seed[0] = byte(i)
		// x := crypto.GenerateSignatureSecrets(seed)
		n, err := rand.Read(genaddrs[i][:])
		if n != 32 {
			panic("rand read != 32")
		}
		if err != nil {
			panic(err)
		}
	}

	initAccounts := make(map[basics.Address]basics.AccountData, startingAddrs)
	for i := range genaddrs {
		// Give each account quite a bit more balance than MinFee or MinBalance
		initAccounts[genaddrs[i]] = basics.MakeAccountData(basics.Online, basics.MicroAlgos{Raw: uint64((i + 100) * 100000)})
	}

	var emptyPayset transactions.Payset
	blk := bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{
		GenesisID:   t.Name(),
		GenesisHash: crypto.Hash([]byte(t.Name())),
		Round:       0,
		TxnRoot:     emptyPayset.Commit(params.PaysetCommitFlat),
	}}
	blk.CurrentProtocol = protocol.ConsensusCurrentVersion

	fmt.Println(len(initAccounts))

	initBlocks := []bookkeeping.Block{blk}
	l, err := OpenLedger(logging.Base(), ledgerName, true, initBlocks, initAccounts, crypto.Hash([]byte(t.Name())))
	if err != nil {
		panic(err)
	}
	blk1 := bookkeeping.MakeBlock(blk.BlockHeader)
	eval, err := l.StartEvaluator(blk1.BlockHeader, basics.AccountTail{}, DummyVerifiedTxnCache{}, backlogPool)
	if err != nil {
		panic(err)
	}
	_ = eval

	return genaddrs[:], l
}

func BenchmarkArchiveRead(b *testing.B) {
	genaddrs, l := benchInit(b.Name(), b)

	fv := basics.Round(0)
	lv := basics.Round(100)
	v := basics.MakeAccountData(basics.Online, basics.MicroAlgos{420000})

	rand.Seed(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		snd := rand.Uint64() % uint64(len(genaddrs))
		tx := transactions.Transaction{
			Type: protocol.Modify,
			Header: transactions.Header{
				Sender:     genaddrs[snd],
				FirstValid: fv,
				LastValid:  lv,
			},
			NewValue: v,
		}
		pf, err := l.LookupProof(tx.FirstValid.SubSaturate(1), tx.Sender)
		if err != nil {
			panic(err)
		}
		_ = pf
	}
}

func XTestTimeArchiveReads(t *testing.T) {
	testTimeArchiveReadsN(t, 10)
}

func testTimeArchiveReadsN(t *testing.T, N int) {
	genaddrs, l := benchInit(t.Name(), t)

	rand.Seed(1)
	fmt.Println(l.Latest())

	txns := make([]transactions.Transaction, N)
	for i := 0; i < N; i++ {
		txtype := protocol.Modify
		txns[i] = generateTxn(l, genaddrs, txtype, i)
	}

	t0 := time.Now()
	for i := 0; i < N; i++ {
		pf, err := l.LookupProof(txns[i].FirstValid.SubSaturate(1), txns[i].Sender)
		if err != nil {
			panic(err)
		}
		_ = pf
	}
	fmt.Println(N, "time:", time.Now().Sub(t0))
}

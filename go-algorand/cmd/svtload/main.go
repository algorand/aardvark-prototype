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

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/db"
)

const targetNumWallets = 1000

var dataDir = flag.String("datadir", "", "path to datadir")
var halt = flag.Bool("halt", false, "halt svtload")
var cut = flag.Bool("cut", false, "return early")

type FuzzStats struct {
	FuzzStart time.Time
	FuzzEnd   time.Time

	FuzzStartRound basics.Round
	FuzzEndRound   basics.Round
}

func main() {
	defer func() {
		fmt.Println("exiting in 5s")
		time.Sleep(5 * time.Second)
	}()

	flag.Parse()

	binDir, err := util.ExeDir()
	if err != nil {
		panic(err)
	}

	if *dataDir == "" {
		panic("no data directory specified!")
	}

	if *halt {
		nc := nodecontrol.MakeNodeController(binDir, *dataDir)
		err = nc.FullStop()
		if err != nil {
			panic(err)
		}
		return
	}

	// start algod
	nc := nodecontrol.MakeNodeController(binDir, *dataDir)
	nodeArgs := nodecontrol.AlgodStartArgs{
		// PeerAddress: *peers,
	}

	nc.SetKMDDataDir(*dataDir)

	_, err = nc.StartAlgod(nodeArgs)
	if err != nil {
		panic(err)
	}

	_, err = nc.StartKMD(nodecontrol.KMDStartArgs{})
	if err != nil {
		panic(err)
	}

	// make libgoal client
	cacheDir, err := ioutil.TempDir("", "svtload")
	if err != nil {
		panic(err)
	}

	client, err := libgoal.MakeClient(*dataDir, cacheDir, libgoal.FullClient)
	if err != nil {
		panic(err)
	}

	importRootKeys(client, *dataDir)

	go walletHandleRefreshWorker(client)
	go currRoundWorker(client)
	time.Sleep(250 * time.Millisecond)

	addresses, err := client.ListAddresses(getWH())
	if err != nil {
		panic(err)
	}

	var prime string

	if len(addresses) == 0 {
		fmt.Println("setup: node has no wallets")
		return
	}
	if *cut {
		fmt.Println("setup: cut set; returning early")
		return
	}

	fmt.Println("setup: addresses are", addresses)

	// coalesce to one wallet
	prime = addresses[0]
	toClose := addresses[1:]

	fmt.Printf("coalesce: closing into %v\n", prime)
	for !allZero(client, toClose) {
		fv, fee := status(client)
		lv := fv + 2

		var wg sync.WaitGroup
		wg.Add(len(toClose))
		for _, addr := range toClose {
			go func(addr string) {
				defer wg.Done()

				_, err := client.SendPaymentFromWallet(getWH(), nil, addr, "", fee, 0, nil, prime, fv, lv)
				if err != nil {
					fmt.Printf("coalesce: could not send payment: %v\n", err)
					return
				}
				fmt.Printf("coalesce: submitted close for: %v\n", addr)
			}(addr)
		}
		wg.Wait()

		fmt.Printf("coalesce: waiting for lv: %d\n", lv)
		waitFor(client, lv)
	}

	fmt.Printf("coalesce: wallets coalesced into %v successfully\n", prime)

	newAddrs := initialDisbursement(client, prime)
	_ = newAddrs

	_, fee := status(client)
	numWorkers := 200
	prodToCons := make(chan txOpenReq, 200)
	toProd := make(chan txPaymentPair)
	for i := 0; i < numWorkers; i++ {
		go txConsWorker("fuzz", client, i, numWorkers, 3*fee, 1, prodToCons)
	}

	done := make(chan struct{})
	go func() {
		txProd("fuzz", client, false, toProd, prodToCons, targetNumWallets)
		close(done)
	}()

	// stopRound := currRound() + basics.Round(1100)
	stopRound := currRound() + basics.Round(1100)
	go func() {
		for {
			for i := 0; i < targetNumWallets; i++ {
				// i := crypto.RandUint64() % uint64(len(newAddrs))
				j := crypto.RandUint64() % uint64(len(newAddrs))

				select {
				case toProd <- txPaymentPair{from: newAddrs[i], to: newAddrs[j]}:
				case <-done:
					return
				}

				if currRound() == stopRound {
					close(toProd)
					return
				}
			}
		}
	}()

	var stats FuzzStats
	stats.FuzzStart = time.Now()
	stats.FuzzStartRound = currRound()
	<-done
	stats.FuzzEnd = time.Now()
	stats.FuzzEndRound = currRound()

	enc, err := json.Marshal(stats)
	if err != nil {
		panic(err)
	}
	ioutil.WriteFile(filepath.Join(*dataDir, "meta.json"), enc, 0666)

	// now, _ = status(client)
	// disburseStart := now
	// fmt.Printf("initial-disbursement: (rnd %d) disbursements are now complete. created %d accounts in %d rounds\n", now, targetNumWallets, now-disburseStart)

	// now, _ := status(client)
	// fmt.Println("round is now", now)
}

func initialDisbursement(client libgoal.Client, prime string) (newAddrs []string) {
	// take 25% and split into targetNumWallets
	resp, err := client.AccountInformation(prime)
	if err != nil {
		fmt.Printf("error: could not get info for %v: %v\n", prime, err)
		return
	}
	disbursements := resp.Amount / 4

	singleAmount := disbursements / targetNumWallets
	newAddrs = make([]string, targetNumWallets)
	for i := 0; i < targetNumWallets; i++ {
		receiver, err := client.GenerateAddress(getWH())
		if err != nil {
			fmt.Printf("could not generate address: %v\n", err)
			return
		}
		newAddrs[i] = receiver
		if (i+1)%100 == 0 {
			fmt.Printf("initial-disbursement: generated %d addresses\n", i+1)
		}
	}

	now, _ := status(client)
	fmt.Printf("initial-disbursement: (rnd %d) prime wallet now has %d. preparing %d for disbursements\n", now, resp.Amount, disbursements)

	numWorkers := 100
	prodToCons := make(chan txOpenReq, 100)
	toProd := make(chan txPaymentPair)
	for i := 0; i < numWorkers; i++ {
		go txConsWorker("initial-disbursement", client, i, numWorkers, singleAmount, 4, prodToCons)
	}

	done := make(chan struct{})
	go func() {
		txProd("initial-disbursement", client, true, toProd, prodToCons, targetNumWallets)
		close(done)
	}()

	go func() {
		for {
			for i := 0; i < targetNumWallets; i++ {
				select {
				case toProd <- txPaymentPair{from: prime, to: newAddrs[i]}:
				case <-done:
					return
				}
			}
		}
	}()

	<-done

	disburseStart := now
	now, _ = status(client)
	fmt.Printf("initial-disbursement: (rnd %d) disbursements are now complete. created %d accounts in %d rounds\n", now, targetNumWallets, now-disburseStart)
	fmt.Printf("initial-disbursement: wait for round 35 for other processes to finish\n")
	waitFor(client, 35)

	return
}

type txOpenReq struct {
	from, to string
	fv, lv   basics.Round
	fee      uint64
}

type txPaymentPair struct {
	from, to string
}

const roundHeadroom = 600

func txProd(info string, client libgoal.Client, termEmpty bool, addrs <-chan txPaymentPair, consumer chan<- txOpenReq, totalAddrs int) {
	doneAddrs := make(map[string]bool)

	fv, fee := status(client)
	lv := fv + roundHeadroom

	deadline := time.After(1 * time.Second)
	for pair := range addrs {
		from, to := pair.from, pair.to

		if termEmpty {
			var amt uint64
			for {
				resp, err := client.AccountInformation(to)
				if err != nil {
					fmt.Printf("warning: could not get account info: %v\n", err)
					fmt.Printf("warning: retrying in 1s\n")
					time.Sleep(time.Second)
					continue
				}
				amt = resp.Amount
				break
			}

			if amt > 0 {
				if !doneAddrs[to] {
					fmt.Printf("%s: created new account %v\n", info, to)
				}
				doneAddrs[to] = true
				if len(doneAddrs) == totalAddrs {
					close(consumer)
					return
				}
				continue
			}
		}

		sent := false
		for !sent {
			select {
			case consumer <- txOpenReq{from: from, to: to, fv: fv, lv: lv, fee: fee}:
				sent = true
			case <-deadline:
				// recompute parameters
				fv0, fee0 := status(client)
				lv0 := fv0 + roundHeadroom
				if fv0 > lv {
					fv, lv, fee = fv0, lv0, fee0
				}

				deadline = time.After(1 * time.Second)
			}
		}
	}
}

func txConsWorker(info string, client libgoal.Client, workerID int, numWorkers int, amount uint64, feeFactor uint64, producer <-chan txOpenReq) {
	mbtw := time.Millisecond / 2

	time.Sleep(time.Duration(workerID) * mbtw)
	// interval := basics.Round(roundHeadroom + 1)
	for req := range producer {
		// fv := (currRound() / interval) * interval
		// lv := fv + roundHeadroom
		fv := req.fv
		lv := req.lv
		key := submittedKey{
			from: req.from,
			to:   req.to,
			fv:   fv,
			lv:   lv,
		}
		submittedTxsMu.Lock()
		_, ok := submittedTxs[key]
		submittedTxsMu.Unlock()

		if !ok {
			_, err := client.SendPaymentFromWallet(getWH(), nil, req.from, req.to, 2*feeFactor*req.fee, amount-(2*feeFactor*req.fee), nil, "", fv, lv)
			if err != nil {
				fmt.Printf("warning: could not send payment: %v\n", err)
			} else {
				submittedTxsMu.Lock()
				submittedTxs[key] = true
				submittedTxsMu.Unlock()
				fmt.Printf("%s: submitted new payment for %d to: %v\n", info, amount-(2*feeFactor*req.fee), req.to)
			}
		}
		time.Sleep(time.Duration(numWorkers) * mbtw)
	}
}

type submittedKey struct {
	from, to string
	fv, lv   basics.Round
}

var submittedTxs map[submittedKey]bool
var submittedTxsMu sync.Mutex

func init() {
	submittedTxs = make(map[submittedKey]bool)
}

var curr uint64

func currRound() basics.Round {
	now := atomic.LoadUint64(&curr)
	return basics.Round(now)
}

func currRoundWorker(client libgoal.Client) {
	for {
		now, _ := status(client)
		atomic.StoreUint64(&curr, uint64(now))
		time.Sleep(time.Second)
	}
}

func status(client libgoal.Client) (now basics.Round, minFee uint64) {
	status, err := client.Status()
	if err != nil {
		fmt.Printf("warning: could not get status: %v\n", err)
	}
	proto := config.Consensus[protocol.ConsensusVersion(status.LastVersion)]

	return basics.Round(status.LastRound), proto.MinTxnFee
}

func waitFor(client libgoal.Client, until basics.Round) {
	for {
		status, err := client.Status()
		if err != nil {
			fmt.Printf("warning: could not get status: %v\n", err)
			fmt.Printf("warning: retrying in 1s\n")
			time.Sleep(time.Second)
		}

		if basics.Round(status.LastRound) > until {
			return
		}
		time.Sleep(time.Second)
		// client.WaitForRound(uint64(until))
	}

}

func allZero(client libgoal.Client, addresses []string) bool {
	allZero := true
	for _, addr := range addresses {
		resp, err := client.AccountInformation(addr)
		if err != nil {
			fmt.Printf("warning: could not get info for %v: %v\n", addr, err)
			continue
		}
		if resp.Amount != 0 {
			allZero = false
		}
	}
	return allZero
}

func importRootKeys(client libgoal.Client, dataDir string) {
	genID, err := client.GenesisID()
	if err != nil {
		return
	}

	keyDir := filepath.Join(dataDir, genID)
	files, err := ioutil.ReadDir(keyDir)
	if err != nil {
		return
	}

	// For each of these files
	for _, info := range files {
		var handle db.Accessor

		// Determine which wallet to import into
		wh, err := client.GetUnencryptedWalletHandle()
		if err != nil {
			panic(err)
		}

		// If it can't be a root key database, skip it
		if !config.IsRootKeyFilename(info.Name()) {
			continue
		}
		filename := info.Name()

		// Fetch a handle to this database
		handle, err = db.MakeErasableAccessor(filepath.Join(keyDir, filename))
		if err != nil {
			// Couldn't open it, skip it
			panic(err)
		}

		// Fetch an account.Root from the database
		root, err := account.RestoreRoot(handle)
		if err != nil {
			// Couldn't read it, skip it
			panic(err)
		}

		secretKey := root.Secrets().SK
		resp, err := client.ImportKey(wh, secretKey[:])
		if err != nil {
			panic(err)
		}
		_ = resp
	}
}

var wmu sync.RWMutex
var whErr error
var wh []byte

func walletHandleRefreshWorker(client libgoal.Client) {
	for {
		wmu.Lock()
		wh, whErr = client.GetUnencryptedWalletHandle()
		err := whErr
		wmu.Unlock()
		if err != nil {
			fmt.Printf("warning: could not get wallet handle: %v\n", err)
			fmt.Printf("warning: retrying in 1s\n")
			time.Sleep(time.Second)
			continue
		}

		time.Sleep(30 * time.Second)
	}

}

func getWH() []byte {
	wmu.RLock()
	defer wmu.RUnlock()

	return wh
}

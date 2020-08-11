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
	"context"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
)

// TODO move to config
const (
	minAcctTailSize = 20 // 2 blocks of deletions
	maxAcctTailSize = 30 // 3 blocks of deletions

	fetchDecommitmentTimeout = 6 * time.Second
)

type TailFetcher interface {
	FetchDecommitment(ctx context.Context, rnd basics.Round, seq int, validateFn func(basics.AccountChunk) error) (basics.AccountChunk, error)
}

type LedgerForTailCache interface {
	Decommit(basics.AccountChunk) error
	NewChunks(from, to basics.Round) (chunks []basics.AccountChunk, maxChunkSeq int, err error)
	UpdateChunk(chunk basics.AccountChunk, to basics.Round) (basics.AccountChunk, error)
}

// A TailCache caches the last several accounts in slot order.
// These accounts are necessary in order for block proposers
// to execute account deletions.
type TailCache struct {
	mu          deadlock.RWMutex
	rnd         basics.Round
	chunks      map[int]basics.AccountChunk // chunk.Seq -> chunk
	maxChunkSeq int

	minChunkRequest int
	maxChunkRequest int

	fetcher TailFetcher
	ledger  LedgerForTailCache

	quit bool

	requestChunks chan struct{}
}

func OpenTailCache(fetcher TailFetcher, ledger LedgerForTailCache) *TailCache {
	cache := &TailCache{
		chunks:        make(map[int]basics.AccountChunk),
		fetcher:       fetcher,
		ledger:        ledger,
		requestChunks: make(chan struct{}, 1),
	}
	go cache.worker()
	return cache
}

func (cache *TailCache) worker() {
	for range cache.requestChunks {
		if cache.quit {
			return
		}

		rnd, seqs := cache.missingChunks()
		for len(seqs) > 0 && !cache.quit {
			ctx, cancel := context.WithTimeout(context.Background(), fetchDecommitmentTimeout)
			chunk, err := cache.fetcher.FetchDecommitment(ctx, rnd, seqs[0], cache.ledger.Decommit)
			cancel()

			if err != nil {
				logging.Base().Infof("TailCache: could not fetch decommitment: %v (retrying in 1s)", err)
				time.Sleep(time.Second)
			} else {
				cache.addChunk(chunk)
			}
			rnd, seqs = cache.missingChunks()
		}
	}
}

func (cache *TailCache) Close() {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	cache.quit = true
	close(cache.requestChunks)
}

func (cache *TailCache) missingChunks() (rnd basics.Round, seqs []int) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	rnd = cache.rnd
	for i := cache.minChunkRequest; i <= cache.maxChunkRequest; i++ {
		_, ok := cache.chunks[i]
		if !ok {
			seqs = append(seqs, i)
		}
	}
	return
}

func (cache *TailCache) addChunk(chunk basics.AccountChunk) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	cache.chunks[chunk.Seq] = chunk
}

func (cache *TailCache) OnNewBlock(block bookkeeping.Block) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	defer func() {
		cache.rnd = block.Round()
	}()

	if cache.quit {
		return
	}

	if cache.rnd == 0 {
		return
	}

	newChunks, maxChunk, err := cache.ledger.NewChunks(cache.rnd, block.Round())
	if err != nil {
		logging.Base().Infof("TailCache: could not get new chunks: %v", err)
		cache.chunks = make(map[int]basics.AccountChunk)
		cache.maxChunkSeq = -1
		return
	}
	cache.maxChunkSeq = maxChunk

	minKeptChunk := 0
	if maxAcctTailSize < maxChunk {
		minKeptChunk = maxChunk - maxAcctTailSize
	}

	for _, oldChunk := range cache.chunks {
		if oldChunk.Seq < minKeptChunk {
			logging.Base().Infof("TailCache: dropping chunk %d: too deep: chunk seq %d < min kept chunk %d", oldChunk.Seq, oldChunk.Seq, minKeptChunk)
			continue
		}

		newChunk, err := cache.ledger.UpdateChunk(oldChunk, block.Round())
		if err != nil {
			logging.Base().Infof("TailCache: dropping chunk %d: cannot update: %v", oldChunk.Seq, err)
			continue
		}
		newChunks = append(newChunks, newChunk)
	}

	cache.chunks = make(map[int]basics.AccountChunk)
	for _, chunk := range newChunks {
		cache.chunks[chunk.Seq] = chunk
	}

	if len(cache.chunks) < minAcctTailSize {
		if minAcctTailSize < maxChunk {
			cache.minChunkRequest = maxChunk - minAcctTailSize
		} else {
			cache.minChunkRequest = 0
		}
		cache.maxChunkRequest = maxChunk - len(cache.chunks)

		logging.Base().Infof("TailCache: set request chunk bounds (rnd-%d): (%d, %d)", block.Round(), cache.minChunkRequest, cache.maxChunkRequest)

		if cache.maxChunkRequest < cache.minChunkRequest {
			return
		}

		select {
		case cache.requestChunks <- struct{}{}:
		default:
		}
	} else {
		cache.minChunkRequest = 0
		cache.maxChunkRequest = -1
		logging.Base().Infof("TailCache: clearing request chunk bounds (rnd-%d)", block.Round())
	}
}

func (cache *TailCache) Tail(latest basics.Round) basics.AccountTail {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	var tail basics.AccountTail
	if len(cache.chunks) == 0 {
		return tail
	}

	for i := cache.maxChunkSeq; i >= 0; i-- {
		chunk, ok := cache.chunks[i]
		if !ok {
			return tail
		}
		if chunk.Round != latest {
			return tail
		}
		tail.Entries = append(chunk.Slots, tail.Entries...)
	}
	return tail
}

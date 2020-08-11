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
	"database/sql"
	"fmt"
	"sort"

	"github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/vector"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// accountsDbQueries is used to cache a prepared SQL statement to look up
// the state of a single account.
type accountsDbQueries struct {
	lookupStmt           *sql.Stmt
	lookupPredStmt       *sql.Stmt
	lookupMaxAddrStmt    *sql.Stmt
	lookupAddrNextStmt   *sql.Stmt
	lookupSlotStmt       *sql.Stmt
	lookupSlotOfAddrStmt *sql.Stmt
}

var accountsSchema = []string{
	`CREATE TABLE IF NOT EXISTS acctrounds (
		id string primary key,
		rnd integer,
		residue blob)`,
	`CREATE TABLE IF NOT EXISTS accounttotals (
		id string primary key,
		online integer,
		onlinerewardunits integer,
		offline integer,
		offlinerewardunits integer,
		notparticipating integer,
		notparticipatingrewardunits integer,
		rewardslevel integer)`,
	`CREATE TABLE IF NOT EXISTS accountslots (
		position integer primary key,
		address blob, --* unique at end of db tx
		next blob,    --* unique at end of db tx
		data blob)`,
	`CREATE INDEX accountorder ON accountslots(address)`,
	`CREATE TABLE IF NOT EXISTS accountbase (
		address blob primary key,
		data blob)`,
}

type accountDelta struct {
	old basics.AccountData
	new basics.AccountData

	// these correspond to old
	ctx accountContext      // ctx.prev must be set if old is nonempty and new is empty
	pf  basics.AccountProof // if old is nonempty and new is empty (or an account is tracked only for context), this corresponds to the slot of old
}

// accountsInit fills the database using tx with initAccounts if the
// database has not been initialized yet.
//
// accountsInit returns nil if either it has initialized the database
// correctly, or if the database has already been initialized.
func accountsInit(tx *sql.Tx, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams, vparams *vector.Parameters) (err0 error) {
	for _, tableCreate := range accountsSchema {
		_, err := tx.Exec(tableCreate)
		if err != nil {
			return err
		}
	}

	_, err := tx.Exec("INSERT INTO acctrounds (id, rnd, residue) VALUES ('acctbase', 0, ?)", protocol.Encode(slotResidue{}))
	if err == nil {
		var addrs addrList
		for addr := range initAccounts {
			addrs = append(addrs, addr)
		}
		// note: tied to veccomInit
		sort.Sort(addrs) // TODO do we want this for benchmarks?

		vsize := int(vparams.VectorSize)
		residueStart := (len(addrs) / vsize) * vsize
		var residue slotResidue

		var ot basics.OverflowTracker
		var totals AccountTotals

		for i, addr := range addrs {
			next := addrs[0]
			if i+1 != len(addrs) {
				next = addrs[i+1]
			}
			data := initAccounts[addr]

			_, err = tx.Exec("INSERT INTO accountslots (position, address, next, data) VALUES (?, ?, ?, ?)",
				i, addr[:], next[:], protocol.Encode(data))
			if err != nil {
				return err
			}

			_, err = tx.Exec("INSERT INTO accountbase (address, data) VALUES (?, ?)",
				addr[:], protocol.Encode(data))
			if err != nil {
				return err
			}

			totals.addAccount(proto, data, &ot)

			if i >= residueStart {
				slot := basics.AccountSlot{Address: addr, AccountData: data, Next: next}
				residue.Positive = append(residue.Positive, slot)
			}
		}

		if ot.Overflowed {
			return fmt.Errorf("overflow computing totals")
		}

		err = accountsPutTotals(tx, totals)
		if err != nil {
			return err
		}

		_, err := tx.Exec("UPDATE acctrounds SET residue=? WHERE id='acctbase'", protocol.Encode(residue))
		if err != nil {
			return err
		}

	} else {
		serr, ok := err.(sqlite3.Error)
		// serr.Code is sqlite.ErrConstraint if the database has already been initalized;
		// in that case, ignore the error and return nil.
		if !ok || serr.Code != sqlite3.ErrConstraint {
			return err
		}
	}
	return nil
}

func accountsRound(tx *sql.Tx) (rnd basics.Round, residue slotResidue, err error) {
	var buf []byte
	err = tx.QueryRow("SELECT rnd, residue FROM acctrounds WHERE id='acctbase'").Scan(&rnd, &buf)
	if err != nil {
		return 0, slotResidue{}, err
	}

	err = protocol.Decode(buf, &residue)
	return
}

func accountsDbInit(q db.Queryable) (*accountsDbQueries, error) {
	var err error
	qs := &accountsDbQueries{}

	qs.lookupStmt, err = q.Prepare("SELECT data FROM accountbase WHERE address=?")
	if err != nil {
		return nil, err
	}

	qs.lookupPredStmt, err = q.Prepare("SELECT address, next FROM accountslots WHERE address<? ORDER BY address DESC")
	if err != nil {
		return nil, err
	}
	qs.lookupMaxAddrStmt, err = q.Prepare("SELECT max(address) FROM accountslots")
	if err != nil {
		return nil, err
	}
	qs.lookupAddrNextStmt, err = q.Prepare("SELECT next FROM accountslots WHERE address=?")
	if err != nil {
		return nil, err
	}

	qs.lookupSlotStmt, err = q.Prepare("SELECT address, next, data FROM accountslots WHERE position=?")
	if err != nil {
		return nil, err
	}

	qs.lookupSlotOfAddrStmt, err = q.Prepare("SELECT position, next, data FROM accountslots WHERE address=?")
	if err != nil {
		return nil, err
	}

	return qs, nil
}

func (qs *accountsDbQueries) lookup(addr basics.Address) (data basics.AccountData, err error) {
	err = db.Retry(func() error {
		var buf []byte
		err := qs.lookupStmt.QueryRow(addr[:]).Scan(&buf)
		if err == nil {
			return protocol.Decode(buf, &data)
		}

		if err == sql.ErrNoRows {
			// Return the zero value of data
			return nil
		}

		return err
	})

	return
}

func (qs *accountsDbQueries) lookupSlot(position int) (slot basics.AccountSlot, err error) {
	err = db.Retry(func() error {
		var buf []byte
		var abuf []byte
		var nbuf []byte
		err := qs.lookupSlotStmt.QueryRow(position).Scan(&abuf, &nbuf, &buf)
		if err == nil {
			copy(slot.Address[:], abuf)
			copy(slot.Next[:], nbuf)
			return protocol.Decode(buf, &slot.AccountData)
		}
		return err
	})

	if err != nil {
		if err == sql.ErrNoRows {
			// Return the zero value of slot
			err = nil
		}
		return basics.AccountSlot{}, err
	}
	return
}

func (qs *accountsDbQueries) lookupSlotOfAddr(addr basics.Address) (slot basics.AccountSlot, position int, err error) {
	slot.Address = addr
	err = db.Retry(func() error {
		var buf []byte
		var nbuf []byte
		err := qs.lookupSlotOfAddrStmt.QueryRow(addr[:]).Scan(&position, &nbuf, &buf)
		if err == nil {
			copy(slot.Next[:], nbuf)
			return protocol.Decode(buf, &slot.AccountData)
		}
		return err
	})

	if err != nil {
		if err == sql.ErrNoRows {
			// Return the zero value of slot
			err = nil
		}
		return basics.AccountSlot{}, 0, err
	}
	return
}

func (qs *accountsDbQueries) lookupPred(addr basics.Address) (pred basics.Address, err error) {
	err = db.Retry(func() error {
		rows, err := qs.lookupPredStmt.Query(addr[:])
		if err != nil {
			return err
		}

		defer rows.Close()
		for rows.Next() {
			var slot basics.AccountSlot
			var abuf []byte
			var nbuf []byte

			err := rows.Scan(&abuf, &nbuf)
			if err != nil {
				return err
			}

			copy(slot.Address[:], abuf)
			copy(slot.Next[:], nbuf)
			if slot.Surrounds(addr) || slot.Next == addr {
				pred = slot.Address
				return nil
			}
		}

		var mslot basics.AccountSlot
		maxrow := qs.lookupMaxAddrStmt.QueryRow()
		var mbuf []byte
		err = maxrow.Scan(&mbuf)
		if err != nil {
			return err
		}
		copy(mslot.Address[:], mbuf)
		nextrow := qs.lookupAddrNextStmt.QueryRow(mslot.Address[:])
		err = nextrow.Scan(&mbuf)
		if err != nil {
			return err
		}
		copy(mslot.Next[:], mbuf)
		if mslot.Surrounds(addr) || mslot.Next == addr {
			pred = mslot.Address
			return nil
		}

		return nil // pred is 0, so now panic
	})
	if err == nil && (pred == basics.Address{}) {
		panic("could not find pred!")
	}

	return
}

func accountsAll(tx *sql.Tx) (bals map[basics.Address]basics.AccountData, err error) {
	rows, err := tx.Query("SELECT address, data FROM accountbase")
	if err != nil {
		return
	}
	defer rows.Close()

	bals = make(map[basics.Address]basics.AccountData)
	for rows.Next() {
		var addrbuf []byte
		var buf []byte
		err = rows.Scan(&addrbuf, &buf)
		if err != nil {
			return
		}

		var data basics.AccountData
		err = protocol.Decode(buf, &data)
		if err != nil {
			return
		}

		var addr basics.Address
		if len(addrbuf) != len(addr) {
			err = fmt.Errorf("Account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
			return
		}

		copy(addr[:], addrbuf)
		bals[addr] = data
	}

	err = rows.Err()
	return
}

func accountsTotals(tx *sql.Tx) (totals AccountTotals, err error) {
	row := tx.QueryRow("SELECT online, onlinerewardunits, offline, offlinerewardunits, notparticipating, notparticipatingrewardunits, rewardslevel FROM accounttotals")
	err = row.Scan(&totals.Online.Money.Raw, &totals.Online.RewardUnits,
		&totals.Offline.Money.Raw, &totals.Offline.RewardUnits,
		&totals.NotParticipating.Money.Raw, &totals.NotParticipating.RewardUnits,
		&totals.RewardsLevel)

	return
}

func accountsPutTotals(tx *sql.Tx, totals AccountTotals) error {
	// The "id" field is there so that we can use a convenient REPLACE INTO statement
	_, err := tx.Exec("REPLACE INTO accounttotals (id, online, onlinerewardunits, offline, offlinerewardunits, notparticipating, notparticipatingrewardunits, rewardslevel) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		"",
		totals.Online.Money.Raw, totals.Online.RewardUnits,
		totals.Offline.Money.Raw, totals.Offline.RewardUnits,
		totals.NotParticipating.Money.Raw, totals.NotParticipating.RewardUnits,
		totals.RewardsLevel)
	return err
}

func accountsNewRound(tx *sql.Tx, rnd basics.Round, updates map[basics.Address]accountDelta, slotupdates slotDelta, rewardsLevel uint64, residue slotResidue, proto config.ConsensusParams) error {
	var base basics.Round
	err := tx.QueryRow("SELECT rnd FROM acctrounds WHERE id='acctbase'").Scan(&base)
	if err != nil {
		return err
	}

	if rnd != base+1 {
		return fmt.Errorf("newRound %d is not immediately after base %d", rnd, base)
	}

	var ot basics.OverflowTracker
	totals, err := accountsTotals(tx)
	if err != nil {
		return err
	}

	totals.applyRewards(rewardsLevel, &ot)

	deleteStmt, err := tx.Prepare("DELETE FROM accountbase WHERE address=?")
	if err != nil {
		return err
	}
	defer deleteStmt.Close()

	deleteStmt1, err := tx.Prepare("DELETE FROM accountslots WHERE position=?")
	if err != nil {
		return err
	}
	defer deleteStmt1.Close()

	replaceStmt, err := tx.Prepare("REPLACE INTO accountbase (address, data) VALUES (?, ?)")
	if err != nil {
		return err
	}
	defer replaceStmt.Close()

	replaceStmt1, err := tx.Prepare("REPLACE INTO accountslots (position, address, next, data) VALUES (?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer replaceStmt1.Close()

	for addr, data := range updates {
		if (data.new == basics.AccountData{}) {
			// prune empty accounts
			_, err = deleteStmt.Exec(addr[:])
		} else {
			_, err = replaceStmt.Exec(addr[:], protocol.Encode(data.new))
		}

		if err != nil {
			return err
		}

		totals.delAccount(proto, data.old, &ot)
		totals.addAccount(proto, data.new, &ot)
	}

	for index, newslot := range slotupdates.new {
		if (newslot == basics.AccountSlot{}) {
			// prune empty accounts
			_, err = deleteStmt1.Exec(index)
		} else {
			_, err = replaceStmt1.Exec(index, newslot.Address[:], newslot.Next[:], protocol.Encode(newslot.AccountData))
		}

		if err != nil {
			return err
		}
	}

	if ot.Overflowed {
		return fmt.Errorf("overflow computing totals")
	}

	res, err := tx.Exec("UPDATE acctrounds SET (rnd,residue) = (?,?) WHERE id='acctbase'", rnd, protocol.Encode(residue))
	if err != nil {
		return err
	}

	aff, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if aff != 1 {
		return fmt.Errorf("accountsNewRound: expected to update 1 row but got %d", aff)
	}

	err = accountsPutTotals(tx, totals)
	if err != nil {
		return err
	}

	return nil
}

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
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/vector"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/util/db"
)

// veccomDbQueries is used to cache a prepared SQL statement to look up
// the state of a single vector commitment.
type veccomDbQueries struct {
	lookupStmt *sql.Stmt
}

var veccomSchema = []string{
	`CREATE TABLE IF NOT EXISTS veccomrounds (
		id string primary key,
                rnd integer,
		nextfree integer)`,
	`CREATE TABLE IF NOT EXISTS veccombase (
		seq integer primary key,
		com blob)`,
}

type veccomDelta struct {
	old vector.Commitment
	new vector.Commitment
}

// used to assign AccountSlot.Next
// satisfies sort.Interface
type addrList []basics.Address

func (l addrList) Len() int {
	return len(l)
}

func (l addrList) Less(i, j int) bool {
	return l[i].Less(l[j])
}

func (l addrList) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

// veccomInit fills the database using tx with initVeccom if the
// database has not been initialized yet.
//
// veccomInit returns nil if either it has initialized the database
// correctly, or if the database has already been initialized.
func veccomInit(tx *sql.Tx, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams, vparams *vector.Parameters) error {
	for _, tableCreate := range veccomSchema {
		_, err := tx.Exec(tableCreate)
		if err != nil {
			return err
		}
	}

	_, err := tx.Exec("INSERT INTO veccomrounds (id, rnd, nextfree) VALUES ('veccombase', 0, ?)", len(initAccounts))
	if err == nil {
		var addrs []basics.Address
		for addr := range initAccounts {
			addrs = append(addrs, addr)
		}
		// note: tied to accountsInit
		sort.Sort(addrList(addrs)) // TODO do we want this for benchmarks?

		// TODO also sort addrs by online stake for commitment order

		for i := 0; i < len(addrs); i += int(proto.AccountVectorSize) {
			comdata := make([]crypto.Digest, proto.AccountVectorSize)
			for j := i; j < i+int(proto.AccountVectorSize) && j < len(addrs); j++ {
				addr := addrs[j]
				data := initAccounts[addr]
				next := addrs[0]
				if j+1 != len(addrs) {
					next = addrs[j+1]
				}
				comdata[j-i] = slotDigest(basics.AccountSlot{Address: addr, AccountData: data, Next: next})
			}

			precom := vector.Commit(vparams, comdata)
			com := precom.ToBytes()
			_, err = tx.Exec("INSERT INTO veccombase (seq, com) VALUES (?, ?)",
				i/int(proto.AccountVectorSize), com[:])
			if err != nil {
				return err
			}
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

func veccomDbInit(q db.Queryable) (*veccomDbQueries, error) {
	var err error
	qs := &veccomDbQueries{}

	qs.lookupStmt, err = q.Prepare("SELECT com FROM veccombase WHERE seq=?")
	if err != nil {
		return nil, err
	}

	return qs, nil
}

func veccomRound(tx *sql.Tx) (rnd basics.Round, err error) {
	err = tx.QueryRow("SELECT rnd FROM veccomrounds WHERE id='veccombase'").Scan(&rnd)
	return
}

func veccomNextFree(tx *sql.Tx) (n int, err error) {
	err = tx.QueryRow("SELECT nextfree FROM veccomrounds WHERE id='veccombase'").Scan(&n)
	return
}

func (qs *veccomDbQueries) lookup(index int) (com vector.Commitment, err error) {
	err = db.Retry(func() error {
		var buf []byte
		err := qs.lookupStmt.QueryRow(index).Scan(&buf)
		if err == nil {
			if len(buf) != 48 {
				err = fmt.Errorf("len(buf) != 48: %d != %d", len(buf), 48)
				return err
			}
			var combytes [48]byte
			copy(combytes[:], buf)
			com = vector.CommitmentFromBytes(combytes)
			return nil
		}

		// TODO confirm that the absence of a vc is erroneous
		// if err == sql.ErrNoRows {
		// 	// Return the zero value of com
		// 	return nil
		// }

		return err
	})

	return
}

func veccomNewRound(tx *sql.Tx, rnd basics.Round, nextSlot int, updates map[int]veccomDelta, proto config.ConsensusParams) error {
	var base basics.Round
	err := tx.QueryRow("SELECT rnd FROM veccomrounds WHERE id='veccombase'").Scan(&base)
	if err != nil {
		return err
	}

	if rnd != base+1 {
		return fmt.Errorf("newRound %d is not immediately after base %d", rnd, base)
	}

	deleteStmt, err := tx.Prepare("DELETE FROM veccombase WHERE seq=?")
	if err != nil {
		return err
	}
	defer deleteStmt.Close()

	replaceStmt, err := tx.Prepare("REPLACE INTO veccombase (seq, com) VALUES (?, ?)")
	if err != nil {
		return err
	}
	defer replaceStmt.Close()

	for index, data := range updates {
		if (data.new == vector.Commitment{}) {
			// prune empty commitments
			_, err = deleteStmt.Exec(index)
		} else {
			com := data.new.ToBytes()
			_, err = replaceStmt.Exec(index, com[:])
		}
		if err != nil {
			return err
		}
	}

	res, err := tx.Exec("UPDATE veccomrounds SET rnd=?, nextfree=? WHERE id='veccombase'", rnd, nextSlot)
	if err != nil {
		return err
	}

	aff, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if aff != 1 {
		return fmt.Errorf("veccomNewRound: expected to update 1 row but got %d", aff)
	}

	return nil
}

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

	"github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// acctProofDbQueries is used to cache a prepared SQL statement to look up
// the state of a single vector commitment.
type acctProofDbQueries struct {
	lookupStmt *sql.Stmt
}

var acctProofSchema = []string{
	`CREATE TABLE IF NOT EXISTS acctproofs (
		address blob,
                rnd integer,
		proof blob,
		primary key (rnd, address))`,
	`CREATE TABLE IF NOT EXISTS proofrounds (
		id string primary key,
		rnd integer)`,
}

func acctProofsInit(tx *sql.Tx, proto config.ConsensusParams) (err0 error) {
	for _, tableCreate := range acctProofSchema {
		_, err := tx.Exec(tableCreate)
		if err != nil {
			return err
		}
	}

	_, err := tx.Exec("INSERT INTO proofrounds (id, rnd) VALUES ('proofbase', 0)")
	if err != nil {
		serr, ok := err.(sqlite3.Error)
		// serr.Code is sqlite.ErrConstraint if the database has already been initalized;
		// in that case, ignore the error and return nil.
		if !ok || serr.Code != sqlite3.ErrConstraint {
			return err
		}
	}
	return nil
}

func acctProofsRound(tx *sql.Tx) (rnd basics.Round, err error) {
	err = tx.QueryRow("SELECT rnd FROM proofrounds WHERE id='proofbase'").Scan(&rnd)
	return
}

func acctProofsAll(tx *sql.Tx) ([]basics.UnvalidatedAccountProof, error) {
	rows, err := tx.Query("SELECT proof FROM acctproofs")
	if err != nil {
		return nil, err
	}

	var proofs []basics.UnvalidatedAccountProof
	defer rows.Close()
	for rows.Next() {
		var pf basics.UnvalidatedAccountProof
		var buf []byte

		err := rows.Scan(&buf)
		if err != nil {
			return nil, err
		}

		err = protocol.Decode(buf, &pf)
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, pf)
	}
	return proofs, nil
}

func acctProofsInsert(tx *sql.Tx, pf basics.AccountProof) error {
	enc := protocol.Encode(pf.Unvalidated())
	_, err := tx.Exec("INSERT INTO acctproofs (address, rnd, proof) VALUES (?, ?, ?)", pf.Address[:], pf.Round, enc)
	if err != nil {
		serr, ok := err.(sqlite3.Error)
		// serr.Code is sqlite.ErrConstraint if a proof is already present;
		// in that case, ignore the error and return nil.
		if !ok || serr.Code != sqlite3.ErrConstraint {
			return err
		}
	}
	return nil
}

func acctProofsNewRound(tx *sql.Tx, rnd basics.Round) error {
	_, err := tx.Exec("DELETE FROM acctproofs WHERE rnd < ?", rnd)
	if err != nil {
		return err
	}

	res, err := tx.Exec("UPDATE proofrounds SET rnd=? WHERE id='proofbase'", rnd)
	if err != nil {
		return err
	}

	aff, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if aff != 1 {
		return fmt.Errorf("acctProofsNewRound: expected to update 1 row but got %d", aff)
	}

	return nil
}

func acctProofsDrop(tx *sql.Tx, addr basics.Address) error {
	_, err := tx.Exec("DELETE FROM acctproofs WHERE addr = ?", addr[:])
	return err
}

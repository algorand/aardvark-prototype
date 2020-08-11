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

package transactions

import (
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
)

// PaymentTxnFields captures the fields used by payment transactions.
type PaymentTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Receiver basics.Address    `codec:"rcv"`
	Amount   basics.MicroAlgos `codec:"amt"`

	// When CloseRemainderTo is set, it indicates that the
	// transaction is requesting that the account should be
	// closed, and all remaining funds be transferred to this
	// address.
	CloseRemainderTo basics.Address `codec:"close"`
}

func (payment PaymentTxnFields) checkSpender(header Header, spec SpecialAddresses, proto config.ConsensusParams) error {
	if header.Sender == payment.CloseRemainderTo {
		return fmt.Errorf("transaction cannot close account to its sender %v", header.Sender)
	}

	// the FeeSink account may only spend to the IncentivePool
	if header.Sender == spec.FeeSink {
		if payment.Receiver != spec.RewardsPool {
			return fmt.Errorf("cannot spend from fee sink's address %v to non incentive pool address %v", header.Sender, payment.Receiver)
		}
		if payment.CloseRemainderTo != (basics.Address{}) {
			return fmt.Errorf("cannot close fee sink %v to %v", header.Sender, payment.CloseRemainderTo)
		}
	}
	return nil
}

func (payment PaymentTxnFields) prove(header Header, firstValid basics.Round, orcl Archive) (pf TransactionProof, err error) {
	// if (payment.Receiver != basics.Address{}) {
	// 	pf.Receiver, err = orcl.LookupProof(firstValid, payment.Receiver)
	// 	if err != nil {
	// 		return TransactionProof{}, err
	// 	}
	// }

	// if (payment.CloseRemainderTo != basics.Address{}) {
	// 	pf.Close, err = orcl.LookupProof(firstValid, payment.CloseRemainderTo)
	// 	if err != nil {
	// 		return TransactionProof{}, err
	// 	}
	// 	pf.ClosePrev, err = orcl.LookupPrevProof(firstValid, header.Sender)
	// 	if err != nil {
	// 		return TransactionProof{}, err
	// 	}
	// }
	return
}

func (payment PaymentTxnFields) verify(header Header, firstValid basics.Round, vcdb VectorCommitmentDB, pf UnvalidatedTransactionProof) (okpf TransactionProof, err error) {
	// var okrcv, okcls, okprv basics.AccountProof

	// if (payment.Receiver != basics.Address{}) {
	// 	okrcv, err = verifyTransactionSlot(pf.Receiver, firstValid, vcdb)
	// 	if err != nil {
	// 		return
	// 	}
	// }

	// if (payment.CloseRemainderTo != basics.Address{}) {
	// 	if pf.ClosePrev.Next != header.Sender {
	// 		err = fmt.Errorf("pf.ClosePrev.Next != header.Sender: %v != %v", pf.ClosePrev.Next, header.Sender)
	// 		return
	// 	}
	// 	okcls, err = verifyTransactionSlot(pf.Close, firstValid, vcdb)
	// 	if err != nil {
	// 		return
	// 	}
	// 	okprv, err = verifyTransactionSlot(pf.ClosePrev, firstValid, vcdb)
	// 	if err != nil {
	// 		return
	// 	}
	// }

	// okpf.Receiver = okrcv
	// okpf.Close = okcls
	// okpf.ClosePrev = okprv
	// return
	return
}

func (payment PaymentTxnFields) unsafeDecode(header Header, vcdb VectorCommitmentDB, pf UnvalidatedTransactionProof) (okpf TransactionProof, err error) {
	// var okrcv, okcls, okprv basics.AccountProof

	// if (payment.Receiver != basics.Address{}) {
	// 	okrcv, err = unsafeDecodeTransactionSlot(pf.Receiver, vcdb)
	// 	if err != nil {
	// 		return
	// 	}
	// }

	// if (payment.CloseRemainderTo != basics.Address{}) {
	// 	if pf.ClosePrev.Next != header.Sender {
	// 		err = fmt.Errorf("pf.ClosePrev.Next != header.Sender: %v != %v", pf.ClosePrev.Next, header.Sender)
	// 		return
	// 	}
	// 	okcls, err = unsafeDecodeTransactionSlot(pf.Close, vcdb)
	// 	if err != nil {
	// 		return
	// 	}
	// 	okprv, err = unsafeDecodeTransactionSlot(pf.ClosePrev, vcdb)
	// 	if err != nil {
	// 		return
	// 	}
	// }

	// okpf.Receiver = okrcv
	// okpf.Close = okcls
	// okpf.ClosePrev = okprv
	return
}

// Apply changes the balances according to this transaction.
// The ApplyData argument should reflect the changes made by
// apply().  It may already include changes made by the caller
// (i.e., Transaction.Apply), so apply() must update it rather
// than overwriting it.  For example, Transaction.Apply() may
// have updated ad.SenderRewards, and this function should only
// add to ad.SenderRewards (if needed), but not overwrite it.
func (payment PaymentTxnFields) apply(header Header, pf TransactionProof, balances Balances, spec SpecialAddresses) error {
	// // move tx money
	// if !payment.Amount.IsZero() || payment.Receiver != (basics.Address{}) {
	// 	err := balances.Move(header.Sender, payment.Receiver, pf.Sender, pf.Receiver, payment.Amount, &ad.SenderRewards, &ad.ReceiverRewards)
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	// if payment.CloseRemainderTo != (basics.Address{}) {
	// 	rec, err := balances.Get(header.Sender, pf.Sender)
	// 	if err != nil {
	// 		return err
	// 	}

	// 	closeAmount := rec.AccountData.MicroAlgos
	// 	ad.ClosingAmount = closeAmount
	// 	err = balances.Move(header.Sender, payment.CloseRemainderTo, pf.Sender, pf.Close, closeAmount, &ad.SenderRewards, &ad.CloseRewards)
	// 	if err != nil {
	// 		return err
	// 	}

	// 	// Confirm that we have no balance left
	// 	rec, err = balances.Get(header.Sender, pf.Sender)
	// 	if !rec.AccountData.MicroAlgos.IsZero() {
	// 		return fmt.Errorf("balance %d still not zero after CloseRemainderTo", rec.AccountData.MicroAlgos.Raw)
	// 	}

	// 	// Clear out entire account record, to allow the DB to GC it
	// 	err = balances.Clear(rec.Addr, pf.Sender, pf.ClosePrev)
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	return nil
}

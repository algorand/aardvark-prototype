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

package fuzzer

import (
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
)

type simpleKeyManager []account.Participation

func (m simpleKeyManager) Keys(rnd basics.Round) []account.ParticipationData {
	var km []account.ParticipationData
	for _, acc := range m {
		if rnd >= acc.FirstValid && rnd <= acc.LastValid {
			var pf basics.AccountProof
			pf.Address = acc.Parent
			pf.Round = rnd
			km = append(km, account.ParticipationData{Participation: acc, AccountProof: pf})
		}
	}
	return km
}

func (m simpleKeyManager) HasLiveKeys(from, to basics.Round) bool {
	for _, acc := range m {
		if acc.OverlapsInterval(from, to) {
			return true
		}
	}
	return false
}

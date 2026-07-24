// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"math/big"
	"testing"

	"github.com/ThinkIbrokeIt/waychain-consensus/evm"
)

// TestGenesisSeedsFaucetReserve verifies the GasFaucet 0x27 reserve is actually
// present in genesis state with the expected 1M WAY balance. This is the exact
// state a user's way_getBalance(0x27) reads — if this fails, the faucet is
// "merged and tested" but BROKEN LIVE (the failure mode caught 2026-07-20).
func TestGenesisSeedsFaucetReserve(t *testing.T) {
	gs := InitGenesis(DefaultGenesis())

	faucetAddr := evm.PrecompileAddrHex(0x27)
	acc := gs.Chain.State.GetAccount(faucetAddr)
	if acc == nil {
		t.Fatalf("FAUCET BROKEN: account 0x27 not present in genesis state")
	}

	want, ok := new(big.Int).SetString("1000000000000000000000000", 10)
	if !ok {
		t.Fatalf("test setup error: bad want literal")
	}
	if acc.Balance == nil {
		t.Fatalf("FAUCET BROKEN: 0x27 Balance is nil (seeded but not set)")
	}
	if acc.Balance.Cmp(want) != 0 {
		t.Fatalf("FAUCET BROKEN: 0x27 reserve = %s, want %s (1M WAY wei)", acc.Balance.String(), want.String())
	}
}

// TestGenesisSeedsTreasuryReserve verifies the treasury precompile 0x03 holds
// the 10M WAY seed (not orphaned under the string key "treasury").
// Mirrors TestGenesisSeedsFaucetReserve for completeness.
func TestGenesisSeedsTreasuryReserve(t *testing.T) {
	gs := InitGenesis(DefaultGenesis())

	treasuryAddr := evm.PrecompileAddrHex(0x03)
	acc := gs.Chain.State.GetAccount(treasuryAddr)
	if acc == nil {
		t.Fatalf("TREASURY BROKEN: precompile 0x03 not present in genesis state")
	}
	want := new(big.Int).SetUint64(10_000_000)
	if acc.Balance == nil || acc.Balance.Cmp(want) != 0 {
		got := "nil"
		if acc.Balance != nil {
			got = acc.Balance.String()
		}
		t.Fatalf("TREASURY BROKEN: 0x03 = %s, want %s", got, want.String())
	}
}

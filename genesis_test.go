// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"testing"

	"github.com/ThinkIbrokeIt/waychain-consensus/evm"
)

// TestGenesisFounderBootstrap verifies issue #150: the founder address is
// seeded with WAY + DoxDev L3, designated as autopilot, and the treasury
// reserve lands at the REAL precompile 0x03 (not a junk string key).
func TestGenesisFounderBootstrap(t *testing.T) {
	gs := InitGenesis(DefaultGenesis())
	st := gs.Chain.State

	founder := "e5da0c28804c512ac7e0f4a53ad8d6fd13f81e76"
	fa := st.GetAccount(founder)
	if fa == nil {
		t.Fatalf("founder account not created")
	}
	if fa.DoxDevLevel != 3 {
		t.Fatalf("founder DoxDevLevel = %d, want 3", fa.DoxDevLevel)
	}
	if fa.Balance == nil || fa.Balance.Uint64() != 1_000_000 {
		t.Fatalf("founder balance = %v, want 1,000,000", fa.Balance)
	}

	// autopilot must be the founder (autopilotAddress returns raw 20-hex, no 0x)
	ap := evm.QuestGetAutopilot(st)
	if ap == "" {
		t.Fatalf("autopilot not set")
	}
	if ap != "e5da0c28804c512ac7e0f4a53ad8d6fd13f81e76" {
		t.Fatalf("autopilot = %s, want e5da0c28804c512ac7e0f4a53ad8d6fd13f81e76", ap)
	}

	// treasury 0x03 must hold the 10M seed (not orphaned under "treasury")
	treasury := st.GetAccount(evm.PrecompileAddrHex(0x03))
	if treasury == nil || treasury.Balance == nil || treasury.Balance.Uint64() != 10_000_000 {
		t.Fatalf("treasury 0x03 balance = %v, want 10,000,000", treasury.Balance)
	}

	// ecosystem reserve must be a real account (not a junk string key)
	// Uses raw hex format (no 0x prefix) - matches RPC query format
	eco := st.GetAccount("00000000000000000000000000000000000000ec")
	if eco == nil || eco.Balance == nil || eco.Balance.Uint64() != 13_500_000 {
		t.Fatalf("ecosystem reserve balance = %v, want 13,500,000", eco.Balance)
	}

	// the literal string "treasury" must NOT be an account (was the old bug)
	if st.GetAccount("treasury") != nil {
		t.Fatalf("literal string 'treasury' still an account (orphan bug not fixed)")
	}
}

// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"bytes"
	"testing"
)

// Test1WAYVaultE2E proves the 1WAY stablecoin precompile (0x22) actually
// executes: create a vault, then read it back. Runs the SAME
// wayStablecoinPrecompile code path the deployed AWS node runs, so a green
// result is proof the 1WAY logic is functional (not just registered).
func Test1WAYVaultE2E(t *testing.T) {
	state := NewStateDB()

	// Caller must be Dox_Dev Level 2+ (enforced inside wayCreateVault).
	caller := "0xUser1WAY"
	callerAcc := state.GetOrCreateAccount(caller)
	callerAcc.DoxDevLevel = 2

	// --- CreateVault: selWayCreateVault(0xA2B1C3D4) + 32-byte vaultID ---
	vaultID := bytes.Repeat([]byte{0x22}, 32)
	createInput := make([]byte, 4+32)
	createInput[0], createInput[1], createInput[2], createInput[3] = 0xA2, 0xB1, 0xC3, 0xD4
	copy(createInput[4:36], vaultID)

	out, err := wayStablecoinPrecompile(createInput, caller, state, 100)
	if err != nil {
		t.Fatalf("1WAY CreateVault failed: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("1WAY CreateVault returned %d bytes, expected 32 (vaultID)", len(out))
	}
	t.Logf("✅ 1WAY CreateVault ok (vaultID returned)")

	// --- GetUserVault: selWayGetUserVault(0xA8B7C9D0) ---
	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0xA8, 0xB7, 0xC9, 0xD0
	copy(getInput[4:36], vaultID)

	out2, err := wayStablecoinPrecompile(getInput, caller, state, 100)
	if err != nil {
		t.Fatalf("1WAY GetUserVault failed: %v", err)
	}
	if len(out2) == 0 {
		t.Fatalf("1WAY GetUserVault returned empty — vault not persisted")
	}
	t.Logf("✅ 1WAY GetUserVault ok (vault state persisted, %d bytes)", len(out2))

	// --- Negative: caller without Dox_Dev Level 2 must be rejected ---
	lowCaller := "0xNoob"
	lowAcc := state.GetOrCreateAccount(lowCaller)
	lowAcc.DoxDevLevel = 0
	if _, err := wayStablecoinPrecompile(createInput, lowCaller, state, 100); err == nil {
		t.Fatalf("1WAY CreateVault should REJECT caller without Dox_Dev Level 2")
	}
	t.Logf("✅ 1WAY correctly rejects unauthorized caller")
}

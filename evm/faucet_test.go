// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"math/big"
	"testing"
)

// TestGasFaucetRegistered confirms 0x27 is wired into the dispatch table and
// IsPrecompile now covers the extended range (issue #90/#92).
func TestGasFaucetRegistered(t *testing.T) {
	if !IsPrecompile(0x27) {
		t.Fatal("0x27 (GasFaucet) should be a registered precompile")
	}
	pc, ok := PrecompilesTable[0x27]
	if !ok {
		t.Fatal("0x27 missing from PrecompilesTable")
	}
	if pc.Fn == nil {
		t.Fatal("0x27 has no handler")
	}
}

// TestGasFaucetDrip seeds a faucet reserve, drips to a caller, and verifies the
// caller balance increased and the reserve decreased.
func TestGasFaucetDrip(t *testing.T) {
	state := NewStateDB()

	// Seed faucet 0x27 reserve with 1M WAY (wei).
	faucetAddr := PrecompileAddrHex(0x27)
	fa := state.GetOrCreateAccount(faucetAddr)
	fa.Balance = new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil) // 1M WAY

	caller := "00000000000000000000000000000000000000bb"
	before := new(big.Int).Set(state.GetOrCreateAccount(caller).Balance) // copy, not alias

	// drip() selector = 0x2A7AB5DA
	calldata := []byte{0x2A, 0x7A, 0xB5, 0xDA}
	out, err := faucetPrecompile(calldata, caller, state, 100)
	if err != nil {
		t.Fatalf("drip failed: %v", err)
	}
	if len(out) != 1 || out[0] != 1 {
		t.Fatalf("expected drip success byte 0x01, got %v", out)
	}

	after := state.GetOrCreateAccount(caller).Balance
	if after.Cmp(before) <= 0 {
		t.Fatalf("caller balance should increase after drip: before=%v after=%v", before, after)
	}
	seed := new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil)
	if state.GetOrCreateAccount(faucetAddr).Balance.Cmp(seed) >= 0 {
		t.Fatalf("faucet reserve should decrease after drip")
	}
}

// TestGasFaucetAdminGate verifies only treasury (0x03) or an L3 curator may
// set the drip amount.
func TestGasFaucetAdminGate(t *testing.T) {
	state := NewStateDB()

	// Non-admin caller tries setDripAmount (selector 0x94AC47F1 + 32-byte amount).
	nonAdmin := "00000000000000000000000000000000000000bb"
	bad := append([]byte{0x94, 0xAC, 0x47, 0xF1}, make([]byte, 32)...)
	if _, err := faucetPrecompile(bad, nonAdmin, state, 1); err == nil {
		t.Fatal("non-admin should be rejected from setDripAmount")
	}

	// Treasury 0x03 is admin.
	treasury := PrecompileAddrHex(0x03)
	if !isFaucetAdmin(treasury, state) {
		t.Fatal("treasury 0x03 must be faucet admin")
	}
}

// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestCommunityTaskLifecycle(t *testing.T) {
	state := NewStateDB()

	// accounts
	founder := "fff0000000000000000000000000000000000fff"
	poster := "bbb0000000000000000000000000000000000bbb"
	claimant := "ccc0000000000000000000000000000000000ccc"

	for _, a := range []string{founder, poster, claimant} {
		acc := state.GetOrCreateAccount(a)
		acc.Balance = new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18)) // 1000 WAY
	}
	// founder gets L3 so it can set autopilot
	state.GetOrCreateAccount(founder).DoxDevLevel = 3

	// set autopilot to founder via questSetAutopilot (caller must be L3)
	setAuto := append([]byte{0x76, 0x80, 0x32, 0x3F}, mustHex(founder)...)
	if _, err := taskRegistryPrecompile(setAuto, founder, state, 1); err != nil {
		t.Fatalf("questSetAutopilot failed: %v", err)
	}

	// 1) createTask (any account may create)
	taskId := padTask("ct-test-1")
	reward := new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18)) // 50 WAY
	createInput := append([]byte{0x71, 0xC2, 0xD3, 0xE4}, taskId...)
	rb := make([]byte, 32)
	reward.FillBytes(rb)
	createInput = append(createInput, rb...)
	createInput = append(createInput, 1, 0) // minLevel=1, verifyMode=0 (autopilot/objective)
	if _, err := taskRegistryPrecompile(createInput, poster, state, 1); err != nil {
		t.Fatalf("createTask failed: %v", err)
	}

	// 2) escrowTask (poster funds 50 WAY)
	escInput := append([]byte{0x82, 0xD3, 0xE4, 0xF5}, taskId...)
	escInput = append(escInput, rb...)
	posterBalBefore := state.GetAccount(poster).Balance.Uint64()
	if _, err := taskRegistryPrecompile(escInput, poster, state, 1); err != nil {
		t.Fatalf("escrowTask failed: %v", err)
	}
	posterBalAfter := state.GetAccount(poster).Balance.Uint64()
	if posterBalAfter != posterBalBefore-reward.Uint64() {
		t.Fatalf("escrow did not debit poster: before=%d after=%d reward=%d", posterBalBefore, posterBalAfter, reward.Uint64())
	}
	// escrow held under 0x23 account balance
	escBal := state.GetAccount(PrecompileAddrHex(0x23)).Balance.Uint64()
	if escBal < reward.Uint64() {
		t.Fatalf("escrow not held by 0x23: %d", escBal)
	}

	// 3) claimant taskClaim
	claimInput := append([]byte{0xA1, 0xB2, 0xC3, 0xD4}, taskId...)
	if _, err := taskRegistryPrecompile(claimInput, claimant, state, 1); err != nil {
		t.Fatalf("taskClaim failed: %v", err)
	}
	if TaskStatusOf(state, taskId, claimant) != "claimed" {
		t.Fatalf("expected claimed after taskClaim")
	}

	// 4) verifyCommunity by autopilot (objective) pays from escrow
	verInput := append([]byte{0x93, 0xE4, 0xF5, 0xA6}, taskId...)
	verInput = append(verInput, mustHex(claimant)...)
	claimBalBefore := state.GetAccount(claimant).Balance.Uint64()
	if _, err := taskRegistryPrecompile(verInput, founder, state, 1); err != nil {
		t.Fatalf("verifyCommunity failed: %v", err)
	}
	if TaskStatusOf(state, taskId, claimant) != "verified" {
		t.Fatalf("expected verified after verifyCommunity")
	}
	claimBalAfter := state.GetAccount(claimant).Balance.Uint64()
	if claimBalAfter != claimBalBefore+reward.Uint64() {
		t.Fatalf("verifyCommunity did not pay reward: before=%d after=%d reward=%d", claimBalBefore, claimBalAfter, reward.Uint64())
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

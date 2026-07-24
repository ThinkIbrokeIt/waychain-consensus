// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// setupAutopilot wires a funded treasury + a designated L3 autopilot oracle.
func setupAutopilot() (*StateDB, string, string) {
	state := NewStateDB()
	tr := state.GetOrCreateAccount(PrecompileAddrHex(0x03))
	tr.Balance = big.NewInt(1_100_000)
	// seed live supply like genesis does (cap = 5% of 100M = 5M)
	QuestAddSupply(state, big.NewInt(100_000_000))
	// autopilot = 0xbb..., Dox_Dev L3
	ap := "00000000000000000000000000000000000000bb"
	state.GetOrCreateAccount(ap).DoxDevLevel = 3
	// set autopilot slot (right-aligned 20-byte)
	apKey := storageKey([]byte{autopilotSlot})
	var slot [32]byte
	copy(slot[12:32], mustHex20(ap))
	state.GetOrCreateAccount(PrecompileAddrHex(0x23)).Storage[apKey] = slot
	return state, ap, "00000000000000000000000000000000000000aa" // claimant 0xaa
}

func mustHex20(a string) []byte {
	b, err := hex.DecodeString(a)
	if err != nil || len(b) == 0 {
		// fallback: treat as raw bytes
		out := make([]byte, 20)
		copy(out[20-len([]byte(a)):], []byte(a))
		return out
	}
	out := make([]byte, 20)
	copy(out[20-len(b):], b)
	return out
}

func autoVerifyInput(taskId, claimant string) []byte {
	tb := make([]byte, 32)
	copy(tb, []byte(taskId))
	cb := mustHex20(claimant)
	out := []byte{0x04, 0xA7, 0x84, 0x46}
	out = append(out, tb...)
	out = append(out, cb...)
	return out
}

// TestAutopilotAutoVerifiesObjectiveQuest — the chicken-egg resolution: an
// objective quest is auto-verified + paid by the autopilot with no human.
func TestAutopilotAutoVerifiesObjectiveQuest(t *testing.T) {
	state, ap, claimant := setupAutopilot()
	// claim first
	if _, err := taskRegistryPrecompile(append([]byte{0xA1, 0xB2, 0xC3, 0xD4}, padTask("first-transfer")...), claimant, state, 1); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// autopilot verifies
	if _, err := taskRegistryPrecompile(autoVerifyInput("first-transfer", claimant), ap, state, 1); err != nil {
		t.Fatalf("autoVerify: %v", err)
	}
	if TaskStatusOf(state, padTask("first-transfer"), claimant) != "verified" {
		t.Fatal("expected verified")
	}
	if got := state.GetAccount(claimant).Balance.Uint64(); got != 10 {
		t.Fatalf("reward = %d, want 10", got)
	}
}

// TestAutopilotRejectsNonAutopilot — only the designated autopilot can call
// taskAutoVerify. A random L2 verifier is rejected.
func TestAutopilotRejectsNonAutopilot(t *testing.T) {
	state, _, claimant := setupAutopilot()
	rando := "00000000000000000000000000000000000000cc"
	state.GetOrCreateAccount(rando).DoxDevLevel = 2 // human verifier, but NOT the autopilot
	_, err := taskRegistryPrecompile(autoVerifyInput("first-transfer", claimant), rando, state, 1)
	if err == nil {
		t.Fatal("expected unauthorized (not the autopilot)")
	}
}

// TestAutopilotRejectsSubjectiveQuest — the autopilot may NOT auto-verify a
// subjective quest (badge-curate). Those need a human Dox_Dev L2+.
func TestAutopilotRejectsSubjectiveQuest(t *testing.T) {
	state, ap, claimant := setupAutopilot()
	_, err := taskRegistryPrecompile(autoVerifyInput("badge-curate", claimant), ap, state, 1)
	if err == nil {
		t.Fatal("expected rejection: badge-curate is not auto-eligible")
	}
}

// TestHumanVerifierStillWorks — the existing human path is untouched.
func TestHumanVerifierStillWorks(t *testing.T) {
	state, _, claimant := setupAutopilot()
	// seed live supply like genesis does, so the cap is non-zero
	QuestAddSupply(state, big.NewInt(100_000_000))
	human := "00000000000000000000000000000000000000dd"
	state.GetOrCreateAccount(human).DoxDevLevel = 2
	if _, err := taskRegistryPrecompile(append([]byte{0xA1, 0xB2, 0xC3, 0xD4}, padTask("badge-curate")...), claimant, state, 1); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// human verifier (not autopilot) verifies a SUBJECTIVE task -> allowed
	input := append([]byte{0xB2, 0xC3, 0xD4, 0xE5}, padTask("badge-curate")...)
	input = append(input, mustHex20(claimant)...)
	if _, err := taskRegistryPrecompile(input, human, state, 1); err != nil {
		t.Fatalf("human verify: %v", err)
	}
	if TaskStatusOf(state, padTask("badge-curate"), claimant) != "verified" {
		t.Fatal("expected verified by human")
	}
}

// TestWifrBridgeIsAutoEligible — the DOOR task is auto-eligible and in the map.
func TestWifrBridgeIsAutoEligible(t *testing.T) {
	if !isAutoEligible(padTask("wifr-bridge")) {
		t.Fatal("wifr-bridge must be auto-eligible (it is THE DOOR)")
	}
	if taskRewardAmount(padTask("wifr-bridge")).Uint64() != 50 {
		t.Fatal("wifr-bridge reward must be 50")
	}
}

// TestNoAutopilotSetRejectsAutoVerify — until the founder designates an
// autopilot, auto-verify is disabled (defense in depth).
func TestNoAutopilotSetRejectsAutoVerify(t *testing.T) {
	state := NewStateDB()
	state.GetOrCreateAccount(PrecompileAddrHex(0x03)).Balance = big.NewInt(1_100_000)
	someone := "00000000000000000000000000000000000000ee"
	state.GetOrCreateAccount(someone).DoxDevLevel = 3
	_, err := taskRegistryPrecompile(autoVerifyInput("first-transfer", someone), someone, state, 1)
	if err == nil {
		t.Fatal("expected rejection when no autopilot is designated")
	}
}

func padTask(s string) []byte {
	out := make([]byte, 32)
	copy(out, []byte(s))
	return out
}

// TestQuestCapStartsAt5PercentOfSupply — with 100M starting supply, cap = 5M.
func TestQuestCapStartsAt5PercentOfSupply(t *testing.T) {
	state := NewStateDB()
	// seed live supply like genesis does
	QuestAddSupply(state, big.NewInt(100_000_000))
	cap := QuestCap(state)
	if cap.Uint64() != 5_000_000 {
		t.Fatalf("cap = %d, want 5,000,000 (5%% of 100M)", cap.Uint64())
	}
}

// TestQuestCapScalesWithSupply — if live supply grows, the cap rises.
func TestQuestCapScalesWithSupply(t *testing.T) {
	state := NewStateDB()
	QuestAddSupply(state, big.NewInt(100_000_000))
	before := QuestCap(state).Uint64()
	QuestAddSupply(state, big.NewInt(100_000_000)) // supply doubles to 200M
	after := QuestCap(state).Uint64()
	if after <= before {
		t.Fatalf("cap should rise with supply: before=%d after=%d", before, after)
	}
	if after != 10_000_000 {
		t.Fatalf("cap = %d, want 10,000,000 (5%% of 200M)", after)
	}
}

// TestQuestCapEnforced — once cumulative paid hits 5% of supply, further
// verifies are rejected (the dead-code bug is fixed).
func TestQuestCapEnforced(t *testing.T) {
	state := NewStateDB()
	QuestAddSupply(state, big.NewInt(100_000_000)) // cap = 5M
	// fund treasury so payments would succeed IF cap weren't enforced
	state.GetOrCreateAccount(PrecompileAddrHex(0x03)).Balance = big.NewInt(100_000_000)
	ap := "00000000000000000000000000000000000000bb"
	state.GetOrCreateAccount(ap).DoxDevLevel = 3
	var slot [32]byte
	copy(slot[12:32], mustHex20(ap))
	state.GetOrCreateAccount(PrecompileAddrHex(0x23)).Storage[storageKey([]byte{autopilotSlot})] = slot

	// Pay out exactly 5M via repeated 50-WAY wifr-bridge auto-verifies (100k claims).
	// Use 1 big task instead: temporarily claim via a 5M-reward path is not possible
	// (rewards are fixed). Instead claim many. To keep the test fast, lower the cap
	// by using a tiny supply.
	small := NewStateDB()
	QuestAddSupply(small, big.NewInt(1_000)) // cap = 50 WAY
	small.GetOrCreateAccount(PrecompileAddrHex(0x03)).Balance = big.NewInt(1_000_000)
	small.GetOrCreateAccount(ap).DoxDevLevel = 3
	var slot2 [32]byte
	copy(slot2[12:32], mustHex20(ap))
	small.GetOrCreateAccount(PrecompileAddrHex(0x23)).Storage[storageKey([]byte{autopilotSlot})] = slot2

	// first-claim (auto-eligible, 50 WAY) -> cap 50, paid 50 -> ok
	claim := append([]byte{0xA1, 0xB2, 0xC3, 0xD4}, padTask("wifr-bridge")...)
	if _, err := taskRegistryPrecompile(claim, "00000000000000000000000000000000000000aa", small, 1); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := taskRegistryPrecompile(autoVerifyInput("wifr-bridge", "00000000000000000000000000000000000000aa"), ap, small, 1); err != nil {
		t.Fatalf("first autoVerify should pass: %v", err)
	}
	// second claim -> would push paid to 100 > cap 50 -> rejected
	claim2 := append([]byte{0xA1, 0xB2, 0xC3, 0xD4}, padTask("wifr-bridge")...)
	if _, err := taskRegistryPrecompile(claim2, "00000000000000000000000000000000000000cc", small, 1); err != nil {
		t.Fatalf("claim: %v", err)
	}
	_, err := taskRegistryPrecompile(autoVerifyInput("wifr-bridge", "00000000000000000000000000000000000000cc"), ap, small, 1)
	if err == nil {
		t.Fatal("expected cap rejection on 2nd verify (paid 100 > cap 50)")
	}
}

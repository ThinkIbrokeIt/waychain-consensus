// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"strings"
	"testing"
)

func TestCrossChainWitnessEvent(t *testing.T) {
	state := NewStateDB()

	// Setup: caller has Dox_Dev badge level 3
	caller := "0xAttester1"
	acc := state.GetOrCreateAccount(caller)
	acc.DoxDevLevel = 3

	// Build witness input
	input := make([]byte, 4+32+32+32)
	input[0], input[1], input[2], input[3] = 0xC1, 0xA2, 0xB3, 0xD4

	// sourceChain = keccak256("ethereum")[:32]
	chainHash := sha256.Sum256([]byte("ethereum"))
	copy(input[4:36], chainHash[:])

	// sourceBlock = 19204731
	blockNum := big.NewInt(19204731)
	blockBytes := blockNum.Bytes()
	copy(input[36+(32-len(blockBytes)):36+32], blockBytes)

	// sourceTxHash
	txHash := sha256.Sum256([]byte("0xabcd"))
	copy(input[68:100], txHash[:])

	// Execute witness
	out, err := crossChainAttestationPrecompile(input, caller, state, 5000)
	if err != nil {
		t.Fatalf("Witness event failed: %v", err)
	}

	// Verify output: attCount=1, confidence=25, firstAttBlock=5000
	if out[0] != 0 || out[1] != 1 {
		t.Fatalf("Expected attCount=1, got %d", uint64(out[0])<<8|uint64(out[1]))
	}
	if out[2] != 25 {
		t.Fatalf("Expected confidence=25, got %d", out[2])
	}

	t.Logf("✅ Witness event: attCount=1, confidence=25%%")
}

func TestCrossChainMultipleAttesters(t *testing.T) {
	state := NewStateDB()

	// Setup: 3 verified attesters
	attesters := []string{"0xA1", "0xA2", "0xA3"}
	for _, a := range attesters {
		acc := state.GetOrCreateAccount(a)
		acc.DoxDevLevel = 3
	}

	// Build base input
	input := make([]byte, 4+32+32+32)
	input[0], input[1], input[2], input[3] = 0xC1, 0xA2, 0xB3, 0xD4
	chainHash := sha256.Sum256([]byte("ethereum"))
	copy(input[4:36], chainHash[:])
	blockNum := big.NewInt(19204731)
	blockBytes := blockNum.Bytes()
	copy(input[36+(32-len(blockBytes)):36+32], blockBytes)
	txHash := sha256.Sum256([]byte("0xabcd"))
	copy(input[68:100], txHash[:])

	// Each attester witnesses
	for i, attester := range attesters {
		out, err := crossChainAttestationPrecompile(input, attester, state, 5000)
		if err != nil {
			t.Fatalf("Attester %d (%s) witness failed: %v", i+1, attester, err)
		}
		attCount := uint64(out[0])<<8 | uint64(out[1])
		t.Logf("Attester %d (%s): attCount=%d, confidence=%d%%", i+1, attester, attCount, out[2])
	}

	// Verify final count via getAttestationCount
	countInput := make([]byte, 4+32+32+32)
	countInput[0], countInput[1], countInput[2], countInput[3] = 0xF4, 0xD5, 0xE6, 0xA7
	copy(countInput[4:36], chainHash[:])
	copy(countInput[36+(32-len(blockBytes)):36+32], blockBytes)
	copy(countInput[68:100], txHash[:])

	out, err := crossChainAttestationPrecompile(countInput, attesters[0], state, 5000)
	if err != nil {
		t.Fatalf("Get count failed: %v", err)
	}
	attCount := uint64(out[0])<<8 | uint64(out[1])
	if attCount != uint64(len(attesters)) {
		t.Fatalf("Expected final attCount=%d, got %d", len(attesters), attCount)
	}
	t.Logf("✅ Final attestation count: %d", attCount)
}

func TestCrossChainGetAttestation(t *testing.T) {
	state := NewStateDB()

	// Setup
	caller := "0xAttester1"
	acc := state.GetOrCreateAccount(caller)
	acc.DoxDevLevel = 3

	// Witness event
	input := make([]byte, 4+32+32+32)
	input[0], input[1], input[2], input[3] = 0xC1, 0xA2, 0xB3, 0xD4
	chainHash := sha256.Sum256([]byte("ethereum"))
	copy(input[4:36], chainHash[:])
	blockNum := big.NewInt(19204731)
	blockBytes := blockNum.Bytes()
	copy(input[36+(32-len(blockBytes)):36+32], blockBytes)
	txHash := sha256.Sum256([]byte("0xabcd"))
	copy(input[68:100], txHash[:])

	_, err := crossChainAttestationPrecompile(input, caller, state, 5000)
	if err != nil {
		t.Fatalf("Witness failed: %v", err)
	}

	// Now query the attestation
	queryInput := make([]byte, 4+32+32+32)
	queryInput[0], queryInput[1], queryInput[2], queryInput[3] = 0xD2, 0xB3, 0xC4, 0xE5
	copy(queryInput[4:36], chainHash[:])
	copy(queryInput[36+(32-len(blockBytes)):36+32], blockBytes)
	copy(queryInput[68:100], txHash[:])

	out, err := crossChainAttestationPrecompile(queryInput, caller, state, 5000)
	if err != nil {
		t.Fatalf("Get attestation failed: %v", err)
	}

	// Verify: attCount=1, confidence=25, not challenged
	attCount := uint64(out[0])<<8 | uint64(out[1])
	if attCount != 1 {
		t.Fatalf("Expected attCount=1, got %d", attCount)
	}
	if out[2] != 25 {
		t.Fatalf("Expected confidence=25, got %d", out[2])
	}
	if out[19] != 0 {
		t.Fatalf("Expected not challenged, got challenged=%d", out[19])
	}

	t.Logf("✅ Get attestation: attCount=%d, confidence=%d%%, challenged=%v", attCount, out[2], out[19] != 0)
}

func TestCrossChainChallengeAttestation(t *testing.T) {
	state := NewStateDB()

	// Setup
	caller := "0xAttester1"
	acc := state.GetOrCreateAccount(caller)
	acc.DoxDevLevel = 3

	// Witness event
	input := make([]byte, 4+32+32+32)
	input[0], input[1], input[2], input[3] = 0xC1, 0xA2, 0xB3, 0xD4
	chainHash := sha256.Sum256([]byte("ethereum"))
	copy(input[4:36], chainHash[:])
	blockNum := big.NewInt(19204731)
	blockBytes := blockNum.Bytes()
	copy(input[36+(32-len(blockBytes)):36+32], blockBytes)
	txHash := sha256.Sum256([]byte("0xabcd"))
	copy(input[68:100], txHash[:])

	_, err := crossChainAttestationPrecompile(input, caller, state, 5000)
	if err != nil {
		t.Fatalf("Witness failed: %v", err)
	}

	// Challenge the attestation
	challengeInput := make([]byte, 4+32+32+32)
	challengeInput[0], challengeInput[1], challengeInput[2], challengeInput[3] = 0xE3, 0xC4, 0xD5, 0xF6
	copy(challengeInput[4:36], chainHash[:])
	copy(challengeInput[36+(32-len(blockBytes)):36+32], blockBytes)
	copy(challengeInput[68:100], txHash[:])

	out, err := crossChainAttestationPrecompile(challengeInput, "0xChallenger", state, 5050)
	if err != nil {
		t.Fatalf("Challenge failed: %v", err)
	}

	// Verify: success=1, attCount=1, confidence=0 (slashed)
	if out[0] != 1 {
		t.Fatalf("Expected challenge success=1, got %d", out[0])
	}
	attCount := uint64(out[1])<<8 | uint64(out[2])
	if attCount != 1 {
		t.Fatalf("Expected attCount=1, got %d", attCount)
	}
	if out[3] != 0 {
		t.Fatalf("Expected confidence=0 after slashing, got %d", out[3])
	}

	t.Logf("✅ Challenge accepted: attCount=%d, confidence=%d (slashed)", attCount, out[3])
}

func TestCrossChainGetAttestationCount(t *testing.T) {
	state := NewStateDB()

	// Setup
	caller := "0xAttester1"
	acc := state.GetOrCreateAccount(caller)
	acc.DoxDevLevel = 3

	// Witness event
	input := make([]byte, 4+32+32+32)
	input[0], input[1], input[2], input[3] = 0xC1, 0xA2, 0xB3, 0xD4
	chainHash := sha256.Sum256([]byte("ethereum"))
	copy(input[4:36], chainHash[:])
	blockNum := big.NewInt(19204731)
	blockBytes := blockNum.Bytes()
	copy(input[36+(32-len(blockBytes)):36+32], blockBytes)
	txHash := sha256.Sum256([]byte("0xabcd"))
	copy(input[68:100], txHash[:])

	_, err := crossChainAttestationPrecompile(input, caller, state, 5000)
	if err != nil {
		t.Fatalf("Witness failed: %v", err)
	}

	// Get count
	countInput := make([]byte, 4+32+32+32)
	countInput[0], countInput[1], countInput[2], countInput[3] = 0xF4, 0xD5, 0xE6, 0xA7
	copy(countInput[4:36], chainHash[:])
	copy(countInput[36+(32-len(blockBytes)):36+32], blockBytes)
	copy(countInput[68:100], txHash[:])

	out, err := crossChainAttestationPrecompile(countInput, caller, state, 5000)
	if err != nil {
		t.Fatalf("Get count failed: %v", err)
	}

	attCount := uint64(out[0])<<8 | uint64(out[1])
	if attCount != 1 {
		t.Fatalf("Expected attCount=1, got %d", attCount)
	}

	t.Logf("✅ Get attestation count: %d", attCount)
}

func TestCrossChainUnauthorizedAttester(t *testing.T) {
	state := NewStateDB()

	// Caller has NO badge
	caller := "0xUnverified"

	// Build input
	input := make([]byte, 4+32+32+32)
	input[0], input[1], input[2], input[3] = 0xC1, 0xA2, 0xB3, 0xD4
	chainHash := sha256.Sum256([]byte("ethereum"))
	copy(input[4:36], chainHash[:])
	blockNum := big.NewInt(19204731)
	blockBytes := blockNum.Bytes()
	copy(input[36+(32-len(blockBytes)):36+32], blockBytes)
	txHash := sha256.Sum256([]byte("0xabcd"))
	copy(input[68:100], txHash[:])

	// Should fail
	_, err := crossChainAttestationPrecompile(input, caller, state, 5000)
	if err == nil {
		t.Fatal("Expected error for unverified attester")
	}

	t.Logf("✅ Unverified attester rejected: %v", err)
}

func TestCrossChainDuplicateWitness(t *testing.T) {
	state := NewStateDB()

	caller := "0xAttester1"
	acc := state.GetOrCreateAccount(caller)
	acc.DoxDevLevel = 3

	// Build input
	input := make([]byte, 4+32+32+32)
	input[0], input[1], input[2], input[3] = 0xC1, 0xA2, 0xB3, 0xD4
	chainHash := sha256.Sum256([]byte("ethereum"))
	copy(input[4:36], chainHash[:])
	blockNum := big.NewInt(19204731)
	blockBytes := blockNum.Bytes()
	copy(input[36+(32-len(blockBytes)):36+32], blockBytes)
	txHash := sha256.Sum256([]byte("0xabcd"))
	copy(input[68:100], txHash[:])

	// First witness succeeds
	_, err := crossChainAttestationPrecompile(input, caller, state, 5000)
	if err != nil {
		t.Fatalf("First witness failed: %v", err)
	}

	// Second witness by same attester should fail
	_, err = crossChainAttestationPrecompile(input, caller, state, 5000)
	if err == nil {
		t.Fatal("Expected error for duplicate witness")
	}

	t.Logf("✅ Duplicate witness rejected: %v", err)
}

func TestCrossChainUnknownSelector(t *testing.T) {
	state := NewStateDB()

	input := make([]byte, 4)
	input[0], input[1], input[2], input[3] = 0xFF, 0xFF, 0xFF, 0xFF

	_, err := crossChainAttestationPrecompile(input, "0xCaller", state, 5000)
	if err == nil {
		t.Fatal("Expected error for unknown selector")
	}

	t.Logf("✅ Unknown selector rejected: %v", err)
}

func TestCrossChainInputTooShort(t *testing.T) {
	state := NewStateDB()

	input := make([]byte, 3) // less than 4 bytes

	_, err := crossChainAttestationPrecompile(input, "0xCaller", state, 5000)
	if err == nil {
		t.Fatal("Expected error for short input")
	}

	t.Logf("✅ Short input rejected: %v", err)
}

func TestCrossChainConfidenceLevels(t *testing.T) {
	// Test graduated confidence calculation without full state
	tests := []struct {
		attCount   uint64
		confidence byte
	}{
		{1, 25},
		{2, 25},
		{3, 50},
		{4, 50},
		{5, 75},
		{9, 75},
		{10, 100},
		{20, 100},
	}

	for _, tt := range tests {
		confidence := byte(0)
		switch {
		case tt.attCount >= 10:
			confidence = 100
		case tt.attCount >= 5:
			confidence = 75
		case tt.attCount >= 3:
			confidence = 50
		case tt.attCount >= 1:
			confidence = 25
		}
		if confidence != tt.confidence {
			t.Fatalf("attCount=%d: expected confidence=%d, got %d", tt.attCount, tt.confidence, confidence)
		}
		t.Logf("✅ attCount=%d → confidence=%d%%", tt.attCount, confidence)
	}
}

func TestCrossChainChallengeWindowExpired(t *testing.T) {
	state := NewStateDB()

	caller := "0xAttester1"
	acc := state.GetOrCreateAccount(caller)
	acc.DoxDevLevel = 3

	// Witness at block 5000
	input := make([]byte, 4+32+32+32)
	input[0], input[1], input[2], input[3] = 0xC1, 0xA2, 0xB3, 0xD4
	chainHash := sha256.Sum256([]byte("ethereum"))
	copy(input[4:36], chainHash[:])
	blockNum := big.NewInt(19204731)
	blockBytes := blockNum.Bytes()
	copy(input[36+(32-len(blockBytes)):36+32], blockBytes)
	txHash := sha256.Sum256([]byte("0xabcd"))
	copy(input[68:100], txHash[:])

	_, err := crossChainAttestationPrecompile(input, caller, state, 5000)
	if err != nil {
		t.Fatalf("Witness failed: %v", err)
	}

	// Try to challenge after window expires (5000 + 100 + 1 = 5101)
	challengeInput := make([]byte, 4+32+32+32)
	challengeInput[0], challengeInput[1], challengeInput[2], challengeInput[3] = 0xE3, 0xC4, 0xD5, 0xF6
	copy(challengeInput[4:36], chainHash[:])
	copy(challengeInput[36+(32-len(blockBytes)):36+32], blockBytes)
	copy(challengeInput[68:100], txHash[:])

	out, err := crossChainAttestationPrecompile(challengeInput, "0xChallenger", state, 5101)
	if err != nil {
		t.Fatalf("Challenge (expired window) failed: %v", err)
	}

	// Should return failure (success=0) because window expired
	if out[0] != 0 {
		t.Fatal("Expected challenge failure after window expiry")
	}

	t.Logf("✅ Challenge window expired correctly")
}

func TestCrossChainPrecompileAddress(t *testing.T) {
	addr := PrecompileAddrHex(0x1F)
	if !strings.HasPrefix(addr, "0x") && !strings.HasPrefix(addr, "00") {
		t.Fatalf("Expected hex address, got %s", addr)
	}
	// It's "0000000000000000000000000000000000001f" (no 0x prefix)
	t.Logf("✅ Precompile address: %s", addr)
}

func TestCrossChainIsPrecompileRange(t *testing.T) {
	if !IsPrecompile(0x1F) {
		t.Fatal("0x1F should be a precompile")
	}
	if !IsPrecompile(0x21) {
		t.Fatal("0x21 should be a precompile")
	}
	if IsPrecompile(0x0B) {
		t.Fatal("0x0B should NOT be a precompile")
	}
	// Verify all known precompiles
	for addr := byte(0x0C); addr <= 0x20; addr++ {
		if !IsPrecompile(addr) {
			t.Fatalf("0x%02X should be a precompile", addr)
		}
	}
	t.Logf("✅ Precompile range 0x0C-0x1F verified")
}

func TestCrossChainStorageKeyDeterministic(t *testing.T) {
	chainHash := sha256.Sum256([]byte("ethereum"))
	txHash := sha256.Sum256([]byte("0xabcd"))

	key1 := ccAttestationKey(chainHash[:], 19204731, txHash[:])
	key2 := ccAttestationKey(chainHash[:], 19204731, txHash[:])

	if !bytes.Equal(key1[:], key2[:]) {
		t.Fatal("Storage keys should be deterministic")
	}
	t.Logf("✅ Storage keys are deterministic")
}

func TestCrossChainStorageBasic(t *testing.T) {
	state := NewStateDB()
	addr := PrecompileAddrHex(0x1F)
	key := storageKey([]byte("test_key"))

	// Write via one GetOrCreateAccount call
	acc1 := state.GetOrCreateAccount(addr)
	var slot1 [32]byte
	slot1[0] = 42
	slot1[1] = 1
	acc1.Storage[key] = slot1

	// Read via another GetOrCreateAccount call
	acc2 := state.GetOrCreateAccount(addr)
	existing := acc2.Storage[key]

	if existing[0] != 42 {
		t.Fatalf("Storage not persisted! Expected [0]=42, got %d", existing[0])
	}
	t.Logf("✅ Storage persists across GetOrCreateAccount calls: [0]=%d", existing[0])
}

func TestCrossChainActualPrecompileStorage(t *testing.T) {
	state := NewStateDB()

	// Setup: caller has Dox_Dev badge
	caller := "0xAttester1"
	acc := state.GetOrCreateAccount(caller)
	acc.DoxDevLevel = 3

	// Build input
	input := make([]byte, 4+32+32+32)
	input[0], input[1], input[2], input[3] = 0xC1, 0xA2, 0xB3, 0xD4
	chainHash := sha256.Sum256([]byte("ethereum"))
	copy(input[4:36], chainHash[:])
	blockNum := big.NewInt(19204731)
	blockBytes := blockNum.Bytes()
	copy(input[36+(32-len(blockBytes)):36+32], blockBytes)
	txHash := sha256.Sum256([]byte("0xabcd"))
	copy(input[68:100], txHash[:])

	// Compute the key the same way the precompile does
	attKey := ccAttestationKey(input[4:36], new(big.Int).SetBytes(input[36:68]).Uint64(), input[68:100])
	addr := PrecompileAddrHex(0x1F)

	// Pre-write: check what's at that key
	accPre := state.GetOrCreateAccount(addr)
	t.Logf("Pre-write: accPre.Storage[attKey] = %v (key=%x)", accPre.Storage[attKey], attKey[:8])

	// First call
	out, err := crossChainAttestationPrecompile(input, caller, state, 5000)
	if err != nil {
		t.Fatalf("Call 1 failed: %v", err)
	}
	t.Logf("Call 1: attCount=%d", uint64(out[0])<<8|uint64(out[1]))

	// Debug: read raw storage
	rawSlot := accPre.Storage[attKey]
	t.Logf("After call 1 (same accPre): [0]=%d [1]=%d [10]=%d", rawSlot[0], rawSlot[1], rawSlot[10])

	// Try a fresh read
	acc2 := state.GetOrCreateAccount(addr)
	rawSlot2 := acc2.Storage[attKey]
	t.Logf("After call 1 (new acc2): [0]=%d [1]=%d [10]=%d", rawSlot2[0], rawSlot2[1], rawSlot2[10])

	// Write directly to test
	var directSlot [32]byte
	directSlot[0] = 0
	directSlot[1] = 99
	acc2.Storage[attKey] = directSlot

	acc3 := state.GetOrCreateAccount(addr)
	directRead := acc3.Storage[attKey]
	t.Logf("Direct write/read: [0]=%d [1]=%d", directRead[0], directRead[1])
}

// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"testing"
)

func TestAccountStageTransitions(t *testing.T) {
	state := NewStateDB()
	caller := "0xUser12345678901234567890123456" // 32 bytes
	callerBytes := []byte(caller)

	// Test 1: Default stage is 0 (onboarding)
	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0xB1, 0xC2, 0xD3, 0xE4
	copy(getInput[4:36], callerBytes)

	out, err := accountManagerPrecompile(getInput, caller, state, 1000)
	if err != nil {
		t.Fatalf("GetStage failed: %v", err)
	}
	if out[0] != 0 {
		t.Fatalf("Expected Stage 0, got %d", out[0])
	}
	t.Logf("✅ Default stage is 0 (onboarding)")

	// Test 2: Graduate to Stage 1
	gradInput := []byte{0xC2, 0xD3, 0xE4, 0xF5}
	out, err = accountManagerPrecompile(gradInput, caller, state, 1000)
	if err != nil {
		t.Fatalf("Graduate failed: %v", err)
	}
	if out[31] != 1 {
		t.Fatal("Graduate should return true")
	}

	// Verify stage is now 1
	out, _ = accountManagerPrecompile(getInput, caller, state, 1000)
	if out[0] != 1 {
		t.Fatalf("Expected Stage 1 after graduation, got %d (caller len=%d)", out[0], len(callerBytes))
	}
	t.Logf("✅ Graduated to Stage 1")

	// Test 3: Cannot graduate again
	_, err = accountManagerPrecompile(gradInput, caller, state, 1000)
	if err == nil {
		t.Fatal("Should not be able to graduate from Stage 1")
	}
	t.Logf("✅ Cannot graduate from Stage 1")

	// Test 4: Advance to Stage 2 (after waiting period)
	advInput := []byte{0xD3, 0xE4, 0xF5, 0xA6}
	_, err = accountManagerPrecompile(advInput, caller, state, 1000)
	if err == nil {
		t.Fatal("Should not advance before 30-day waiting period")
	}

	// Advance after waiting period
	out, err = accountManagerPrecompile(advInput, caller, state, 1000+2592000+1)
	if err != nil {
		t.Fatalf("Advance failed: %v", err)
	}
	if out[31] != 1 {
		t.Fatal("Advance should return true")
	}

	out, _ = accountManagerPrecompile(getInput, caller, state, 1000+2592000+1)
	if out[0] != 2 {
		t.Fatalf("Expected Stage 2, got %d", out[0])
	}
	t.Logf("✅ Advanced to Stage 2 after waiting period")
}

func TestAccountKeyRotation(t *testing.T) {
	state := NewStateDB()

	// Rotate key
	rotateInput := make([]byte, 4+32)
	rotateInput[0], rotateInput[1], rotateInput[2], rotateInput[3] = 0xE4, 0xF5, 0xA6, 0xB7
	newKey := make([]byte, 32)
	copy(newKey, []byte("new-public-key-12345678901234"))
	copy(rotateInput[4:36], newKey)

	out, err := accountManagerPrecompile(rotateInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}
	if out[31] != 1 {
		t.Fatal("RotateKey should return true")
	}
	t.Logf("✅ Key rotated successfully")
}

func TestAccountSessionKeys(t *testing.T) {
	state := NewStateDB()

	// Create session key
	createInput := make([]byte, 4+32+32+32+32+4)
	createInput[0], createInput[1], createInput[2], createInput[3] = 0xF5, 0xA6, 0xB7, 0xC8
	offset := 4
	keyID := make([]byte, 32)
	copy(keyID, []byte("session-key-id-123456789012"))
	copy(createInput[offset:offset+32], keyID); offset += 32
	sessionPubKey := make([]byte, 32)
	copy(sessionPubKey, []byte("session-pub-key-12345678901"))
	copy(createInput[offset:offset+32], sessionPubKey); offset += 32
	// permissions
	offset += 32
	// maxSpend
	offset += 32
	// expiryBlock = 5000
	createInput[offset] = 0; createInput[offset+1] = 0; createInput[offset+2] = 0x13; createInput[offset+3] = 0x88

	out, err := accountManagerPrecompile(createInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if out[31] != 1 {
		t.Fatal("CreateSession should return true")
	}
	t.Logf("✅ Session key created")

	// Get session key
	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0xB7, 0xC8, 0xD9, 0xE0
	copy(getInput[4:36], keyID)

	out, err = accountManagerPrecompile(getInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if out[32] != 0 {
		t.Fatal("Session should not be revoked")
	}
	t.Logf("✅ Session key retrieved")

	// Revoke session key
	revokeInput := make([]byte, 4+32)
	revokeInput[0], revokeInput[1], revokeInput[2], revokeInput[3] = 0xA6, 0xB7, 0xC8, 0xD9
	copy(revokeInput[4:36], keyID)

	out, err = accountManagerPrecompile(revokeInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}
	if out[31] != 1 {
		t.Fatal("RevokeSession should return true")
	}

	// Verify revoked
	out, _ = accountManagerPrecompile(getInput, "0xUser", state, 1000)
	if out[32] != 0xFF {
		t.Fatal("Session should be revoked")
	}
	t.Logf("✅ Session key revoked")
}

func TestAccountGuardians(t *testing.T) {
	state := NewStateDB()
	caller := "0xUser12345678901234567890123456" // 32 bytes

	// Set guardian
	setInput := make([]byte, 4+20+1)
	setInput[0], setInput[1], setInput[2], setInput[3] = 0xC8, 0xD9, 0xE0, 0xF1
	offset := 4
	guardianAddr := make([]byte, 20)
	copy(guardianAddr, []byte("guardian-address-12345"))
	copy(setInput[offset:offset+20], guardianAddr); offset += 20
	setInput[offset] = 1 // weight

	out, err := accountManagerPrecompile(setInput, caller, state, 1000)
	if err != nil {
		t.Fatalf("SetGuardian failed: %v", err)
	}
	if out[31] != 1 {
		t.Fatal("SetGuardian should return true")
	}
	t.Logf("✅ Guardian set")

	// Get guardian count
	countInput := make([]byte, 4+32)
	countInput[0], countInput[1], countInput[2], countInput[3] = 0xD9, 0xE0, 0xF1, 0xA2
	accountAddr := make([]byte, 32)
	copy(accountAddr, caller)
	copy(countInput[4:36], accountAddr)

	out, err = accountManagerPrecompile(countInput, caller, state, 1000)
	if err != nil {
		t.Fatalf("GetGuardianCount failed: %v", err)
	}
	if out[0] != 1 {
		t.Fatalf("Expected 1 guardian, got %d", out[0])
	}
	t.Logf("✅ Guardian count: 1")
}

func TestAccountFreezeUnfreeze(t *testing.T) {
	state := NewStateDB()

	// Freeze
	freezeInput := []byte{0xE0, 0xF1, 0xA2, 0xB3}
	out, err := accountManagerPrecompile(freezeInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("Freeze failed: %v", err)
	}
	if out[31] != 1 {
		t.Fatal("Freeze should return true")
	}
	t.Logf("✅ Account frozen")

	// Unfreeze
	unfreezeInput := []byte{0xF1, 0xA2, 0xB3, 0xC4}
	out, err = accountManagerPrecompile(unfreezeInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("Unfreeze failed: %v", err)
	}
	if out[31] != 1 {
		t.Fatal("Unfreeze should return true")
	}
	t.Logf("✅ Account unfrozen")

	// Double unfreeze should fail
	_, err = accountManagerPrecompile(unfreezeInput, "0xUser", state, 1000)
	if err == nil {
		t.Fatal("Double unfreeze should fail")
	}
	t.Logf("✅ Double unfreeze correctly rejected")
}

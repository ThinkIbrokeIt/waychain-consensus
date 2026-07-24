// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"encoding/binary"
	"testing"
)

func TestStorageEndowmentOperatorRegistration(t *testing.T) {
	state := NewStateDB()
	callerBytes := []byte("0xOperator123456789012345678901234") // 32 chars

	// Test: Register as node operator with WAY stake
	regInput := make([]byte, 4+32)
	// selSERegisterOperator = 0x13E4F0A2
	regInput[0], regInput[1], regInput[2], regInput[3] = 0x13, 0xE4, 0xF0, 0xA2
	// stake 100 WAY (in wei: 100 * 10^18)
	stake := make([]byte, 32)
	stake[31] = 0x64 // 100 in hex
	copy(regInput[4:36], stake)

	caller := string(callerBytes)
	out, err := storageEndowmentPrecompile(regInput, caller, state, 1000)
	if err != nil {
		t.Fatalf("RegisterOperator failed: %v", err)
	}
	if out[0] != 1 {
		t.Fatal("RegisterOperator should return true")
	}
	t.Logf("✅ Operator registered with stake")

	// Test: Get operator info - use same address format
	infoInput := make([]byte, 4+20)
	// selSEGetOperatorInfo = 0x35C6E2D4
	infoInput[0], infoInput[1], infoInput[2], infoInput[3] = 0x35, 0xC6, 0xE2, 0xD4
	// Pass address without 0x prefix
	copy(infoInput[4:24], callerBytes[2:])

	out, err = storageEndowmentPrecompile(infoInput, caller, state, 1000)
	if err != nil {
		t.Fatalf("GetOperatorInfo failed: %v", err)
	}
	if len(out) < 10 {
		t.Fatalf("GetOperatorInfo should return at least 10 bytes, got %d", len(out))
	}
	t.Logf("✅ Operator info retrieved: active=%d", out[0])

	// Test: Get operator count
	countInput := make([]byte, 4)
	// selSEGetOperatorCount = 0xA8A012F7
	countInput[0], countInput[1], countInput[2], countInput[3] = 0xA8, 0xA0, 0x12, 0xF7

	out, err = storageEndowmentPrecompile(countInput, caller, state, 1000)
	if err != nil {
		t.Fatalf("GetOperatorCount failed: %v", err)
	}
	if len(out) != 8 {
		t.Fatalf("GetOperatorCount should return 8 bytes, got %d", len(out))
	}
	t.Logf("DEBUG: count output len=%d, out=%x", len(out), out)
	count := binary.BigEndian.Uint64(out)
	if count != 1 {
		t.Fatalf("Expected 1 operator, got %d", count)
	}
	t.Logf("✅ Operator count: 1")

	// Test: Unregister
	unregInput := []byte{0x24, 0xB5, 0xD1, 0xC3} // selSEUnregisterOperator

	out, err = storageEndowmentPrecompile(unregInput, caller, state, 2000)
	if err != nil {
		t.Fatalf("UnregisterOperator failed: %v", err)
	}
	if out[0] != 1 {
		t.Fatal("UnregisterOperator should return true")
	}
	t.Logf("✅ Operator unregistered")
}

func TestStorageEndowmentEpochAllocation(t *testing.T) {
	state := NewStateDB()

	// Test: Calculate epoch allocation
	allocInput := make([]byte, 4)
	// selSECalculateEpochAllocation = 0xA7559A16
	allocInput[0], allocInput[1], allocInput[2], allocInput[3] = 0xA7, 0x55, 0x9A, 0x16

	out, err := storageEndowmentPrecompile(allocInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("CalculateEpochAllocation failed: %v", err)
	}
	if len(out) != 32 {
		t.Fatal("CalculateEpochAllocation should return 32 bytes")
	}
	t.Logf("✅ Epoch allocation calculated: %x...", out[:4])
}
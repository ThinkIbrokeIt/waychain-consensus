package evm

import (
	"fmt"
	"math/big"
	"testing"
)

func TestPrecompileOracleAggregator(t *testing.T) {
	state := NewStateDB()

	// Create test accounts with hex addresses matching what the precompile produces
	// fmt.Sprintf("oracle_%x", [20]byte{...}) → "oracle_61616161..."
	accBytes := func(prefix byte) []byte {
		b := make([]byte, 20)
		for i := 0; i < 20; i++ {
			b[i] = prefix
		}
		return b
	}

	acc1 := state.GetOrCreateAccount(fmt.Sprintf("oracle_%x", accBytes(0xaa)))
	acc1.DoxDevLevel = 2
	acc2 := state.GetOrCreateAccount(fmt.Sprintf("oracle_%x", accBytes(0xbb)))
	acc2.DoxDevLevel = 3
	acc3 := state.GetOrCreateAccount(fmt.Sprintf("oracle_%x", accBytes(0xcc)))
	acc3.DoxDevLevel = 1 // Level 1 — not eligible

	// Input: 3 oracle IDs (20 bytes each) + data (32 bytes)
	input := make([]byte, 92)
	copy(input[0:20], accBytes(0xaa))
	copy(input[20:40], accBytes(0xbb))
	copy(input[40:60], accBytes(0xcc))
	// data at position 60
	copy(input[60:92], []byte("test_data_32_bytes_1234567890123456"))

	result, err := oracleAggregator(input, "", state, 100)
	if err != nil {
		t.Fatalf("oracleAggregator failed: %v", err)
	}
	if len(result) < 33 {
		t.Fatalf("output too short: %d", len(result))
	}
	// 2 of 3 oracles verified = 66% confidence
	if result[0] != 66 {
		t.Fatalf("expected 66%% confidence, got %d%%", result[0])
	}
	t.Logf("✅ OracleAggregator: %d%% confidence (2/3 verified)", result[0])
}

func TestPrecompileOracleVerifier(t *testing.T) {
	accBytes := func(prefix byte) []byte {
		b := make([]byte, 20)
		for i := 0; i < 20; i++ {
			b[i] = prefix
		}
		return b
	}

	state := NewStateDB()
	acc := state.GetOrCreateAccount(fmt.Sprintf("%x", accBytes(0xaa)))
	acc.DoxDevLevel = 2

	// Input: oracle_id(20) + hash(32) + sig(32)
	input := make([]byte, 84)
	copy(input[0:20], accBytes(0xaa))

	result, err := oracleVerifier(input, "", state, 100)
	if err != nil {
		t.Fatalf("oracleVerifier failed: %v", err)
	}
	if result[0] != 1 {
		t.Fatalf("expected valid (1), got %d", result[0])
	}
	t.Logf("✅ OracleVerifier: oracle verified (Dox_Dev Level 2)")
}

func TestPrecompileStateRent(t *testing.T) {
	state := NewStateDB()

	// Input: address(20) + contract_size(8)
	input := make([]byte, 28)
	copy(input[0:20], []byte("contract_addr_12345"))
	// contract size: 10KB
	new(big.Int).SetUint64(10).FillBytes(input[20:28])

	result, err := stateRentCalc(input, "", state, 1000)
	if err != nil {
		t.Fatalf("stateRentCalc failed: %v", err)
	}
	if len(result) < 40 {
		t.Fatalf("output too short: %d", len(result))
	}
	rent := new(big.Int).SetBytes(result[0:32])
	if rent.Uint64() == 0 {
		t.Fatalf("rent should be > 0")
	}
	t.Logf("✅ StateRent: %d WAY due for 10KB contract", rent.Uint64())
}

func TestPrecompileAccountRecovery(t *testing.T) {
	accBytes := func(prefix byte) []byte {
		b := make([]byte, 20)
		for i := 0; i < 20; i++ {
			b[i] = prefix
		}
		return b
	}

	state := NewStateDB()

	// Set up guardians with Dox_Dev badges
	for i, prefix := range []byte{0xaa, 0xbb, 0xcc} {
		acc := state.GetOrCreateAccount(fmt.Sprintf("%x", accBytes(prefix)))
		acc.DoxDevLevel = uint8(i + 2)
	}

	// Input: target(20) + 3 guardian IDs (20 each) + 3 sigs (32 each)
	input := make([]byte, 156)
	copy(input[0:20], accBytes(0x11)) // target account
	copy(input[20:40], accBytes(0xaa))
	copy(input[40:60], accBytes(0xbb))
	copy(input[60:80], accBytes(0xcc))

	result, err := accountRecovery(input, "", state, 100)
	if err != nil {
		t.Fatalf("accountRecovery failed: %v", err)
	}
	if result[20] != 1 {
		t.Fatalf("expected recovery success (1), got %d", result[20])
	}
	t.Logf("✅ AccountRecovery: 3/3 guardians approved")
}

func TestPrecompileBLS(t *testing.T) {
	// Input: pubkey(48) + message(32) + sig(96)
	input := make([]byte, 176)
	// Fill with test data
	for i := 0; i < 176; i++ {
		input[i] = byte(i % 256)
	}

	state := NewStateDB()
	result, err := blsVerify(input, "", state, 100)
	if err != nil {
		t.Fatalf("blsVerify failed: %v", err)
	}
	if result[0] != 1 {
		t.Fatalf("expected valid (1), got %d", result[0])
	}
	t.Logf("✅ BLSVerify: structural validation passed")
}

func TestPrecompileInvalidInput(t *testing.T) {
	state := NewStateDB()

	_, err := oracleAggregator([]byte{0x01}, "", state, 100)
	if err == nil {
		t.Fatal("expected error for short input")
	}
	t.Logf("✅ OracleAggregator: short input correctly rejected")
}

func TestPrecompileNames(t *testing.T) {
	names := PrecompileNames()
	if len(names) == 0 {
		t.Fatal("precompile names should not be empty")
	}
	// Check all 12 are listed
	count := 0
	for addr := byte(0x0C); addr <= 0x1F; addr++ {
		if _, ok := PrecompilesTable[addr]; ok {
			count++
		}
	}
	if count != 19 {
		t.Fatalf("expected 19 precompiles, got %d", count)
	}
	t.Logf("✅ All 19 precompiles registered:\n%s", names)
}
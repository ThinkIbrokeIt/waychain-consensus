// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"bytes"
	"golang.org/x/crypto/sha3"
	"testing"
)

// TestKeccakPrecompileHash verifies the 0x21 keccak256 precompile computes a
// real keccak256 digest (Ethereum-compatible) and matches sha3.NewLegacyKeccak256.
func TestKeccakPrecompileHash(t *testing.T) {
	state := NewStateDB()
	payload := []byte("waychain-app-layer")
	input := append([]byte{0x19, 0x01, 0xA3, 0x9A}, payload...) // hash(bytes) selector

	out, err := keccak256Precompile(input, "0xCaller", state, 1)
	if err != nil {
		t.Fatalf("hash err: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("expected 32-byte digest, got %d", len(out))
	}
	k := sha3.NewLegacyKeccak256()
	k.Write(payload)
	want := k.Sum(nil)
	if !bytes.Equal(out, want) {
		t.Fatalf("keccak mismatch:\n got %x\nwant %x", out, want)
	}
}

// TestKeccakPrecompileHash4 verifies hash4 returns the first 4 bytes of the
// keccak digest (used by the app layer to derive Solidity selectors).
func TestKeccakPrecompileHash4(t *testing.T) {
	state := NewStateDB()
	payload := []byte("transfer(address,uint256)")
	input := append([]byte{0x69, 0x63, 0x20, 0x3C}, payload...) // hash4(bytes) selector

	out, err := keccak256Precompile(input, "0xCaller", state, 1)
	if err != nil {
		t.Fatalf("hash4 err: %v", err)
	}
	if len(out) != 4 {
		t.Fatalf("expected 4-byte selector, got %d", len(out))
	}
	k := sha3.NewLegacyKeccak256()
	k.Write(payload)
	want := k.Sum(nil)[:4]
	if !bytes.Equal(out, want) {
		t.Fatalf("hash4 mismatch:\n got %x\nwant %x", out, want)
	}
}

// TestKeccakPrecompileUnknownSelector ensures an unknown selector is rejected.
func TestKeccakPrecompileUnknownSelector(t *testing.T) {
	state := NewStateDB()
	_, err := keccak256Precompile([]byte{0xDE, 0xAD, 0xBE, 0xEF}, "0xCaller", state, 1)
	if err == nil {
		t.Fatal("expected error for unknown selector")
	}
}

// TestKeccakPrecompileRange ensures 0x21 remains a valid precompile address.
func TestKeccakPrecompileRange(t *testing.T) {
	if !IsPrecompile(0x21) {
		t.Fatal("0x21 should be a precompile")
	}
}

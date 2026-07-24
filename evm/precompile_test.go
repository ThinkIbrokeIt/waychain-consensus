// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"crypto/ed25519"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestPrecompileOracleAggregator(t *testing.T) {
	o1pub, o1priv, _ := ed25519.GenerateKey(rand.Reader)
	o2pub, o2priv, _ := ed25519.GenerateKey(rand.Reader)
	o3pub, o3priv, _ := ed25519.GenerateKey(rand.Reader)
	state := NewStateDB()
	for _, o := range []ed25519.PublicKey{o1pub, o2pub, o3pub} {
		a := state.GetOrCreateAccount(addrFromPubKey(o))
		a.DoxDevLevel = 2
	}
	dh := make([]byte, 32)
	copy(dh, []byte("shared-data-hash-1234567890abcdef"))

	vals := []*big.Int{big.NewInt(100), big.NewInt(200), big.NewInt(300)}
	input := []byte{3}
	for i, o := range []ed25519.PublicKey{o1pub, o2pub, o3pub} {
		vb := make([]byte, 32)
		vals[i].FillBytes(vb)
		sig := ed25519.Sign([]ed25519.PrivateKey{o1priv, o2priv, o3priv}[i], dh)
		input = append(input, o...)
		input = append(input, vb...)
		input = append(input, dh...)
		input = append(input, sig...)
	}

	result, err := oracleAggregator(input, "", state, 100)
	if err != nil {
		t.Fatalf("oracleAggregator failed: %v", err)
	}
	if result[0] != 100 {
		t.Fatalf("expected 100%% confidence, got %d%%", result[0])
	}
	med := new(big.Int).SetBytes(result[1:33])
	if med.Cmp(big.NewInt(200)) != 0 {
		t.Fatalf("expected median 200, got %s", med)
	}
	t.Logf("✅ OracleAggregator: 3/3 verified, 100%% confidence, median 200")
}

func TestPrecompileOracleVerifier(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	state := NewStateDB()
	acc := state.GetOrCreateAccount(addrFromPubKey(pub))
	acc.DoxDevLevel = 2

	dh := make([]byte, 32)
	copy(dh, []byte("attestation-hash-1234567890abcdef"))
	sig := ed25519.Sign(priv, dh)

	input := append(append(make([]byte, 0, 128), pub...), dh...)
	input = append(input, sig...)

	result, err := oracleVerifier(input, "", state, 100)
	if err != nil {
		t.Fatalf("oracleVerifier failed: %v", err)
	}
	if result[0] != 1 {
		t.Fatalf("expected valid (1), got %d", result[0])
	}
	t.Logf("✅ OracleVerifier: oracle signature verified (Dox_Dev Level 2)")
}

func TestPrecompileAccountRecovery(t *testing.T) {
	g1pub, g1priv, _ := ed25519.GenerateKey(rand.Reader)
	g2pub, g2priv, _ := ed25519.GenerateKey(rand.Reader)
	g3pub, g3priv, _ := ed25519.GenerateKey(rand.Reader)
	targetPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newOwnerPub, _, _ := ed25519.GenerateKey(rand.Reader)

	state := NewStateDB()
	for _, g := range []ed25519.PublicKey{g1pub, g2pub, g3pub} {
		a := state.GetOrCreateAccount(addrFromPubKey(g))
		a.DoxDevLevel = 3
	}

	msg := append(append(make([]byte, 0, 64), targetPub...), newOwnerPub...)
	input := append(make([]byte, 0, 32+32+3*(32+64)), targetPub...)
	input = append(input, newOwnerPub...)
	for _, g := range []struct {
		pub ed25519.PublicKey
		priv ed25519.PrivateKey
	}{{g1pub, g1priv}, {g2pub, g2priv}, {g3pub, g3priv}} {
		sig := ed25519.Sign(g.priv, msg)
		input = append(input, g.pub...)
		input = append(input, sig...)
	}

	result, err := accountRecovery(input, "", state, 100)
	if err != nil {
		t.Fatalf("accountRecovery failed: %v", err)
	}
	if result[20] != 1 {
		t.Fatalf("expected recovery success (1), got %d", result[20])
	}
	t.Logf("✅ AccountRecovery: 3/3 guardian signatures verified, account re-keyed")
}

func TestPrecompileBLS(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := make([]byte, 32)
	copy(msg, []byte("message-to-sign-1234567890abcdef"))
	sig := ed25519.Sign(priv, msg)

	input := append(append(make([]byte, 0, 128), pub...), msg...)
	input = append(input, sig...)

	result, err := blsVerify(input, "", nil, 100)
	if err != nil {
		t.Fatalf("blsVerify failed: %v", err)
	}
	if result[0] != 1 {
		t.Fatalf("expected valid (1), got %d", result[0])
	}
	t.Logf("✅ AggregateSignatureVerify: ed25519 signature verified")
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
	// Check all are listed
	count := 0
	for addr := byte(0x0C); addr <= 0x20; addr++ {
		if _, ok := PrecompilesTable[addr]; ok {
			count++
		}
	}
	if count != 21 {
		t.Fatalf("expected 21 precompiles, got %d", count)
	}
	t.Logf("✅ All 21 precompiles registered:\n%s", names)
}

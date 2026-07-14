package evm

import (
	"crypto/ed25519"
	"crypto/rand"
	"math/big"
	"testing"
)

// helper: make a StateDB with one account (addr derived from pub) at DoxDev level.
func acctWithLevel(pub ed25519.PublicKey, level uint8) *StateDB {
	s := NewStateDB()
	addr := addrFromPubKey(pub)
	acc := s.GetOrCreateAccount(addr)
	acc.DoxDevLevel = level
	return s
}

func TestOracleVerifierRealSig(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	state := acctWithLevel(pub, 2)

	dataHash := make([]byte, 32)
	copy(dataHash, []byte("attestation-hash-1234567890abcdef"))
	sig := ed25519.Sign(priv, dataHash)

	input := append(append(make([]byte, 0, 128), pub...), dataHash...)
	input = append(input, sig...)

	out, err := oracleVerifier(input, "", state, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(out) != 1 || out[0] != 1 {
		t.Fatalf("expected valid=1, got %v", out)
	}

	// Forged signature must fail.
	badSig := make([]byte, ed25519.SignatureSize)
	inputBad := append(append(make([]byte, 0, 128), pub...), dataHash...)
	inputBad = append(inputBad, badSig...)
	out2, _ := oracleVerifier(inputBad, "", state, 100)
	if len(out2) != 1 || out2[0] != 0 {
		t.Fatalf("expected forged sig to be invalid (0), got %v", out2)
	}
}

func TestAggregateSignatureVerifyReal(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := make([]byte, 32)
	copy(msg, []byte("message-to-sign-1234567890abcdef"))
	sig := ed25519.Sign(priv, msg)

	input := append(append(make([]byte, 0, 128), pub...), msg...)
	input = append(input, sig...)

	out, err := blsVerify(input, "", nil, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out[0] != 1 {
		t.Fatalf("expected valid=1, got %v", out)
	}

	// Tampered message -> invalid.
	bad := append(append(make([]byte, 0, 128), pub...), msg...)
	bad[40] ^= 0xFF // flip a byte in the message portion
	bad = append(bad, sig...)
	out2, _ := blsVerify(bad, "", nil, 100)
	if out2[0] != 0 {
		t.Fatalf("expected tampered message to be invalid, got %v", out2)
	}
}

func TestTLSVerifierRealSig(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	state := acctWithLevel(pub, 3)
	origin := make([]byte, 32)
	copy(origin, []byte("https://sec.gov/edgar-1234567890ab"))
	dataHash := make([]byte, 32)
	copy(dataHash, []byte("document-hash-1234567890abcdef"))
	msg := append(append(make([]byte, 0, 64), origin...), dataHash...)
	sig := ed25519.Sign(priv, msg)

	input := append(append(append(make([]byte, 0, 160), pub...), origin...), dataHash...)
	input = append(input, sig...)

	out, err := tlsVerifier(input, "", state, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out[0] != 1 {
		t.Fatalf("expected verified=1, got %v", out)
	}
	if string(out[1:5]) != "http" {
		t.Fatalf("expected origin echoed, got %v", out[1:33])
	}
}

func TestAccountRecoveryReal(t *testing.T) {
	// Three guardians, all Level 3, plus target + new owner.
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
	// Build input: target, newOwner, then 3 x (pub+sig)
	input := append(make([]byte, 0, 32+32+3*(32+64)), targetPub...)
	input = append(input, newOwnerPub...)
	for _, g := range []struct {
		pub ed25519.PublicKey
		priv ed25519.PrivateKey
	}{
		{g1pub, g1priv}, {g2pub, g2priv}, {g3pub, g3priv},
	} {
		sig := ed25519.Sign(g.priv, msg)
		input = append(input, g.pub...)
		input = append(input, sig...)
	}

	out, err := accountRecovery(input, "", state, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out[20] != 1 {
		t.Fatalf("expected recovered=1, got %v", out)
	}
	// Confirm target account re-keyed to new owner.
	targetAddr := addrFromPubKey(targetPub)
	acc := state.GetAccount(targetAddr)
	if acc == nil {
		t.Fatalf("target account missing")
	}
	var key [32]byte
	copy(key[:], []byte("owner-pubkey"))
	stored := acc.Storage[key]
	if string(stored[:]) != string(newOwnerPub) {
		t.Fatalf("account not re-keyed to new owner")
	}

	// Now test: only 2 valid guardians -> must fail.
	badInput := append(make([]byte, 0, 32+32+3*(32+64)), targetPub...)
	badInput = append(badInput, newOwnerPub...)
	for i, g := range []struct {
		pub ed25519.PublicKey
		priv ed25519.PrivateKey
	}{
		{g1pub, g1priv}, {g2pub, g2priv}, {g3pub, g3priv},
	} {
		sig := ed25519.Sign(g.priv, msg)
		if i == 2 {
			sig = make([]byte, ed25519.SignatureSize) // corrupt 3rd
		}
		badInput = append(badInput, g.pub...)
		badInput = append(badInput, sig...)
	}
	_, err = accountRecovery(badInput, "", state, 100)
	if err == nil {
		t.Fatalf("expected error with only 2 valid guardians")
	}
}

func TestOracleAggregatorMedian(t *testing.T) {
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

	// values 100, 200, 300 -> median 200
	vals := []*big.Int{big.NewInt(100), big.NewInt(200), big.NewInt(300)}
	input := []byte{3}
	for i, o := range []ed25519.PublicKey{o1pub, o2pub, o3pub} {
		vb := make([]byte, 32)
		vals[i].FillBytes(vb)
		msg := dh
		sig := ed25519.Sign([]ed25519.PrivateKey{o1priv, o2priv, o3priv}[i], msg)
		input = append(input, o...)
		input = append(input, vb...)
		input = append(input, msg...)
		input = append(input, sig...)
	}

	out, err := oracleAggregator(input, "", state, 100)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out[0] != 100 {
		t.Fatalf("expected confidence 100, got %d", out[0])
	}
	got := new(big.Int).SetBytes(out[1:33])
	if got.Cmp(big.NewInt(200)) != 0 {
		t.Fatalf("expected median 200, got %s", got)
	}
}

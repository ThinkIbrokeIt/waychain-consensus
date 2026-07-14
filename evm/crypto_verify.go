package evm

// crypto_verify.go — REAL cryptographic verification for WayChain precompiles.
// Replaces the earlier structural/placeholder ("demo") checks. No demo logic.
//
// Identity scheme: account/oracle/guardian identities are ed25519 keys. The
// precompile verification inputs carry the FULL 32-byte public key (64-hex)
// so the signature can be verified against the actual key. This matches the
// chain's own transaction signature verification in chain.go (ed25519).
//
// Note: the chain's canonical account address is the 20-byte (40-hex) form,
// but the 32-byte public key is required to verify a signature, so the
// precompile ABIs below take the 32-byte key directly.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
)

// verifyEd25519Sig verifies that `sig` (64 bytes) is a valid ed25519 signature
// by `pubkey32` (32 bytes) over `msg`. Returns (valid, error). A malformed
// input is an error; a bad signature is (false, nil).
func verifyEd25519Sig(pubkey32, msg, sig []byte) (bool, error) {
	if len(pubkey32) != ed25519.PublicKeySize {
		return false, fmt.Errorf("verifyEd25519Sig: pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(pubkey32))
	}
	if len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("verifyEd25519Sig: signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	pub := ed25519.PublicKey(pubkey32)
	return ed25519.Verify(pub, msg, sig), nil
}

// addrFromPubKey returns the canonical 20-byte (40-hex) address string used by
// the StateDB for a given 32-byte ed25519 public key.
func addrFromPubKey(pubkey32 []byte) string {
	return hex.EncodeToString(pubkey32)[0:40]
}

// hashToBytes is a deterministic SHA-256 over concatenated attestation data.
func hashToBytes(data ...[]byte) [32]byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// medianBig returns the median of a slice of *big.Int (sorted copy).
func medianBig(vals []*big.Int) *big.Int {
	if len(vals) == 0 {
		return big.NewInt(0)
	}
	sorted := make([]*big.Int, len(vals))
	copy(sorted, vals)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Cmp(sorted[j]) < 0 })
	return new(big.Int).Set(sorted[len(sorted)/2])
}

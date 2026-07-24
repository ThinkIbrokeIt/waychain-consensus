// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GenerateKey generates a new Ed25519 key pair for WayChain
func GenerateKey() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("keygen: %w", err)
	}
	return priv, pub, nil
}

// KeyFromSeed creates a private key from a 32-byte seed
func KeyFromSeed(seed []byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(seed)
}

// PubKeyHex returns the hex-encoded public key (address)
func PubKeyHex(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub)
}

// ParsePubKey decodes a hex public key
func ParsePubKey(hexStr string) (ed25519.PublicKey, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("parse pubkey: %w", err)
	}
	if len(data) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("parse pubkey: invalid length %d", len(data))
	}
	return ed25519.PublicKey(data), nil
}

// ParsePrivKey decodes a hex private key
func ParsePrivKey(hexStr string) (ed25519.PrivateKey, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("parse privkey: %w", err)
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("parse privkey: invalid length %d", len(data))
	}
	return ed25519.PrivateKey(data), nil
}

// SignTransaction signs a transaction and returns the signature
func SignTransaction(tx *Transaction, priv ed25519.PrivateKey) []byte {
	// Sign the tx hash (already computed)
	return ed25519.Sign(priv, tx.Hash[:])
}

// VerifyTransaction verifies a transaction's signature
func VerifyTransaction(tx *Transaction, pub ed25519.PublicKey) bool {
	return ed25519.Verify(pub, tx.Hash[:], tx.Signature)
}
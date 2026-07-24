// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/ThinkIbrokeIt/waychain-consensus/evm"
)

// TestRPCSubmitWithFund verifies transaction serialization and signature verification
func TestRPCSubmitWithFund(t *testing.T) {
	// Generate Ed25519 key
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fromAddr := hex.EncodeToString(pub)
	
	t.Logf("From address: 0x%s", fromAddr)
	
	// Build a transaction
	tx := Transaction{
		Nonce:    0,
		From:     fromAddr,
		To:       "bob",
		Value:    big.NewInt(1000),
		GasLimit: 21000,
		GasPrice: 1,
		Lane:     evm.ConsensusLane,
	}
	
	// Compute hash
	hashInput := fmt.Sprintf("%d:%s:%s:%s:%d:%d:%d:%x:%x",
		tx.Nonce, tx.From, tx.To, tx.Value.String(), tx.GasLimit, tx.Lane, len(tx.Data), tx.Data, tx.EncryptedData)
	tx.Hash = sha256.Sum256([]byte(hashInput))
	
	// Sign
	tx.Signature = ed25519.Sign(priv, tx.Hash[:])
	
	// Serialize
	ser := SerializeTxHex(&tx)
	
	// Verify serialization round-trip
	deser, err := DeserializeTxHex(ser)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	t.Logf("✅ Round-trip serialization works")
	
	// Verify signature
	pubParsed, err := ParsePubKey(deser.From)
	if err != nil {
		t.Fatalf("Parse pubkey: %v", err)
	}
	if !ed25519.Verify(pubParsed, deser.Hash[:], deser.Signature) {
		t.Fatal("Signature verification failed")
	}
	t.Logf("✅ Signature verification works")
}
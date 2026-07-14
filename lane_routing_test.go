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

// TestLaneRouting verifies transactions route to correct pool lanes
func TestLaneRouting(t *testing.T) {
	chain := NewChain()

	// Create funded account
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fromAddr := hex.EncodeToString(pub)
	acc := chain.State.GetOrCreateAccount(fromAddr)
	acc.Balance.SetUint64(1_000_000)
	acc.DoxDevLevel = 3

	// Test each lane
	lanes := []struct {
		name     string
		lane     evm.LaneType
		poolSize func() int
	}{
		{"ConsensusLane", evm.ConsensusLane, func() int { return len(chain.Pool.Consensus) }},
		{"OracleLane", evm.OracleLane, func() int { return len(chain.Pool.Oracle) }},
		{"PrivateLane", evm.PrivateLane, func() int { return len(chain.Pool.Private) }},
	}

	for _, tc := range lanes {
		t.Run(tc.name, func(t *testing.T) {
			// Build tx with specific lane
			tx := Transaction{
				Nonce:         0,
				From:          fromAddr,
				To:            "recipient",
				Value:         big.NewInt(100),
				GasLimit:      21000,
				GasPrice:      1,
				Data:          []byte{},
				Lane:          tc.lane,
				EncryptedData: []byte("encrypted-payload"),
			}

			// Compute hash and sign
			hashInput := fmt.Sprintf("%d:%s:%s:%s:%d:%d:%d:%x:%x",
				tx.Nonce, tx.From, tx.To, tx.Value.String(), tx.GasLimit, tx.Lane, len(tx.Data), tx.Data, tx.EncryptedData)
			tx.Hash = sha256.Sum256([]byte(hashInput))
			tx.Signature = ed25519.Sign(priv, tx.Hash[:])

			// Serialize and deserialize (RPC round-trip)
			serHex := SerializeTxHex(&tx)
			deser, err := DeserializeTxHex(serHex)
			if err != nil {
				t.Fatalf("deserialize: %v", err)
			}

			// Verify lane preserved
			if deser.Lane != tc.lane {
				t.Fatalf("lane not preserved: got %d, want %d", deser.Lane, tc.lane)
			}
			if string(deser.EncryptedData) != "encrypted-payload" {
				t.Fatalf("encrypted data not preserved: got %x", deser.EncryptedData)
			}

			// Submit to pool
			chain.Pool.Add(*deser)

			// Verify routed to correct lane pool
			if tc.poolSize() != 1 {
				t.Fatalf("%s: pool size = %d, want 1", tc.name, tc.poolSize())
			}

			// Verify other pools empty
			for _, other := range lanes {
				if other.name != tc.name && other.poolSize() != 0 {
					t.Fatalf("%s: leaked into %s pool (size=%d)", tc.name, other.name, other.poolSize())
				}
			}

			// Clean up for next iteration
			chain.Pool.Consensus = nil
			chain.Pool.Oracle = nil
			chain.Pool.Private = nil
		})
	}
}
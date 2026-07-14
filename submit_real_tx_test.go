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

// TestSubmitDevTx exercises the full dev tx lifecycle in-process.
func TestSubmitDevTx(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	fromAddr := hex.EncodeToString(pub)

	chain := NewChain()
	acc := chain.State.GetOrCreateAccount(fromAddr)
	acc.Balance.SetUint64(1_000_000)
	acc.DoxDevLevel = 3

	tx := Transaction{
		Nonce:    0,
		From:     fromAddr,
		To:       "bob",
		Value:    big.NewInt(5000),
		GasLimit: 21000,
		GasPrice: 1,
		Lane:     evm.ConsensusLane,
	}
	hashInput := fmt.Sprintf("%d:%s:%s:%s:%d:%d:%d:%x:%x",
		tx.Nonce, tx.From, tx.To, tx.Value.String(), tx.GasLimit, tx.Lane, len(tx.Data), tx.Data, tx.EncryptedData)
	tx.Hash = sha256.Sum256([]byte(hashInput))
	tx.Signature = ed25519.Sign(priv, tx.Hash[:])

	ser := SerializeTxHex(&tx)
	deser, err := DeserializeTxHex(ser)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if deser.Hash != tx.Hash {
		t.Fatal("hash mismatch after round-trip")
	}
	if !ed25519.Verify(pub, deser.Hash[:], deser.Signature) {
		t.Fatal("signature verify failed after round-trip")
	}

	chain.Pool.Add(*deser)
	vs := NewValidatorSet()
	vs.Add(NewValidatorID(0x01), 5000)
	proposer := vs.SelectProposer(1)
	block := chain.ProduceBlock(proposer)
	if len(block.Transactions) != 1 {
		t.Fatalf("expected 1 tx mined, got %d", len(block.Transactions))
	}

	sender := chain.State.GetAccount(fromAddr)
	if sender == nil || sender.Nonce != 1 {
		t.Fatalf("expected sender nonce 1, got %+v", sender)
	}
	if chain.State.GetAccount("bob") == nil {
		t.Fatal("bob account not created")
	}
}

func rpcCall(method string, params ...interface{}) map[string]interface{} {
	return map[string]interface{}{"error": "rpcCall disabled in suite; use in-process tests"}
}

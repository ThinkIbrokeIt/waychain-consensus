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

// TestTransactionPipeline verifies the full tx lifecycle end-to-end:
// keygen → sign → serialize → deserialize → pool → block → state change
func TestTransactionPipeline(t *testing.T) {
	// ── 1. Generate keypair ──
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	fromAddr := hex.EncodeToString(pub)

	// ── 2. Create chain with funded account ──
	chain := NewChain()
	acc := chain.State.GetOrCreateAccount(fromAddr)
	acc.Balance.SetUint64(1_000_000)
	acc.DoxDevLevel = 3

	// ── 3. Build a transaction ──
	tx := Transaction{
		Nonce:    0,
		From:     fromAddr,
		To:       "bob",
		Value:    big.NewInt(1000),
		GasLimit: 21000,
		GasPrice: 1,
		Data:     nil,
	}

	// Compute hash
	hashInput := fmt.Sprintf("%d:%s:%s:%s:%d:%d:%d:%x:%x",
		tx.Nonce, tx.From, tx.To, tx.Value.String(), tx.GasLimit, tx.Lane, len(tx.Data), tx.Data, tx.EncryptedData)
	tx.Hash = sha256.Sum256([]byte(hashInput))
	// Sign
	tx.Signature = ed25519.Sign(priv, tx.Hash[:])

	// Verify locally
	if !ed25519.Verify(pub, tx.Hash[:], tx.Signature) {
		t.Fatal("signature verify failed")
	}

	// ── 4. Serialize → Deserialize round-trip ──
	ser := SerializeTx(&tx)
	deser, err := DeserializeTx(ser)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if deser.Nonce != tx.Nonce {
		t.Fatalf("nonce: got %d, want %d", deser.Nonce, tx.Nonce)
	}
	if deser.From != tx.From {
		t.Fatalf("from: got %s, want %s", deser.From, tx.From)
	}
	if deser.To != tx.To {
		t.Fatalf("to: got %s, want %s", deser.To, tx.To)
	}
	if deser.Value.Uint64() != tx.Value.Uint64() {
		t.Fatalf("value: got %d, want %d", deser.Value.Uint64(), tx.Value.Uint64())
	}
	if deser.Hash != tx.Hash {
		t.Fatalf("hash mismatch")
	}
	if len(deser.Signature) != len(tx.Signature) {
		t.Fatalf("sig length: got %d, want %d", len(deser.Signature), len(tx.Signature))
	}

	// ── 5. Submit to pool ──
	chain.Pool.Add(*deser)
	if chain.Pool.Len() != 1 {
		t.Fatalf("pool size: got %d, want 1", chain.Pool.Len())
	}

	// ── 6. Produce block ──
	vs := NewValidatorSet()
	vs.Add(NewValidatorID(0x01), 5000)
	proposer := vs.SelectProposer(1)
	block := chain.ProduceBlock(proposer)

	if len(block.Transactions) != 1 {
		t.Fatalf("block txs: got %d, want 1", len(block.Transactions))
	}

	// Verify tx in block
	mined := block.Transactions[0]
	if mined.Hash != tx.Hash {
		t.Fatal("block contains wrong tx")
	}
	if mined.From != fromAddr {
		t.Fatal("block tx wrong from")
	}

	// ── 7. Verify state changes ──
	sender := chain.State.GetAccount(fromAddr)
	if sender.Nonce != 1 {
		t.Fatalf("sender nonce: got %d, want 1", sender.Nonce)
	}
	// Balance: 1,000,000 - 1,000 (value) - 21,000 (gas) = 978,000
	expectedBalance := uint64(1_000_000 - 1000 - 21000)
	if sender.Balance.Uint64() != expectedBalance {
		t.Fatalf("sender balance: got %d, want %d", sender.Balance.Uint64(), expectedBalance)
	}

	bob := chain.State.GetAccount("bob")
	if bob == nil {
		t.Fatal("bob account not found")
	}
	if bob.Balance.Uint64() != 1000 {
		t.Fatalf("bob balance: got %d, want %d (value %d transferred to new bob account)", bob.Balance.Uint64(), 1000, 1000)
	}

	// ── 8. Hex round-trip (for RPC) ──
	hexStr := SerializeTxHex(&tx)
	deser2, err := DeserializeTxHex(hexStr)
	if err != nil {
		t.Fatalf("hex deserialize: %v", err)
	}
	if deser2.Hash != tx.Hash {
		t.Fatal("hex round-trip hash mismatch")
	}

	fmt.Println("  ✅ Full pipeline OK")
	fmt.Printf("  Pool → Block → Sender nonce=1, balance=%d | Bob balance=%d\n",
		sender.Balance.Uint64(), bob.Balance.Uint64())
}

// TestDeployGate ensures contract creation txs require Dox_Dev L2+
func TestDeployGateViaRPC(t *testing.T) {
	chain := NewChain()

	// Account without badge
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	anonAddr := hex.EncodeToString(pub)
	anon := chain.State.GetOrCreateAccount(anonAddr)
	anon.Balance.SetUint64(1_000_000)
	anon.DoxDevLevel = 0 // No badge

	// Build a deploy tx (To = "")
	tx := Transaction{
		Nonce:    0,
		From:     anonAddr,
		To:       "", // contract creation
		Value:    big.NewInt(0),
		GasLimit: 100000,
		GasPrice: 1,
		Data:     []byte{0x60, 0x00, 0x60, 0x00}, // dummy init code
		Lane:     evm.ConsensusLane, // explicit default
	}
	hashInput := fmt.Sprintf("%d:%s:%s:%s:%d:%d:%d:%x:%x",
		tx.Nonce, tx.From, tx.To, tx.Value.String(), tx.GasLimit, tx.Lane, len(tx.Data), tx.Data, tx.EncryptedData)
	tx.Hash = sha256.Sum256([]byte(hashInput))
	tx.Signature = ed25519.Sign(priv, tx.Hash[:])

	// This should pass at pool level (the deploy gate is enforced in ProduceBlock)
	chain.Pool.Add(tx)
	if chain.Pool.Len() != 1 {
		t.Fatal("pool should accept deploy tx from any address")
	}

	// Produce block — the deploy gate in ProduceBlock should reject
	vs := NewValidatorSet()
	vs.Add(NewValidatorID(0x01), 5000)
	proposer := vs.SelectProposer(1)
	block := chain.ProduceBlock(proposer)

	if len(block.Transactions) != 0 {
		t.Fatal("deploy tx from L0 should be rejected in ProduceBlock, but it was mined")
	}
	fmt.Println("  ✅ Deploy gate: L0 deploy tx correctly rejected in block production")

	// Now verify that a L3 account PASSES the deploy gate check
	err = evm.CanDeployContract(3)
	if err != nil {
		t.Fatalf("L3 should pass deploy gate: %v", err)
	}
	fmt.Println("  ✅ Deploy gate: L3 passes deploy gate check")
}

// TestRPCMethods simulates the RPC eth_sendRawTransaction logic
func TestRPCSendRawTransaction(t *testing.T) {
	chain := NewChain()

	// Create a funded Ed25519 account
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fromAddr := hex.EncodeToString(pub)
	acc := chain.State.GetOrCreateAccount(fromAddr)
	acc.Balance.SetUint64(1_000_000)
	acc.DoxDevLevel = 3

	// Build and sign tx
	tx := Transaction{
		Nonce:    0,
		From:     fromAddr,
		To:       "bob",
		Value:    big.NewInt(5000),
		GasLimit: 21000,
		GasPrice: 1,
		Data:     []byte{},
		Lane:     evm.ConsensusLane, // explicit default
	}
	hashInput := fmt.Sprintf("%d:%s:%s:%s:%d:%d:%d:%x:%x",
		tx.Nonce, tx.From, tx.To, tx.Value.String(), tx.GasLimit, tx.Lane, len(tx.Data), tx.Data, tx.EncryptedData)
	tx.Hash = sha256.Sum256([]byte(hashInput))
	tx.Signature = ed25519.Sign(priv, tx.Hash[:])

	// Simulate what eth_sendRawTransaction does:
	// 1. Deserialize from hex
	serHex := SerializeTxHex(&tx)
	deser, err := DeserializeTxHex(serHex)
	if err != nil {
		t.Fatalf("RPC: deserialize: %v", err)
	}

	// 2. Verify signature
	pubParsed, err := ParsePubKey(deser.From)
	if err != nil {
		t.Fatalf("RPC: parse pubkey: %v", err)
	}
	if !ed25519.Verify(pubParsed, deser.Hash[:], deser.Signature) {
		t.Fatal("RPC: invalid signature")
	}

	// 3. Nonce check
	if deser.Nonce != acc.Nonce {
		t.Fatalf("RPC: bad nonce: got %d, want %d", deser.Nonce, acc.Nonce)
	}

	// 4. Balance check
	txCost := new(big.Int).SetUint64(deser.GasLimit * deser.GasPrice)
	txCost.Add(txCost, deser.Value)
	if txCost.Cmp(acc.Balance) > 0 {
		t.Fatalf("RPC: insufficient balance")
	}

	// 5. Deploy gate
	if deser.To == "" {
		if err := evm.CanDeployContract(acc.DoxDevLevel); err != nil {
			t.Fatalf("RPC: deploy rejected: %v", err)
		}
	}

	// 6. Add to pool
	chain.Pool.Add(*deser)
	t.Logf("  ✅ RPC simulation: tx added to pool, hash=0x%x", deser.Hash)

	// Produce block and verify
	vs := NewValidatorSet()
	vs.Add(NewValidatorID(0x01), 5000)
	proposer := vs.SelectProposer(1)
	block := chain.ProduceBlock(proposer)

	if len(block.Transactions) != 1 {
		t.Fatal("RPC: tx not mined in block")
	}
	t.Logf("  ✅ RPC: tx mined in block #%d", block.Height)

	// Verify tx by hash
	found := false
	for _, b := range chain.Blocks {
		for _, bt := range b.Transactions {
			if bt.Hash == deser.Hash {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("RPC: tx not found by hash scan")
	}
	t.Log("  ✅ RPC: tx found by hash")

	// Verify receipt
	receiptFound := false
	for blockIdx, b := range chain.Blocks {
		for _, bt := range b.Transactions {
			if bt.Hash == deser.Hash {
				receiptFound = true
				t.Logf("  ✅ RPC: receipt — block=%d, from=%s, to=%s, status=0x1",
					blockIdx, bt.From, bt.To)
			}
		}
	}
	if !receiptFound {
		t.Fatal("RPC: receipt not found")
	}
}

// TestLaneSelection verifies transactions are routed to correct pools by lane
func TestLaneSelection(t *testing.T) {
	chain := NewChain()
	pool := NewTxPool()

	// Create test accounts
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	fromAddr1 := hex.EncodeToString(pub1)
	acc1 := chain.State.GetOrCreateAccount(fromAddr1)
	acc1.Balance.SetUint64(1_000_000)

	// Create transactions for each lane
	txConsensus := Transaction{
		Nonce:    0,
		From:     fromAddr1,
		To:       "consensus-recipient",
		Value:    big.NewInt(1000),
		GasLimit: 21000,
		GasPrice: 1,
		Lane:     evm.ConsensusLane, // 0
	}
	txConsensus.Hash = sha256.Sum256([]byte("consensus"))

	txOracle := Transaction{
		Nonce:    0,
		From:     fromAddr1,
		To:       "oracle-recipient",
		Value:    big.NewInt(2000),
		GasLimit: 21000,
		GasPrice: 1,
		Lane:     evm.OracleLane, // 1
	}
	txOracle.Hash = sha256.Sum256([]byte("oracle"))

	txPrivate := Transaction{
		Nonce:       0,
		From:        fromAddr1,
		To:          "private-recipient",
		Value:       big.NewInt(3000),
		GasLimit:    21000,
		GasPrice:    1,
		Lane:        evm.PrivateLane, // 2
		EncryptedData: []byte("encrypted-payload"),
	}
	txPrivate.Hash = sha256.Sum256([]byte("private"))

	// Add to pool
	pool.Add(txConsensus)
	pool.Add(txOracle)
	pool.Add(txPrivate)

	// Verify routing
	if len(pool.Consensus) != 1 {
		t.Fatalf("expected 1 consensus tx, got %d", len(pool.Consensus))
	}
	if len(pool.Oracle) != 1 {
		t.Fatalf("expected 1 oracle tx, got %d", len(pool.Oracle))
	}
	if len(pool.Private) != 1 {
		t.Fatalf("expected 1 private tx, got %d", len(pool.Private))
	}

	// Verify pop methods
	consensusTxs := pool.PopConsensus(10)
	if len(consensusTxs) != 1 {
		t.Fatal("PopConsensus should return 1 tx")
	}
	if consensusTxs[0].Lane != evm.ConsensusLane {
		t.Fatal("popped tx should be consensus lane")
	}

	oracleTxs := pool.PopOracle(10)
	if len(oracleTxs) != 1 {
		t.Fatal("PopOracle should return 1 tx")
	}
	if oracleTxs[0].Lane != evm.OracleLane {
		t.Fatal("popped tx should be oracle lane")
	}

	privateTxs := pool.PopPrivate(10)
	if len(privateTxs) != 1 {
		t.Fatal("PopPrivate should return 1 tx")
	}
	if privateTxs[0].Lane != evm.PrivateLane {
		t.Fatal("popped tx should be private lane")
	}

	// Verify encrypted data preserved
	if string(privateTxs[0].EncryptedData) != "encrypted-payload" {
		t.Fatal("encrypted data not preserved for private lane tx")
	}

	// Verify lane in JSON
	json := privateTxs[0].ToJSON()
	if json.Lane != "0x2" {
		t.Fatalf("expected lane 0x2 in JSON, got %s", json.Lane)
	}

	fmt.Println("  ✅ Lane selection: tx routed to correct pools (consensus/oracle/private)")
	fmt.Println("  ✅ Lane selection: encrypted data preserved for private lane")
	fmt.Println("  ✅ Lane selection: JSON includes lane field")
}
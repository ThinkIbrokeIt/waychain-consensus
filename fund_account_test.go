package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	st "github.com/ThinkIbrokeIt/waychain-consensus/store"
)

// TestFundEd25519Account funds an Ed25519 account in the BoltDB
func TestFundEd25519Account(t *testing.T) {
	// Generate Ed25519 key
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fromAddr := hex.EncodeToString(pub)
	
	t.Logf("From: 0x%s", fromAddr)
	t.Logf("Private: %s", hex.EncodeToString([]byte(priv)))
	
	// Open the store
	homeDir, _ := os.UserHomeDir()
	dbPath := homeDir + "/.waychain/chain.db"
	
	store, err := st.Open(dbPath)
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	defer store.Close()
	
	// Load all accounts
	state, err := store.LoadAllAccounts()
	if err != nil {
		t.Fatalf("Load accounts: %v", err)
	}
	
	t.Logf("Loaded %d accounts from store", len(state.Accounts))
	
	// Fund our new Ed25519 account
	newAcc := state.GetOrCreateAccount(fromAddr)
	newAcc.Balance.SetUint64(10_000_000)
	newAcc.DoxDevLevel = 3
	
	t.Logf("Funded new account with 10,000,000 WAY, level 3")
	
	// Save back
	err = store.SaveAllAccounts(state)
	if err != nil {
		t.Fatalf("Save accounts: %v", err)
	}
	
	t.Logf("✅ Account funded and saved to BoltDB")
}
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"math/big"
	"path/filepath"
	"testing"

	"github.com/ThinkIbrokeIt/waychain-consensus/evm"
	"github.com/ThinkIbrokeIt/waychain-consensus/store"
)

// TestLiveGenesisCyclePersistsFaucet reproduces EXACTLY what the running node
// does on a fresh deploy (cli.go runNode):
//   OpenStore(fresh) -> InitGenesis -> ProduceGenesisBlock -> Sync -> [restart] -> LoadAllAccounts
// Then asserts a user's way_getBalance(0x27) would read the seeded 1M WAY.
// This is the test that was missing — "passed unit tests, broken live" gap.
func TestLiveGenesisCyclePersistsFaucet(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "chain.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store open: %v", err)
	}

	// fresh DB -> height 0 -> genesis runs
	chain := NewChain()
	chain.Store = st
	gs := InitGenesis(DefaultGenesis())
	gs.ProduceGenesisBlock()
	chain = gs.Chain
	chain.Store = st
	chain.SeedQuestSupply()
	if err := chain.Sync("genesis", 0, [32]byte{}, [32]byte{}); err != nil {
		t.Fatalf("sync: %v", err)
	}

	// Simulate node restart: reload accounts from disk (what cli.go does)
	reloaded, err := st.LoadAllAccounts()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	faucetAddr := evm.PrecompileAddrHex(0x27)
	acc := reloaded.GetAccount(faucetAddr)
	if acc == nil {
		t.Fatalf("FAUCET BROKEN LIVE: 0x27 absent after genesis+sync+reload (what a user sees: 0x0)")
	}
	want, _ := new(big.Int).SetString("1000000000000000000000000", 10)
	if acc.Balance == nil || acc.Balance.Cmp(want) != 0 {
		got := "nil"
		if acc.Balance != nil {
			got = acc.Balance.String()
		}
		t.Fatalf("FAUCET BROKEN LIVE: 0x27 = %s, want %s (1M WAY wei)", got, want.String())
	}
}

package evm

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestSeedAllGenesis(t *testing.T) {
	state := NewStateDB()

	// First run seeds everything.
	SeedAllGenesis(state)

	faucet := state.GetAccount(PrecompileAddrHex(0x27))
	if faucet == nil || faucet.Balance == nil {
		t.Fatal("faucet account/balance nil after seed")
	}
	want, _ := new(big.Int).SetString("1000000000000000000000000", 10) // 1M WAY
	if faucet.Balance.Cmp(want) != 0 {
		t.Fatalf("faucet reserve = %v, want %v", faucet.Balance, want)
	}

	founder := state.GetAccount(FounderAddress)
	if founder == nil {
		t.Fatal("founder account nil after seed")
	}
	if founder.DoxDevLevel != 3 {
		t.Fatalf("founder DoxDev level = %d, want 3", founder.DoxDevLevel)
	}
	if founder.Balance == nil || founder.Balance.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Fatalf("founder balance = %v, want 1_000_000", founder.Balance)
	}

	// Autopilot oracle slot (0x50 on TaskRegistry 0x23) set to founder.
	taskReg := state.GetAccount(PrecompileAddrHex(0x23))
	if taskReg == nil {
		t.Fatal("TaskRegistry account nil")
	}
	apSlot := taskReg.Storage[storageKey([]byte{autopilotSlot})]
	founderBytes, _ := hex.DecodeString(FounderAddress)
	if len(apSlot) < 32 || !bytes.Equal(apSlot[12:32], founderBytes) {
		t.Fatalf("autopilot slot not set to founder: %x", apSlot)
	}

	// Idempotency: a second run must NOT double-count.
	SeedAllGenesis(state)
	founder2 := state.GetAccount(FounderAddress)
	if founder2.Balance.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Fatalf("founder double-seeded = %v, want 1_000_000", founder2.Balance)
	}
	faucet2 := state.GetAccount(PrecompileAddrHex(0x27))
	if faucet2.Balance.Cmp(want) != 0 {
		t.Fatalf("faucet double-seeded = %v, want %v", faucet2.Balance, want)
	}
}

func TestSeedAllGenesisBackfillsLiveChain(t *testing.T) {
	state := NewStateDB()
	// Simulate a live chain that already has a funded treasury (older genesis)
	// but is missing the faucet reserve + founder funds.
	treasury := state.GetOrCreateAccount(PrecompileAddrHex(0x03))
	treasury.Balance, _ = new(big.Int).SetString("97900000000000000000000000", 10) // 97.9M WAY

	SeedAllGenesis(state)

	// Treasury preserved (not clobbered).
	treasury2 := state.GetAccount(PrecompileAddrHex(0x03))
	if treasury2.Balance.Cmp(treasury.Balance) != 0 {
		t.Fatalf("treasury clobbered = %v, want %v", treasury2.Balance, treasury.Balance)
	}
	// Faucet + founder backfilled.
	faucet := state.GetAccount(PrecompileAddrHex(0x27))
	if faucet.Balance == nil || faucet.Balance.Sign() == 0 {
		t.Fatal("faucet not backfilled on live chain")
	}
	founder := state.GetAccount(FounderAddress)
	if founder.Balance == nil || founder.Balance.Sign() == 0 {
		t.Fatal("founder not backfilled on live chain")
	}
}

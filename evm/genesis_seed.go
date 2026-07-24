package evm

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

// GenesisSeedAccount is a single bootstrap account seeded at genesis (and by
// the founder's first faucet drip on a live chain).
type GenesisSeedAccount struct {
	Address string
	Balance uint64
	Level   uint8
}

// GenesisBootstrapAccounts is the SINGLE source of truth for the bootstrap
// accounts seeded at genesis. DefaultGenesis() (main) mirrors this list and
// SeedAllGenesis() consumes it, so the two never drift.
var GenesisBootstrapAccounts = []GenesisSeedAccount{
	// Treasury precompile (0x03) — paying treasury for quests + gov tasks.
	{Address: PrecompileAddrHex(0x03), Balance: 10_000_000, Level: 3},
	// Ecosystem reserve — real fixed reserve address (raw hex, no 0x prefix).
	{Address: "00000000000000000000000000000000000000ec", Balance: 13_500_000, Level: 3},
	// Founder bootstrap (issue #150): gas + DoxDev L3 + autopilot oracle.
	{Address: "e5da0c28804c512ac7e0f4a53ad8d6fd13f81e76", Balance: 1_000_000, Level: 3},
}

// FounderAddress — the founder's bootstrap key. Kept here so SeedAllGenesis
// can set the autopilot oracle and the faucet can gate the seed trigger.
const FounderAddress = "e5da0c28804c512ac7e0f4a53ad8d6fd13f81e76"

// SeedAllGenesis performs the ONE-SHOT bulk genesis seeding of every
// bootstrap account + the GasFaucet reserve. It is idempotent: each target is
// only filled when currently empty, so calling it again (e.g. from the
// founder's first faucet drip on an already-running chain) is a safe no-op
// for anything already funded and only backfills what was missing.
//
// This consolidates what was previously seeded piecemeal (treasury, ecosystem,
// founder, faucet reserve added in separate commits) into a single mechanism.
func SeedAllGenesis(state *StateDB) {
	// Bootstrap accounts
	for _, a := range GenesisBootstrapAccounts {
		seedAccountIfEmpty(state, a.Address, a.Balance, a.Level)
	}
	// GasFaucet 0x27 reserve (1M WAY, wei-denominated -> big.Int)
	faucetAddr := PrecompileAddrHex(0x27)
	faucetAcc := state.GetOrCreateAccount(faucetAddr)
	if faucetAcc.Balance == nil {
		faucetAcc.Balance = new(big.Int)
	}
	if faucetAcc.Balance.Sign() == 0 {
		faucetAcc.Balance.SetString("1000000000000000000000000", 10) // 1M WAY
		fmt.Printf("  GasFaucet 0x27 seeded with 1,000,000 WAY\n")
	}
	// Founder = autopilot oracle (Dox_Dev L3) for objective quest auto-verify.
	founderBytes, err := hex.DecodeString(FounderAddress)
	if err != nil {
		fmt.Printf("  WARN: founder addr decode failed: %v\n", err)
	} else {
		apKey := storageKey([]byte{autopilotSlot})
		var apSlot [32]byte
		copy(apSlot[12:32], founderBytes[:]) // right-align 20-byte address
		state.GetOrCreateAccount(PrecompileAddrHex(0x23)).Storage[apKey] = apSlot
	}
}

// seedAccountIfEmpty sets balance + DoxDev level only if the account is
// currently unfunded (balance nil or zero). Preserves any existing funds
// (e.g. a live treasury seeded from an older genesis).
func seedAccountIfEmpty(state *StateDB, addr string, balance uint64, level uint8) {
	acc := state.GetOrCreateAccount(addr)
	if acc.Balance == nil {
		acc.Balance = new(big.Int)
	}
	if acc.Balance.Sign() == 0 {
		acc.Balance.SetUint64(balance)
		fmt.Printf("  Seeded %s: %d WAY (DoxDev L%d)\n", addr, balance, level)
	}
	if level > 0 && acc.DoxDevLevel < level {
		acc.DoxDevLevel = level
	}
}

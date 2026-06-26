package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// GenesisConfig defines the initial state of the WayChain network
type GenesisConfig struct {
	ChainID       string            `json:"chain_id"`
	GenesisTime   string            `json:"genesis_time"`
	InitialHeight uint64            `json:"initial_height"`
	Supply        uint64            `json:"supply_way"`
	Validators    []GenesisValidator `json:"validators"`
	Accounts      []GenesisAccount   `json:"accounts"`
}

type GenesisValidator struct {
	ID    string `json:"id"`
	Stake uint64 `json:"stake"`
}

type GenesisAccount struct {
	Address string `json:"address"`
	Balance uint64 `json:"balance"`
	Level   uint8  `json:"dox_level"`
}

// GenesisState holds the initialized chain state
type GenesisState struct {
	Config     GenesisConfig
	Validators *ValidatorSet
	Chain      *Chain
}

// DefaultGenesis creates the default WayChain genesis config
func DefaultGenesis() GenesisConfig {
	return GenesisConfig{
		ChainID:       "waychain-1",
		GenesisTime:   "2026-06-22T00:00:00Z",
		InitialHeight: 1,
		Supply:        100_000_000, // 100M WAY
		Validators: []GenesisValidator{
			{ID: "genesis-val-1", Stake: 10000},
			{ID: "genesis-val-2", Stake: 10000},
			{ID: "genesis-val-3", Stake: 10000},
			{ID: "genesis-val-4", Stake: 10000},
			{ID: "genesis-val-5", Stake: 10000},
		},
		Accounts: []GenesisAccount{
			{Address: "treasury", Balance: 10_000_000, Level: 3},  // 10% treasury
			{Address: "ecosystem", Balance: 13_500_000, Level: 3},  // 13.5% reserve
			// Remaining 76.5% distributed equally at genesis event
		},
	}
}

// InitGenesis creates the chain state from a genesis config
func InitGenesis(config GenesisConfig) *GenesisState {
	chain := NewChain()
	vs := NewValidatorSet()

	// ── Validators ──
	for _, v := range config.Validators {
		id := sha256Hash([]byte(v.ID))
		var vid ValidatorID
		copy(vid[:], id[:20])
		vs.Add(vid, v.Stake)
	}

	// ── Genesis accounts ──
	// ── Genesis accounts ──
	for _, acc := range config.Accounts {
		account := chain.State.GetOrCreateAccount(acc.Address)
		account.Balance.SetUint64(acc.Balance)
		account.DoxDevLevel = acc.Level
	}

	// ── Initial supply checks ──
	var totalGenesis uint64
	for _, acc := range config.Accounts {
		totalGenesis += acc.Balance
	}
	fmt.Printf("  Genesis supply: %d WAY distributed\n", totalGenesis)
	fmt.Printf("  Remaining: %d WAY (minted via staking rewards)\n", config.Supply-totalGenesis)

	return &GenesisState{
		Config:     config,
		Validators: vs,
		Chain:      chain,
	}
}

// ProduceGenesisBlock creates the first block
func (gs *GenesisState) ProduceGenesisBlock() {
	proposer := gs.Validators.SelectProposer(gs.Config.InitialHeight)
	block := gs.Chain.ProduceBlock(proposer)
	fmt.Printf("  Genesis block #%d produced by validator %s\n", block.Height, proposer.String())
}

// SaveGenesis writes the genesis config to a file
func SaveGenesis(config GenesisConfig, path string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadGenesis reads a genesis config from a file
func LoadGenesis(path string) (*GenesisConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config GenesisConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func sha256Hash(data []byte) [32]byte {
	// Simple hash function — in production use crypto/sha256
	var result [32]byte
	for i, b := range data {
		result[i%32] ^= b
	}
	return result
}

// RunGenesisDemo shows the genesis process
func RunGenesisDemo() {
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" WayChain Genesis — Initialization")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	config := DefaultGenesis()
	fmt.Println("Chain:", config.ChainID)
	fmt.Println("Supply:", config.Supply, "WAY")
	fmt.Println("Validators:", len(config.Validators))
	fmt.Println()

	gs := InitGenesis(config)
	gs.ProduceGenesisBlock()

	fmt.Println()
	fmt.Println("Genesis accounts:")
	for addr, acc := range gs.Chain.State.Accounts {
		fmt.Printf("  %s | %d WAY | Dox_Dev L%d\n", addr, acc.Balance, acc.DoxDevLevel)
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════")
}
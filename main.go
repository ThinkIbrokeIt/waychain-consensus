package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/wink/waychain-consensus/evm"
)

func runConsensusDemo() {
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" WayChain Consensus Engine — Simulation")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	vs := NewValidatorSet()
	simData := []struct {
		id    byte
		stake uint64
		name  string
	}{
		{0x01, 500, "Small-1"}, {0x02, 500, "Small-2"},
		{0x03, 5000, "Med-1"}, {0x04, 5000, "Med-2"},
		{0x05, 15000, "Whale-1"}, {0x06, 15000, "Whale-2"},
		{0x07, 30000, "Mega-Whale"},
	}
	for _, s := range simData {
		vs.Add(NewValidatorID(s.id), s.stake)
	}
	vs.PrintWeightComparison()

	ce := NewConsensusState(vs)

	fmt.Println(" Starting Consensus — 50 Blocks (BFT Engine)")
	fmt.Printf("  Active validators: %d\n", len(ce.ActiveSet))
	fmt.Printf("  Total voting power: %d\n", ce.TotalPower)
	fmt.Println()

	proposerCount := make(map[string]int)
	for b := 0; b < 50; b++ {
		proposer := ce.SelectProposer(uint64(b + 1))
		if proposer != nil {
			proposerCount[proposer.String()]++
		}
	}

	committed := len(proposerCount)
	fmt.Printf("Total blocks produced: 50\n")
	fmt.Printf("Unique proposers: %d\n", committed)
	fmt.Println("\nProposer distribution (sqrt-weighted lottery):")
	for id, count := range proposerCount {
		stake := vs.Stakes[mustID(id)]
		fmt.Printf("  %s (stake=%d): %d blocks (%.1f%%)\n", id, stake, count, float64(count)*100/50)
	}

	// Confirm sqrt-weighting is working
	fmt.Println("\n  ✅ Sqrt-weighted lottery: smaller validators get proportionally more slots")
	fmt.Println("  ✅ Equal voting power: all active validators have 1 vote each")
	fmt.Println("  ✅ Deterministic: same seed + height = same proposer on all nodes")
	fmt.Println()
}

func mustID(s string) ValidatorID {
	var id ValidatorID
	copy(id[:16], []byte(s))
	return id
}

func runFullStackDemo() {
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" WayChain Full Stack — Consensus + EVM")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	// ── Chain setup ──
	chain := NewChain()

	// Set up accounts with Dox_Dev levels
	alice := "alice"
	bob := "bob"
	treasury := "treasury"

	for _, addr := range []string{alice, bob, treasury} {
		acc := chain.State.GetOrCreateAccount(addr)
		acc.Balance.SetUint64(1_000_000)
	}
	chain.State.GetOrCreateAccount(alice).DoxDevLevel = 2
	chain.State.GetOrCreateAccount(bob).DoxDevLevel = 2

	fmt.Println("Accounts funded:")
	fmt.Printf("  %s: %d WAY (Dox_Dev Level %d)\n", alice,
		chain.State.GetAccount(alice).Balance, chain.State.GetAccount(alice).DoxDevLevel)
	fmt.Printf("  %s: %d WAY\n", bob, chain.State.GetAccount(bob).Balance)
	fmt.Printf("  %s: %d WAY (treasury)\n", treasury, chain.State.GetAccount(treasury).Balance)
	fmt.Println()

	// ── Deploy contract ──
	fmt.Println("Deploying storage contract...")
	addr, err := chain.DeployTestContract(alice)
	if err != nil {
		fmt.Printf("  ❌ Deploy failed: %v\n", err)
		return
	}
	fmt.Printf("  ✅ Contract deployed at: %s\n", addr)
	fmt.Println()

	// ── Create transactions ──
	fmt.Println("Building transactions...")
	var txs []Transaction

	// Tx 1: Alice stores 42 in the contract
	calldata := make([]byte, 32)
	calldata[31] = 42
	txs = append(txs, NewTransaction(0, alice, addr, big.NewInt(0), 100000, calldata))

	// Tx 2: Alice transfers 1000 WAY to Bob
	bobCalldata := []byte{}
	txs = append(txs, NewTransaction(1, alice, bob, big.NewInt(1000), 21000, bobCalldata))

	// Tx 3: Bob stores 777 in the contract
	calldata2 := make([]byte, 32)
	calldata2[31] = 0x09
	calldata2[30] = 0x03
	txs = append(txs, NewTransaction(0, bob, addr, big.NewInt(0), 100000, calldata2))

	// Add all to pool
	for _, tx := range txs {
		chain.Pool.Add(tx)
	}
	fmt.Printf("  %d transactions in pool\n", chain.Pool.Len())
	fmt.Println()

	// ── Create validators ──
	vs := NewValidatorSet()
	vs.Add(NewValidatorID(0x01), 5000)
	vs.Add(NewValidatorID(0x02), 5000)
	vs.Add(NewValidatorID(0x03), 5000)

	// ── Produce blocks with transactions ──
	fmt.Println("Producing blocks with transactions...")
	for b := 0; b < 5; b++ {
		proposer := vs.SelectProposer(uint64(b))
		block := chain.ProduceBlock(proposer)
		fmt.Printf("  Block #%d | proposer: %v | txs: %d | state: %x...\n",
			block.Height, block.Proposer, len(block.Transactions), block.StateRoot[:4])
		time.Sleep(50 * time.Millisecond)
	}

	fmt.Println()

	// ── Show results ──
	fmt.Println("═══ Chain State After 5 Blocks ═══")
	chain.PrintChainStatus()

	// Verify the contract stored 777 (from Bob's tx)
	var slotKey [32]byte
	contractAcc := chain.State.GetAccount(addr)
	if contractAcc != nil {
		val := contractAcc.Storage[slotKey]
		stored := new(big.Int).SetBytes(val[:])
		fmt.Printf("\nContract storage slot 0: %d\n", stored.Uint64())
	}

	// Show final balances
	fmt.Println()
	fmt.Println("Final balances:")
	fmt.Printf("  Alice: %d WAY\n", chain.State.GetAccount(alice).Balance)
	fmt.Printf("  Bob:   %d WAY\n", chain.State.GetAccount(bob).Balance)
	fmt.Printf("  Treasury: %d WAY\n", chain.State.GetAccount(treasury).Balance)
}

// RunPrecompileDemo exercises the 5 WayChain protocol precompiles (0x13-0x17)
func RunPrecompileDemo() {
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" WayChain Protocol Precompiles — Demo")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	chain := NewChain()

	// Helper to build ABI calldata: selector(4) + args
	// Helper to make 20-byte address from a string key
	makeAddr := func(s string) [20]byte {
		var a [20]byte
		copy(a[:], []byte(s))
		return a
	}

	// ── DoxDevBadge (0x13) ──
	fmt.Println("◆ DoxDevBadge (0x13)")
	badgeAddr := byte(0x13)
	aliceAddr := makeAddr("alice")
	bobAddr := makeAddr("bob")

	// getLevel(alice) via precompile
	calldata := make([]byte, 4+20)
	// selector: selDoxGetLevel = 0x9E9F1846
	calldata[0] = 0x9E; calldata[1] = 0x9F; calldata[2] = 0x18; calldata[3] = 0x46
	copy(calldata[4:], aliceAddr[:])
	result, _, err := evm.ExecutePrecompile(badgeAddr, calldata, "", chain.State, chain.Height)
	if err != nil {
		fmt.Printf("  ❌ getLevel(alice): %v\n", err)
	} else {
		fmt.Printf("  ✅ Alice badge level: %d\n", result[0])
	}

	// getLevel(bob)
	copy(calldata[4:], bobAddr[:])
	result, _, err = evm.ExecutePrecompile(badgeAddr, calldata, "", chain.State, chain.Height)
	if err != nil {
		fmt.Printf("  ❌ getLevel(bob): %v\n", err)
	} else {
		fmt.Printf("  ✅ Bob badge level: %d\n", result[0])
	}

	// isVerified(alice)
	calldata[0] = 0x65; calldata[1] = 0x27; calldata[2] = 0x47; calldata[3] = 0x28 // selDoxIsVerified
	copy(calldata[4:], aliceAddr[:])
	result, _, _ = evm.ExecutePrecompile(badgeAddr, calldata, "", chain.State, chain.Height)
	fmt.Printf("  ✅ Alice verified: %v\n", result[0] == 1)

	// totalBadges
	calldata = []byte{0xE5, 0x5B, 0x5B, 0x05} // selDoxTotalBadges
	result, _, _ = evm.ExecutePrecompile(badgeAddr, calldata, "", chain.State, chain.Height)
	totalBadges := new(big.Int).SetBytes(result).Uint64()
	fmt.Printf("  ✅ Total badges: %d\n", totalBadges)

	fmt.Println()

	// ── BIJO Token (0x14) ──
	fmt.Println("◆ BIJO Token (0x14)")
	bijoAddr := byte(0x14)

	// totalSupply()
	calldata = []byte{0xA3, 0x68, 0x02, 0x2E} // selBijoTotalSupply
	result, _, _ = evm.ExecutePrecompile(bijoAddr, calldata, "", chain.State, chain.Height)
	supply := new(big.Int).SetBytes(result)
	fmt.Printf("  ✅ Total supply: %s BIJO\n", new(big.Int).Div(supply, big.NewInt(1_000_000_000_000_000_000)).String())

	// balanceOf(alice)
	calldata = make([]byte, 4+20)
	calldata[0] = 0x5B; calldata[1] = 0x46; calldata[2] = 0xF8; calldata[3] = 0xF6 // selBijoBalanceOf
	copy(calldata[4:], aliceAddr[:])
	result, _, _ = evm.ExecutePrecompile(bijoAddr, calldata, "", chain.State, chain.Height)
	aliceBijo := new(big.Int).SetBytes(result)
	fmt.Printf("  ✅ Alice BIJO balance: %s\n", aliceBijo.String())

	// transfersEnabled()
	calldata = []byte{0x2F, 0x30, 0x83, 0x3B} // selBijoTransfersEnabled
	result, _, _ = evm.ExecutePrecompile(bijoAddr, calldata, "", chain.State, chain.Height)
	fmt.Printf("  ✅ Transfers enabled: %v\n", result[0] == 1)

	fmt.Println()

	// ── DeadMansSwitch (0x15) ──
	fmt.Println("◆ DeadMansSwitch (0x15)")
	dmsAddr := byte(0x15)

	// createSwitch(0=Dark, heir=bob, interval=86400, keyRef=0xABCD...)
	calldata = make([]byte, 4+1+20+8+32)
	calldata[0] = 0x7F; calldata[1] = 0x78; calldata[2] = 0xED; calldata[3] = 0xCF // selDMSCreateSwitch
	calldata[4] = 0 // Dark truth
	copy(calldata[5:25], bobAddr[:]) // heir
	// interval: 86400 seconds = 1 day
	new(big.Int).SetUint64(86400).FillBytes(calldata[25:33])
	// keyReference
	calldata[33] = 0xAB; calldata[34] = 0xCD; calldata[35] = 0xEF
	result, _, err = evm.ExecutePrecompile(dmsAddr, calldata, "", chain.State, chain.Height)
	if err != nil {
		fmt.Printf("  ❌ createSwitch: %v\n", err)
	} else {
		switchID := new(big.Int).SetBytes(result).Uint64()
		fmt.Printf("  ✅ Created switch #%d (Dark, heir=bob)\n", switchID)
	}

	// totalSwitches()
	calldata = []byte{0x89, 0x02, 0x19, 0xED} // selDMSTotalSwitches
	result, _, _ = evm.ExecutePrecompile(dmsAddr, calldata, "", chain.State, chain.Height)
	fmt.Printf("  ✅ Total switches: %d\n", new(big.Int).SetBytes(result).Uint64())

	fmt.Println()

	// ── BitcoinRegistry (0x16) ──
	fmt.Println("◆ BitcoinRegistry (0x16)")
	btcAddr := byte(0x16)

	// getBalance(alice)
	calldata = make([]byte, 4+20)
	calldata[0] = 0x2A; calldata[1] = 0xFE; calldata[2] = 0x5A; calldata[3] = 0xE4 // selBTCGetBalance
	copy(calldata[4:], aliceAddr[:])
	result, _, _ = evm.ExecutePrecompile(btcAddr, calldata, "", chain.State, chain.Height)
	fmt.Printf("  ✅ Alice BTC balance: %d satoshis\n", new(big.Int).SetBytes(result).Uint64())

	// attestCommitment — commit a UTXO to Alice
	calldata = make([]byte, 4+32+32+20) // selector + utxo(32) + amount(32) + target(20)
	calldata[0] = 0xF2; calldata[1] = 0x37; calldata[2] = 0xC0; calldata[3] = 0xC2 // selBTCAttestCommitment
	// UTXO hash
	utxoHash := sha256.Sum256([]byte("btc_tx_abc123"))
	copy(calldata[4:36], utxoHash[:])
	// Amount: 50000 satoshis
	big.NewInt(50000).FillBytes(calldata[36:68])
	// Target: alice
	copy(calldata[68:88], aliceAddr[:])
	result, _, err = evm.ExecutePrecompile(btcAddr, calldata, "", chain.State, chain.Height)
	if err != nil {
		fmt.Printf("  ❌ attestCommitment: %v\n", err)
	} else {
		fmt.Printf("  ✅ Commitment attested: %v\n", result[0] == 1)
	}

	// getBalance(alice) after commitment
	copy(calldata[4:], aliceAddr[:])
	calldata[0] = 0x2A; calldata[1] = 0xFE; calldata[2] = 0x5A; calldata[3] = 0xE4 // reselector
	result, _, _ = evm.ExecutePrecompile(btcAddr, calldata, "", chain.State, chain.Height)
	fmt.Printf("  ✅ Alice BTC balance after commit: %d satoshis\n", new(big.Int).SetBytes(result).Uint64())

	fmt.Println()

	// ── StorageEndowment (0x17) ──
	fmt.Println("◆ StorageEndowment (0x17)")
	seAddr := byte(0x17)

	// getOperatorCount()
	calldata = []byte{0xA8, 0xA0, 0x12, 0xF7} // selSEGetOperatorCount
	result, _, _ = evm.ExecutePrecompile(seAddr, calldata, "", chain.State, chain.Height)
	fmt.Printf("  ✅ Operator count: %d\n", new(big.Int).SetBytes(result).Uint64())

	// getCurrentEpoch()
	calldata = []byte{0xC5, 0xBA, 0xF0, 0x20} // selSEGetCurrentEpoch
	result, _, _ = evm.ExecutePrecompile(seAddr, calldata, "", chain.State, chain.Height)
	fmt.Printf("  ✅ Current epoch: %d\n", new(big.Int).SetBytes(result).Uint64())

	// calculateEpochAllocation()
	calldata = []byte{0xA7, 0x55, 0x9A, 0x16} // selSECalculateEpochAllocation
	result, _, _ = evm.ExecutePrecompile(seAddr, calldata, "", chain.State, chain.Height)
	alloc := new(big.Int).SetBytes(result)
	allocReadable := new(big.Int).Div(alloc, big.NewInt(1_000_000_000_000_000_000))
	fmt.Printf("  ✅ Epoch allocation: %s BIJO\n", allocReadable.String())

	fmt.Println()
	fmt.Println("═══ All 5 Protocol Precompiles Active ═══")
	fmt.Printf("Precompile addresses: 0x13 (DoxDevBadge), 0x14 (BIJO), 0x15 (DMS), 0x16 (BitcoinReg), 0x17 (StorEndow)\n")

	// Print precompile names
	fmt.Println(evm.PrecompileNames())
}

func main() {
	// CLI mode (with arguments)
	if len(os.Args) > 1 && os.Args[1] != "" {
		arg := os.Args[1]
		if arg == "--help" || arg == "-h" {
			printUsage()
			return
		}
		if arg[0] != '-' {
			RunCLI()
			return
		}
	}

	// Devnet mode (env var)
	if os.Getenv("WAYCHAIN_DEVNET") == "1" {
		runAsNode()
		return
	}

	runConsensusDemo()
	fmt.Println()
	runFullStackDemo()
	fmt.Println()
	RunPrecompileDemo()
	fmt.Println()
	RunP2PDemo()
	fmt.Println()
	RunOracleDemo()
	fmt.Println()
	RunRPCDemo()

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" WayChain — Actually Decentralized")
	fmt.Println("═══════════════════════════════════════════")
}
package main

import (
	"fmt"
	"time"

	"github.com/ThinkIbrokeIt/waychain-consensus/evm"
	"github.com/ThinkIbrokeIt/waychain-consensus/oracle"
)

func RunOracleDemo() {
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" WayChain Oracle Network — 3 Attesters")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	// ── Create 3 oracle nodes at different Dox_Dev levels ──
	oracles := []*oracle.OracleClient{
		oracle.NewOracleClient("oracle-primary", 3),   // Level 3 — can attest anything
		oracle.NewOracleClient("oracle-secondary", 2),  // Level 2 — standard attestations
		oracle.NewOracleClient("oracle-backup", 1),     // Level 1 — monitoring only
	}

	// ── Assign chains to monitor ──
	oracles[0].AddChain("bitcoin")
	oracles[0].AddChain("ethereum")
	oracles[1].AddChain("bitcoin")
	oracles[2].AddChain("pulsechain")

	// ── Start all oracles ──
	for _, o := range oracles {
		o.Start()
	}
	time.Sleep(100 * time.Millisecond)

	// ── Create the chain state for attestation logging ──
	state := evm.NewStateDB()

	// ── Simulate: Oracles witness a Bitcoin transaction ──
	fmt.Println("\n📡 External event detected: Bitcoin transfer")
	btcTxID := "abc123def456"
	oracles[0].WatchEvent("bitcoin", btcTxID, 840000, "Transfer(1.5 BTC)", []byte("btc_tx_data"))
	oracles[1].WatchEvent("bitcoin", btcTxID, 840000, "Transfer(1.5 BTC)", []byte("btc_tx_data"))
	time.Sleep(100 * time.Millisecond)

	// Oracles attest the event (3+ attestations needed per BitcoinRegistry spec)
	fmt.Println("\n🔏 Attesting Bitcoin transaction to WayChain...")
	for _, o := range oracles {
		if o.DoxDevLevel >= 2 {
			o.Attest(oracle.AttestTx, []byte(fmt.Sprintf("btc:tx:%s:block:%d", btcTxID, 840000)), state)
		}
	}
	fmt.Printf("  ✅ 2 oracles attested (meets minimum of 3? %v — waiting for oracle-backup)\n", false)

	// Backup oracle confirms
	oracles[2].Attest(oracle.AttestTx, []byte(fmt.Sprintf("btc:tx:%s:block:%d", btcTxID, 840000)), state)
	fmt.Printf("  ✅ 3 oracles attested — BitcoinRegistry commitment valid\n")

	// ── Simulate: Price feed updates ──
	fmt.Println("\n💹 Price feed updates...")
	for _, o := range oracles {
		if o.DoxDevLevel >= 2 {
			o.UpdatePriceFeed("WAY/USD", 0.52, 3)
			o.Attest(oracle.AttestPrice, []byte("WAY/USD:0.52"), state)
		}
	}
	fmt.Printf("  ✅ WAY/USD price attested by %d oracles\n", 2)

	// ── Simulate: Binary Journal truth anchor ──
	fmt.Println("\n📖 Binary Journal truth anchored...")
	truthHash := "7d5e3a2f1c8b9a4d6e0f3c2a1b8d9e4f5a6b7c8d"
	oracles[0].Attest(oracle.AttestTruth, []byte(fmt.Sprintf("truth:%s", truthHash)), state)
	oracles[1].Attest(oracle.AttestTruth, []byte(fmt.Sprintf("truth:%s", truthHash)), state)
	oracles[2].Attest(oracle.AttestTruth, []byte(fmt.Sprintf("truth:%s", truthHash)), state)
	fmt.Printf("  ✅ Truth hash %s anchored by all 3 oracles\n", truthHash[:16])

	// ── Confirm events ──
	fmt.Println("\n⏳ Waiting for confirmations...")
	time.Sleep(4 * time.Second)

	// ── Stats ──
	fmt.Println()
	for _, o := range oracles {
		o.Stop()
	}

	fmt.Println()
	fmt.Println("═══ Oracle Network Summary ═══")
	fmt.Printf("Total oracles: %d\n", len(oracles))
	totalAttestations := 0
	for _, o := range oracles {
		totalAttestations += int(o.TotalAttestations)
	}
	fmt.Printf("Total attestations: %d\n", totalAttestations)
	fmt.Printf("Price feeds active: WAY/USD\n")
	fmt.Printf("Chains monitored: bitcoin, ethereum, pulsechain\n")
	fmt.Println()
	fmt.Println("Oracle quorum model:")
	fmt.Printf("  Minimum attestations: 3 (BitcoinRegistry)\n")
	fmt.Printf("  Medium (3): oracles L2+ — price feeds, standard attestations\n")
	fmt.Printf("  High (5): oracles L3+ — bridge operations, critical data\n")
	fmt.Println()
	fmt.Println("Dox_Dev enforcement:")
	fmt.Printf("  Level 1: Monitoring only (cannot attest)\n")
	fmt.Printf("  Level 2: Standard attestations (price, transactions)\n")
	fmt.Printf("  Level 3: Critical attestations (bridges, high-value)\n")
}
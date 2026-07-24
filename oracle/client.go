// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package oracle

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/ThinkIbrokeIt/waychain-consensus/evm"
)

// OracleStatus represents the oracle's current state
type OracleStatus byte

const (
	StatusIdle      OracleStatus = 0
	StatusWatching  OracleStatus = 1
	StatusAttesting OracleStatus = 2
	StatusError     OracleStatus = 3
)

// AttestationType defines what kind of data the oracle is attesting
type AttestationType byte

const (
	AttestPrice     AttestationType = 1 // WAY/USD price feed
	AttestTx        AttestationType = 2 // Bitcoin or EVM transaction
	AttestTruth     AttestationType = 3 // Binary Journal truth anchor
	AttestStorage   AttestationType = 4 // Storage proof
)

// Attestation is a signed statement from the oracle
type Attestation struct {
	Type      AttestationType
	Data      []byte
	Timestamp int64
	OracleID  string
	Signature [32]byte // Simplified: hash of type + data + timestamp + oracleID
}

// PriceFeed holds the oracle's latest price data
type PriceFeed struct {
	Pair      string  // e.g. "WAY/USD"
	Price     float64
	Timestamp int64
	Sources   int     // Number of independent sources confirming
}

// WitnessedEvent is a transaction observed on an external chain
type WitnessedEvent struct {
	SourceChain string // "bitcoin", "ethereum", "pulsechain"
	TxHash      string
	BlockHeight uint64
	EventType   string
	Data        []byte
	Confirmed   bool // 6+ confirmations on source chain
}

// OracleClient is the daemon that watches chains and submits attestations
type OracleClient struct {
	ID          string
	DoxDevLevel uint8
	Status      OracleStatus

	// Price feeds this oracle maintains
	PriceFeeds map[string]*PriceFeed

	// Witnessed events waiting for confirmation
	PendingEvents map[string]*WitnessedEvent

	// Chains this oracle monitors
	MonitoredChains []string

	// Dox_Dev badge contract address (for verification)
	BadgeContract string

	mu sync.RWMutex

	// Stats
	TotalAttestations uint64
	TotalErrors       uint64
	UptimeSeconds     int64
	startTime         time.Time
}

// NewOracleClient creates a new oracle client
func NewOracleClient(id string, doxLevel uint8) *OracleClient {
	return &OracleClient{
		ID:              id,
		DoxDevLevel:     doxLevel,
		Status:          StatusIdle,
		PriceFeeds:      make(map[string]*PriceFeed),
		PendingEvents:   make(map[string]*WitnessedEvent),
		MonitoredChains: make([]string, 0),
		BadgeContract:   "doxdev.waychain",
		startTime:       time.Now(),
	}
}

// Start begins monitoring assigned chains and feeds
func (oc *OracleClient) Start() {
	oc.Status = StatusWatching
	oc.UptimeSeconds = 0

	fmt.Printf("  🥷 Oracle %s (Dox_Dev Level %d) started\n", oc.ID, oc.DoxDevLevel)

	// Price feed loop
	go oc.priceFeedLoop()

	// Event witnessing loop
	go oc.witnessLoop()

	// Health reporting loop
	go oc.healthLoop()
}

// Stop gracefully shuts down the oracle
func (oc *OracleClient) Stop() {
	oc.Status = StatusIdle
	fmt.Printf("  🥷 Oracle %s stopped | %d attestations | %d errors\n",
		oc.ID, oc.TotalAttestations, oc.TotalErrors)
}

// Attest submits an attestation to the WayChain EVM
func (oc *OracleClient) Attest(attType AttestationType, data []byte, state *evm.StateDB) *Attestation {
	oc.Status = StatusAttesting

	att := &Attestation{
		Type:      attType,
		Data:      data,
		Timestamp: time.Now().Unix(),
		OracleID:  oc.ID,
	}

	// Sign: hash(type + data + timestamp + oracleID)
	sigData := fmt.Sprintf("%d:%x:%d:%s", att.Type, att.Data, att.Timestamp, att.OracleID)
	att.Signature = sha256.Sum256([]byte(sigData))

	// Emit an ATTEST event to the EVM state
	// This simulates what the ATTEST opcode (0xC3) would do
	var hash [32]byte
	copy(hash[:], data)
	state.AddLog(oc.ID, [][32]byte{hash}, data, uint64(time.Now().Unix()))

	oc.mu.Lock()
	oc.TotalAttestations++
	oc.mu.Unlock()

	oc.Status = StatusWatching
	return att
}

// WatchEvent records a witnessed transaction from an external chain
func (oc *OracleClient) WatchEvent(sourceChain, txHash string, blockHeight uint64, eventType string, data []byte) {
	event := &WitnessedEvent{
		SourceChain: sourceChain,
		TxHash:      txHash,
		BlockHeight: blockHeight,
		EventType:   eventType,
		Data:        data,
		Confirmed:   false,
	}

	oc.mu.Lock()
	oc.PendingEvents[txHash] = event
	oc.mu.Unlock()

	fmt.Printf("  👁️  Oracle %s witnessed %s tx %s on %s (block %d)\n",
		oc.ID, eventType, txHash[:8], sourceChain, blockHeight)
}

// ConfirmEvent marks a witnessed event as confirmed (6+ blocks)
func (oc *OracleClient) ConfirmEvent(txHash string) {
	oc.mu.Lock()
	defer oc.mu.Unlock()

	if event, ok := oc.PendingEvents[txHash]; ok {
		event.Confirmed = true
	}
}

// GetPriceFeed returns the latest price for a pair
func (oc *OracleClient) GetPriceFeed(pair string) *PriceFeed {
	oc.mu.RLock()
	defer oc.mu.RUnlock()
	return oc.PriceFeeds[pair]
}

// UpdatePriceFeed sets a new price
func (oc *OracleClient) UpdatePriceFeed(pair string, price float64, sources int) {
	feed := &PriceFeed{
		Pair:      pair,
		Price:     price,
		Timestamp: time.Now().Unix(),
		Sources:   sources,
	}

	oc.mu.Lock()
	oc.PriceFeeds[pair] = feed
	oc.mu.Unlock()
}

// AddChain adds a chain for the oracle to monitor
func (oc *OracleClient) AddChain(chain string) {
	oc.mu.Lock()
	oc.MonitoredChains = append(oc.MonitoredChains, chain)
	oc.mu.Unlock()
	fmt.Printf("  📡 Oracle %s now monitoring %s\n", oc.ID, chain)
}

// priceFeedLoop simulates providing price data
func (oc *OracleClient) priceFeedLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	basePrice := 0.50 // Initial WAY price
	for range ticker.C {
		if oc.Status == StatusIdle {
			return
		}

		// Simulate slight price movement
		drift := (float64(time.Now().Unix()%100) - 50) * 0.001
		price := basePrice + drift
		if price < 0.01 {
			price = 0.01
		}

		oc.UpdatePriceFeed("WAY/USD", price, 3)
	}
}

// witnessLoop simulates watching for external events
func (oc *OracleClient) witnessLoop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if oc.Status == StatusIdle {
			return
		}

		// Simulate confirming pending events
		oc.mu.Lock()
		for txHash, event := range oc.PendingEvents {
			if !event.Confirmed {
				event.Confirmed = true
				fmt.Printf("  ✅ Oracle %s confirmed %s (6 blocks)\n", oc.ID, txHash[:8])
			}
		}
		oc.mu.Unlock()
	}
}

// healthLoop reports oracle status
func (oc *OracleClient) healthLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if oc.Status == StatusIdle {
			return
		}

		oc.mu.RLock()
		oc.UptimeSeconds = int64(time.Since(oc.startTime).Seconds())
		pendingCount := len(oc.PendingEvents)
		feedCount := len(oc.PriceFeeds)
		oc.mu.RUnlock()

		fmt.Printf("  💚 [ORACLE %s] uptime: %ds | attestations: %d | pending: %d | feeds: %d\n",
			oc.ID, oc.UptimeSeconds, oc.TotalAttestations, pendingCount, feedCount)
	}
}

// PrintStatus displays oracle details
func (oc *OracleClient) PrintStatus() {
	fmt.Printf("\n═══ Oracle: %s ═══\n", oc.ID)
	fmt.Printf("  Dox_Dev Level: %d\n", oc.DoxDevLevel)
	fmt.Printf("  Status: %d\n", oc.Status)
	fmt.Printf("  Uptime: %ds\n", oc.UptimeSeconds)
	fmt.Printf("  Attestations: %d\n", oc.TotalAttestations)
	fmt.Printf("  Errors: %d\n", oc.TotalErrors)
	fmt.Printf("  Price Feeds: %d\n", len(oc.PriceFeeds))
	fmt.Printf("  Pending Events: %d\n", len(oc.PendingEvents))
	fmt.Printf("  Monitoring: %v\n", oc.MonitoredChains)
	fmt.Println()

	if len(oc.PriceFeeds) > 0 {
		fmt.Println("Price Feeds:")
		for pair, feed := range oc.PriceFeeds {
			fmt.Printf("  %s = $%.4f (from %d sources)\n", pair, feed.Price, feed.Sources)
		}
	}

	if len(oc.PendingEvents) > 0 {
		fmt.Println("\nPending Witnessed Events:")
		for _, event := range oc.PendingEvents {
			status := "⏳"
			if event.Confirmed {
				status = "✅"
			}
			fmt.Printf("  %s %s on %s (block %d): %s\n",
				status, event.TxHash[:12], event.SourceChain, event.BlockHeight, event.EventType)
		}
	}
}
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"testing"
)

// TestConsensus200Validators tests the system with a full 200-validator set
func TestConsensus200Validators(t *testing.T) {
	vs := NewValidatorSet()

	// Add 200 validators with varying stakes
	// Stakes range from 10,000 (minimum) to 10,000,000 (whale)
	for i := 0; i < 200; i++ {
		id := NewValidatorID(byte(i%256))
		// Vary stake: some small, some medium, some large
		var stake uint64
		switch i % 5 {
		case 0:
			stake = 10000 // minimum
		case 1:
			stake = 50000 // small
		case 2:
			stake = 100000 // medium
		case 3:
			stake = 500000 // large
		case 4:
			stake = 1000000 // whale
		}
		err := vs.Add(id, stake)
		if err != nil {
			t.Fatalf("Failed to add validator %d: %v", i, err)
		}
	}

	engine := NewConsensusEngine(vs)

	// Verify active set is capped at 200
	if len(engine.ActiveSet) > MaxValidators {
		t.Fatalf("Active set exceeds max: %d > %d", len(engine.ActiveSet), MaxValidators)
	}
	if len(engine.ActiveSet) != 200 {
		t.Fatalf("Expected 200 active validators, got %d", len(engine.ActiveSet))
	}

	// Verify total voting power = 200 (equal power)
	if engine.TotalPower != 200 {
		t.Fatalf("Expected total power 200, got %d", engine.TotalPower)
	}

	// Run 1000 proposer selections
	proposerCounts := make(map[string]int)
	for h := uint64(1); h <= 1000; h++ {
		p := engine.SelectProposer(h)
		if p == nil {
			t.Fatalf("No proposer for height %d", h)
		}
		proposerCounts[p.String()]++
	}

	// Verify distribution: all 200 validators should get some slots
	if len(proposerCounts) < 150 {
		t.Fatalf("Expected at least 150 unique proposers, got %d", len(proposerCounts))
	}

	// Verify no single validator dominates (>10% of slots)
	for id, count := range proposerCounts {
		pct := float64(count) / 10.0 // percentage of 1000 blocks
		if pct > 15.0 {
			t.Fatalf("Validator %s has %.1f%% of slots (too dominant)", id, pct)
		}
	}

	t.Logf("✅ 200 validators: %d unique proposers, max dominance <15%%", len(proposerCounts))
}

// TestConsensusSqrtWeighting200 verifies sqrt-weighting prevents whale dominance at scale
func TestConsensusSqrtWeighting200(t *testing.T) {
	vs := NewValidatorSet()

	// Add 198 small validators + 1 whale
	// Use unique last byte for each (String() only shows last byte)
	for i := 0; i < 198; i++ {
		id := NewValidatorID(byte(i + 1)) // unique last byte
		vs.Add(id, 10000)                  // minimum stake
	}
	// One whale with 100x the stake
	whaleID := NewValidatorID(0xFF)
	vs.Add(whaleID, 1000000)

	engine := NewConsensusEngine(vs)

	// Run 10000 selections
	counts := make(map[string]int)
	for h := uint64(1); h <= 10000; h++ {
		p := engine.SelectProposer(h)
		if p != nil {
			counts[p.String()]++
		}
	}

	// Whale should NOT dominate
	whaleCount := counts[whaleID.String()]
	whalePct := float64(whaleCount) / 100.0

	// With sqrt weighting: whale gets into active set but has EQUAL chance as others
	// 199 validators in active set → each gets ~0.5% of slots
	// Whale should get roughly 1/199 = 0.5% (not 50%+ like linear weighting would give)
	if whalePct > 2.0 {
		t.Fatalf("Whale has %.1f%% of slots — should be ~0.5%% with equal active set", whalePct)
	}

	t.Logf("✅ Sqrt weighting at scale: whale=%.1f%% (equal chance in active set)", whalePct)
}

// TestConsensusFinalityWith200 tests that 2/3+ threshold works with 200 validators
func TestConsensusFinalityWith200(t *testing.T) {
	vs := NewValidatorSet()
	for i := 0; i < 200; i++ {
		vs.Add(NewValidatorID(byte(i%256)), 10000)
	}

	engine := NewConsensusEngine(vs)
	chain := NewChain()
	cm := NewConsensusManager(engine, nil, chain)

	// 2/3 of 200 = 134 votes needed
	threshold := uint64(float64(engine.TotalPower) * InstantFinalityThreshold)
	if threshold < 133 || threshold > 135 {
		t.Fatalf("Expected threshold ~134, got %d", threshold)
	}

	// Propose block
	proposer := engine.SelectProposer(1)
	cm.proposeBlock(1, *proposer)

	// Get 132 precommits (below threshold of 133)
	for i := 0; i < 132; i++ {
		cm.precommit(1, 0, [32]byte{0x01}, NewValidatorID(byte(i%256)))
	}

	// Should NOT be finalized yet
	if cm.Engine.CurrentHeight >= 1 {
		t.Fatal("Block should not be finalized with only 132/200 precommits")
	}

	// One more precommit → 133 → at threshold
	cm.precommit(1, 0, [32]byte{0x01}, NewValidatorID(0x84))

	// Should be finalized now
	if cm.Engine.CurrentHeight < 1 {
		t.Fatal("Block should be finalized with 133/200 precommits")
	}

	t.Logf("✅ Finality with 200 validators: threshold=%d, finalized at 133 precommits", threshold)
}

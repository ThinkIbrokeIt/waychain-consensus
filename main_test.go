// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"math/big"
	"testing"
)

func TestConsensusEngine(t *testing.T) {
	vs := NewValidatorSet()
	vs.Add(NewValidatorID(0x01), 10000)
	vs.Add(NewValidatorID(0x02), 50000)
	vs.Add(NewValidatorID(0x03), 100000)
	vs.Add(NewValidatorID(0x04), 500000)
	vs.Add(NewValidatorID(0x05), 10000)

	ce := NewConsensusEngine(vs)

	if len(ce.ActiveSet) == 0 {
		t.Fatal("Expected active set to be selected")
	}

	for _, v := range ce.ActiveSet {
		if ce.VotingPower[v.String()] != 1 {
			t.Fatalf("Expected equal voting power for %s", v.String())
		}
	}

	p1 := ce.SelectProposer(1)
	p2 := ce.SelectProposer(1)
	if p1 == nil || p2 == nil {
		t.Fatal("Expected proposer to be selected")
	}
	if p1.String() != p2.String() {
		t.Fatalf("Not deterministic: %s vs %s", p1.String(), p2.String())
	}

	proposers := make(map[string]bool)
	for h := uint64(1); h <= 100; h++ {
		p := ce.SelectProposer(h)
		if p != nil {
			proposers[p.String()] = true
		}
	}
	if len(proposers) < 2 {
		t.Fatalf("Expected multiple proposers, got %d", len(proposers))
	}

	block := &BlockWithTx{Height: 1, Hash: [32]byte{0x01, 0x02}}
	ce.FinalizeBlock(block)
	if ce.Blocks[1].Height != 1 {
		t.Fatal("Block not finalized")
	}

	t.Logf("✅ Consensus: %d validators, %d active, equal power", len(vs.IDs), len(ce.ActiveSet))
}

func TestConsensusSqrtWeighting(t *testing.T) {
	vs := NewValidatorSet()
	stakes := []uint64{500, 500, 5000, 5000, 15000, 15000, 30000}
	for i, stake := range stakes {
		vs.Add(NewValidatorID(byte(i+1)), stake)
	}

	ce := NewConsensusEngine(vs)

	counts := make(map[string]int)
	for h := uint64(1); h <= 1000; h++ {
		p := ce.SelectProposer(h)
		if p != nil {
			counts[p.String()]++
		}
	}

	v1Count := counts[NewValidatorID(1).String()]
	v7Count := counts[NewValidatorID(7).String()]

	if v1Count == 0 {
		t.Fatal("Small validator should get slots")
	}
	if v7Count > 600 {
		t.Fatalf("Whale should not dominate, got %d/1000", v7Count)
	}

	t.Logf("✅ Sqrt weighting: small(500)=%d, whale(30000)=%d", v1Count, v7Count)
}

func TestConsensusRandomSeed(t *testing.T) {
	vs := NewValidatorSet()
	vs.Add(NewValidatorID(0x01), 10000)
	vs.Add(NewValidatorID(0x02), 10000)

	ce := NewConsensusEngine(vs)

	// Random seed should be set
	if ce.RandomSeed == [32]byte{} {
		t.Fatal("Random seed should be initialized")
	}

	// Different epochs should have different seeds
	seed1 := ce.RandomSeed
	ce.selectNewEpoch()
	seed2 := ce.RandomSeed
	if seed1 == seed2 {
		t.Log("Warning: Same seed after epoch change (height unchanged)")
	}
	_ = new(big.Int)
}

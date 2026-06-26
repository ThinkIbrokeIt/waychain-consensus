package main

import (
	"testing"
)

func TestCalculateRewardBracket1(t *testing.T) {
	// Bracket 1: 1-1000 tokens at 15%
	// 500 tokens → 500 * 0.15 = 75
	if r := CalculateReward(500); r != 75 {
		t.Fatalf("expected 75, got %d", r)
	}
	if r := CalculateReward(1000); r != 150 {
		t.Fatalf("1000 tokens: expected 150, got %d", r)
	}
}

func TestCalculateRewardBracket2(t *testing.T) {
	// 5000 tokens: 1000*0.15 + 4000*0.08 = 150 + 320 = 470
	if r := CalculateReward(5_000); r != 470 {
		t.Fatalf("5000 tokens: expected 470, got %d", r)
	}
}

func TestCalculateRewardBracket3(t *testing.T) {
	// 50,000 tokens: 1000*0.15 + 9000*0.08 + 40000*0.04 = 150 + 720 + 1600 = 2470
	if r := CalculateReward(50_000); r != 2470 {
		t.Fatalf("50000 tokens: expected 2470, got %d", r)
	}
}

func TestCalculateRewardBracket4(t *testing.T) {
	// 500,000 tokens: 1000*0.15 + 9000*0.08 + 90000*0.04 + 400000*0.02
	// = 150 + 720 + 3600 + 8000 = 12470
	if r := CalculateReward(500_000); r != 12470 {
		t.Fatalf("500000 tokens: expected 12470, got %d", r)
	}
}

func TestCalculateRewardBracket5(t *testing.T) {
	// 5,000,000 tokens: 1000*0.15 + 9000*0.08 + 90000*0.04 + 900000*0.02 + 4000000*0.01
	// = 150 + 720 + 3600 + 18000 + 40000 = 62470
	if r := CalculateReward(5_000_000); r != 62470 {
		t.Fatalf("5M tokens: expected 62470, got %d", r)
	}
}

func TestCalculateRewardBelowMinimum(t *testing.T) {
	if r := CalculateReward(0); r != 0 {
		t.Fatalf("0 stake: expected 0, got %d", r)
	}
}

func TestEffectiveAPY(t *testing.T) {
	tests := []struct {
		stake    uint64
		expected float64
	}{
		{100, 15.0},
		{5_000, 9.40},   // 470/5000 = 0.094 → 9.40%
		{50_000, 4.94},  // 2470/50000 = 0.0494 → 4.94%
		{500_000, 2.49}, // 12470/500000 → 2.494%
	}
	for _, tt := range tests {
		got := EffectiveAPY(tt.stake)
		if got < tt.expected-0.01 || got > tt.expected+0.01 {
			t.Fatalf("stake %d: expected APY ~%.2f, got %.2f", tt.stake, tt.expected, got)
		}
	}
}

func TestPerBlockReward(t *testing.T) {
	// 1000 tokens → 150/year → 150/31536000 per block ≈ 0 (below 1 token per block)
	// Larger stake: 50,000 tokens → 2470/year → 2470/31536000 ≈ 0.078 → 0 per block
	pb := PerBlockReward(50_000)
	if pb != 0 {
		t.Fatalf("per-block reward for 50K should be 0 (sub-token), got %d", pb)
	}

	// Large stake: 5M tokens → 62470/year → 62470/31536000 ≈ 0.00198 → 0 per block
	pb = PerBlockReward(5_000_000)
	if pb != 0 {
		t.Fatalf("per-block reward for 5M should still be 0, got %d", pb)
	}
}

func TestAntiWhaleEffect(t *testing.T) {
	// A whale with 500K tokens should earn less effective APY than small staker
	smallAPY := EffectiveAPY(100)
	whaleAPY := EffectiveAPY(500_000)
	if whaleAPY >= smallAPY {
		t.Fatalf("whale APY (%.2f) should be less than small staker APY (%.2f)", whaleAPY, smallAPY)
	}

	// Wealth gap: flat 7% gives 35,000 to 500K whale vs 7 to 100-token small = 5000x gap
	// Progressive: should be much smaller ratio
	flatReward := func(stake uint64) uint64 { return uint64(float64(stake) * 0.07) }
	flatRatio := float64(flatReward(500_000)) / float64(flatReward(100))
	progRatio := float64(CalculateReward(500_000)) / float64(CalculateReward(100))
	if progRatio >= flatRatio {
		t.Fatalf("progressive ratio (%.2f) should be less than flat ratio (%.2f)", progRatio, flatRatio)
	}
}

func TestProgressiveStakingManager(t *testing.T) {
	ps := NewProgressiveStaking(1000) // 1000 tokens per block reward limit

	id1 := NewValidatorID(0x01)
	id2 := NewValidatorID(0x02)

	ps.RegisterStake(id1, 1_000)   // small staker
	ps.RegisterStake(id2, 500_000) // whale

	if ps.TotalStaked != 501_000 {
		t.Fatalf("total stake: expected 501000, got %d", ps.TotalStaked)
	}

	// Distribute — should not exceed pool
	dist := ps.DistributeBlockReward(1)
	var totalDistributed uint64
	for _, v := range dist {
		totalDistributed += v
	}
	if totalDistributed > ps.BlockRewardLimit {
		t.Fatalf("total distributed %d exceeds limit %d", totalDistributed, ps.BlockRewardLimit)
	}

	// Claim
	claimed := ps.ClaimReward(id1)
	if claimed != dist[id1] {
		t.Fatalf("claim mismatch: expected %d, got %d", dist[id1], claimed)
	}
	if ps.ValidatorRewards[id1].Accumulated != 0 {
		t.Fatalf("accumulated should be 0 after claim")
	}
}

func TestProgressiveClaimReset(t *testing.T) {
	ps := NewProgressiveStaking(100000)
	id := NewValidatorID(0x03)
	ps.RegisterStake(id, 5_000_000)

	ps.DistributeBlockReward(1)
	claimed := ps.ClaimReward(id)
	if claimed == 0 {
		t.Fatal("expected non-zero claim")
	}
	// Second claim should be 0 (already claimed)
	if c := ps.ClaimReward(id); c != 0 {
		t.Fatalf("expected 0 on second claim, got %d", c)
	}
}

func TestProgressiveRemoveStake(t *testing.T) {
	ps := NewProgressiveStaking(1000)
	id := NewValidatorID(0x04)
	ps.RegisterStake(id, 5_000)
	if ps.TotalStaked != 5_000 {
		t.Fatalf("expected 5000, got %d", ps.TotalStaked)
	}
	ps.RemoveStake(id)
	if ps.TotalStaked != 0 {
		t.Fatalf("expected 0 after removal, got %d", ps.TotalStaked)
	}
	if _, ok := ps.ValidatorRewards[id]; ok {
		t.Fatal("validator should be removed")
	}
}

func TestProgressiveUpdateStake(t *testing.T) {
	ps := NewProgressiveStaking(1000)
	id := NewValidatorID(0x05)
	ps.RegisterStake(id, 5_000)
	ps.RegisterStake(id, 10_000) // increase
	if ps.TotalStaked != 10_000 {
		t.Fatalf("total should reflect updated stake, got %d", ps.TotalStaked)
	}
	if ps.ValidatorRewards[id].StakedAmount != 10_000 {
		t.Fatal("stake amount not updated")
	}
}

func TestSpecExamples(t *testing.T) {
	// Exact spec examples from tokenomics.md
	tests := []struct {
		stake    uint64
		expected uint64
	}{
		{100, 15},         // 15% * 100
		{5_000, 470},      // 150 + 320
		{50_000, 2470},    // 150 + 720 + 1600
		{500_000, 12470},  // 150 + 720 + 3600 + 8000
		{5_000_000, 62470}, // 150 + 720 + 3600 + 18000 + 40000
	}
	for _, tt := range tests {
		got := CalculateReward(tt.stake)
		if got != tt.expected {
			t.Fatalf("stake %d: expected %d, got %d", tt.stake, tt.expected, got)
		}
	}
}

func TestNewValidatorID(t *testing.T) {
	id := NewValidatorID(0xAB)
	if len(id) != 20 {
		t.Fatalf("expected 20 bytes, got %d", len(id))
	}
	if id[19] != 0xAB {
		t.Fatal("validator ID should have last byte set")
	}
}



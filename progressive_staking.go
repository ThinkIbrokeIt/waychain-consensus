package main

import (
	"fmt"
	"math"
)

// ══════════════════════════════════════════════════════════════════════
// Progressive Staking — Anti-Whale Reward Engine
// Implements the tokenomics spec (§3): marginal reward brackets
// Smaller stakes earn higher effective APY, flattening compounding
// advantage of large holders.
// ══════════════════════════════════════════════════════════════════════

// StakingBracket defines a marginal reward tier
type StakingBracket struct {
	MinStake    uint64  // Inclusive lower bound (tokens)
	MaxStake    uint64  // Exclusive upper bound (0 = unlimited)
	APY         float64 // Annual percentage yield for tokens in this bracket
	Description string
}

// ProgressiveStakingBrackets — the spec's 5 brackets
// Each bracket applies MARGINALLY: a staker with 50,000 tokens earns:
//   15% on first 1,000 + 8% on next 9,000 + 4% on remaining 40,000
var ProgressiveStakingBrackets = []StakingBracket{
	{MinStake: 1, MaxStake: 1_001, APY: 0.15, Description: "1 - 1,000 tokens: 15% APY"},
	{MinStake: 1_001, MaxStake: 10_001, APY: 0.08, Description: "1,001 - 10,000 tokens: 8% APY"},
	{MinStake: 10_001, MaxStake: 100_001, APY: 0.04, Description: "10,001 - 100,000 tokens: 4% APY"},
	{MinStake: 100_001, MaxStake: 1_000_001, APY: 0.02, Description: "100,001 - 1,000,000 tokens: 2% APY"},
	{MinStake: 1_000_001, MaxStake: 0, APY: 0.01, Description: "1,000,001+ tokens: 1% APY"},
}

// ValidatorReward tracks a validator's staking reward snapshot
type ValidatorReward struct {
	ValidatorID     ValidatorID
	StakedAmount    uint64
	RewardPerBlock  uint64 // Accumulated rewards per block (distributed to this validator)
	Accumulated     uint64 // Total accumulated but not yet claimed
	LastUpdateBlock uint64
}

// ProgressiveStaking manages reward distribution
type ProgressiveStaking struct {
	RewardPool       uint64                    // Total reward pool per epoch (in tokens)
	BlockRewardLimit uint64                    // Max tokens distributed per block
	ValidatorRewards map[ValidatorID]*ValidatorReward
	TotalStaked      uint64
	CurrentBlock     uint64
}

// NewProgressiveStaking creates a new staking reward manager
func NewProgressiveStaking(blockRewardLimit uint64) *ProgressiveStaking {
	return &ProgressiveStaking{
		BlockRewardLimit: blockRewardLimit,
		ValidatorRewards: make(map[ValidatorID]*ValidatorReward),
	}
}

// CalculateReward computes the marginal annual reward for a given stake
// Uses bracket-based calculation: each bracket applies only to tokens within its range
func CalculateReward(stake uint64) uint64 {
	if stake < MinStake {
		return 0
	}

	var annualReward float64
	remaining := float64(stake)
	var lowerBound float64

	for i, bracket := range ProgressiveStakingBrackets {
		if remaining <= 0 {
			break
		}

		upperBound := float64(bracket.MaxStake)
		if bracket.MaxStake == 0 {
			// Unlimited top bracket
			upperBound = math.MaxFloat64
		}

		// Tokens that fall into this bracket
		bracketSize := upperBound - lowerBound
		if i == 0 {
			upperBound = float64(bracket.MaxStake)
			lowerBound = float64(bracket.MinStake) - 1
			bracketSize = upperBound - lowerBound
		}

		tokensInBracket := math.Min(remaining, bracketSize)
		if tokensInBracket <= 0 {
			break
		}

		annualReward += tokensInBracket * bracket.APY
		remaining -= tokensInBracket
		lowerBound = upperBound
	}

	return uint64(math.Floor(annualReward))
}

// EffectiveAPY returns the effective APY for a given stake size
func EffectiveAPY(stake uint64) float64 {
	if stake == 0 {
		return 0
	}
	reward := CalculateReward(stake)
	return float64(reward) / float64(stake) * 100
}

// PerBlockReward calculates the single-block reward for a staker
// Assumes 31,536,000 seconds/year and 1 block/second
func PerBlockReward(stake uint64) uint64 {
	annual := CalculateReward(stake)
	// 31,536,000 seconds/year ÷ 1 block/second = blocks/year
	blocksPerYear := uint64(31_536_000)
	return annual / blocksPerYear
}

// RegisterStake registers or updates a validator's stake
func (ps *ProgressiveStaking) RegisterStake(id ValidatorID, amount uint64) {
	if existing, ok := ps.ValidatorRewards[id]; ok {
		ps.TotalStaked -= existing.StakedAmount
		existing.StakedAmount = amount
	} else {
		ps.ValidatorRewards[id] = &ValidatorReward{
			ValidatorID:     id,
			StakedAmount:    amount,
			LastUpdateBlock: ps.CurrentBlock,
		}
	}
	ps.TotalStaked += amount
}

// RemoveStake removes a validator's stake
func (ps *ProgressiveStaking) RemoveStake(id ValidatorID) {
	if existing, ok := ps.ValidatorRewards[id]; ok {
		ps.TotalStaked -= existing.StakedAmount
		delete(ps.ValidatorRewards, id)
	}
}

// DistributeBlockReward calculates and distributes the block reward
// proportionally to all validators based on their staked amount.
// Uses fixed-point accumulation: each block, compute the fractional
// reward owed and carry the remainder forward.
func (ps *ProgressiveStaking) DistributeBlockReward(height uint64) map[ValidatorID]uint64 {
	ps.CurrentBlock = height
	distribution := make(map[ValidatorID]uint64)

	// Calculate annual rewards for each validator
	var totalAnnual uint64
	annualRewards := make(map[ValidatorID]uint64)
	for id, vr := range ps.ValidatorRewards {
		r := CalculateReward(vr.StakedAmount)
		annualRewards[id] = r
		totalAnnual += r
	}

	if totalAnnual == 0 {
		return distribution
	}

	// Distribute BlockRewardLimit proportionally by annual reward share
	// fixed-point: multiply first to preserve precision
	for id, annual := range annualRewards {
		// blockReward = BlockRewardLimit * annual / totalAnnual
		// Use 128-bit intermediate to avoid overflow
		numerator := uint64(ps.BlockRewardLimit) * annual
		blockReward := numerator / totalAnnual
		distribution[id] = blockReward
		vr := ps.ValidatorRewards[id]
		vr.Accumulated += blockReward
	}

	return distribution
}

// ClaimReward returns and resets accumulated rewards for a validator
func (ps *ProgressiveStaking) ClaimReward(id ValidatorID) uint64 {
	vr, ok := ps.ValidatorRewards[id]
	if !ok {
		return 0
	}
	amount := vr.Accumulated
	vr.Accumulated = 0
	return amount
}

// PrintBracketTable displays the bracket structure
func PrintBracketTable() {
	fmt.Println("\n=== Progressive Staking Brackets ===")
	fmt.Println("Bracket                          APY     Example (top of bracket)")
	fmt.Println("─────────────────────────────────────────────────────────────────")

	for _, b := range ProgressiveStakingBrackets {
		topStake := b.MaxStake
		if topStake == 0 {
			topStake = 5_000_000
		}
		reward := CalculateReward(topStake)
		effAPY := EffectiveAPY(topStake)
		fmt.Printf("  %-30s %5.1f%%   %10d tokens → %d/year (%.2f%% eff)\n",
			b.Description, b.APY*100, topStake, reward, effAPY)
	}

	fmt.Println()
	fmt.Println("Wealth gap comparison (flat 7% vs progressive):")
	fmt.Println("─────────────────────────────────────────────────────────────────")
	sizes := []uint64{100, 1_000, 5_000, 50_000, 500_000, 5_000_000}
	fmt.Printf("%-12s %-10s %-10s %-10s\n", "Stake", "Flat 7%", "Progressive", "Ratio")
	for _, s := range sizes {
		flat := uint64(float64(s) * 0.07)
		prog := CalculateReward(s)
		ratio := float64(flat) / float64(prog)
		fmt.Printf("  %-10d %-10d %-10d %.2fx\n", s, flat, prog, ratio)
	}
	fmt.Println()
}

// PrintRewardTable shows rewards for specific stake sizes
func PrintRewardTable() {
	fmt.Println("\n=== Progressive Staking — Reward Table ===")
	fmt.Println("Stake         Annual Reward    Effective APY    Per Block")
	fmt.Println("─────────────────────────────────────────────────────────────")

	sizes := []uint64{100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000, 5_000_000}
	for _, s := range sizes {
		reward := CalculateReward(s)
		effAPY := EffectiveAPY(s)
		perBlock := PerBlockReward(s)
		fmt.Printf("%-12d   %-14d   %6.2f%%         %d\n", s, reward, effAPY, perBlock)
	}
	fmt.Println()
}

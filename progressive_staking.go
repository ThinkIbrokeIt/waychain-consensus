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

// WayChain token supply — single source of truth for emission math.
// The progressive staking model is anchored to this so validator rewards
// are always a fixed fraction of total supply (default 7%/year), NOT a
// magic per-block number that detached from supply in earlier builds.
const WAYTotalSupply uint64 = 100_000_000

// Default emission: 7% of total supply minted per year to validators,
// split by the progressive (anti-whale) brackets defined above.
const DefaultAnnualInflationPct = 7.0

// Default block time (seconds) — matches consensus.go ConsensusTimeout feel.
// Drives per-block reward granularity. Change here to retune chain cadence.
const DefaultBlockTimeSec = 3.0

// Blocks per year at the configured block time.
func blocksPerYear(blockTimeSec float64) float64 {
	return 31_536_000.0 / blockTimeSec
}

// ProgressiveStaking manages reward distribution
type ProgressiveStaking struct {
	AnnualInflationPct float64                  // Target validator emission as % of total supply/year
	BlockTimeSec       float64                  // Seconds per block (drives per-block granularity)
	ValidatorRewards   map[ValidatorID]*ValidatorReward
	TotalStaked        uint64
	CurrentBlock       uint64
	accrued            float64 // fractional token carry (paid out when >= 1.0)
	epochMinted        uint64  // tokens minted in the current epoch (cap enforcement)
	EpochLength        uint64  // blocks per epoch (set from consensus.EpochLength)
}

// NewProgressiveStaking creates a new staking reward manager.
// annualInflationPct: % of WAY_TOTAL_SUPPLY minted per year to validators (default 7.0).
// blockTimeSec: seconds per block (default 3.0). epochLength: blocks per epoch
// (pass consensus.EpochLength so the 7% cap holds regardless of block cadence).
func NewProgressiveStaking(annualInflationPct, blockTimeSec float64, epochLength uint64) *ProgressiveStaking {
	if annualInflationPct <= 0 {
		annualInflationPct = DefaultAnnualInflationPct
	}
	if blockTimeSec <= 0 {
		blockTimeSec = DefaultBlockTimeSec
	}
	return &ProgressiveStaking{
		AnnualInflationPct: annualInflationPct,
		BlockTimeSec:       blockTimeSec,
		EpochLength:        epochLength,
		ValidatorRewards:   make(map[ValidatorID]*ValidatorReward),
	}
}

// AnnualEmission returns the total WAY minted to validators per year
// (7% of total supply by default). This is the anchor the whole model
// was designed around and had been flattened into a magic per-block number.
func (ps *ProgressiveStaking) AnnualEmission() uint64 {
	return uint64(float64(WAYTotalSupply) * ps.AnnualInflationPct / 100.0)
}

// PerBlockEmission returns the exact (fractional) WAY owed validators this block,
// anchored to the annual emission and the configured block time.
func (ps *ProgressiveStaking) PerBlockEmission() float64 {
	return float64(ps.AnnualEmission()) / blocksPerYear(ps.BlockTimeSec)
}

// EpochCap returns the max tokens allowed to be minted in one epoch.
// Guarantees the annual inflation cap holds regardless of block-time granularity:
// at 3s blocks an epoch is short, so the cap prevents over-emission between
// annual resets; the on-chain epoch rollover (consensus.EpochLength) resets it.
func (ps *ProgressiveStaking) EpochCap() uint64 {
	if ps.EpochLength == 0 {
		return ps.AnnualEmission() // degenerate: cap = full year
	}
	blocksPerYear := blocksPerYear(ps.BlockTimeSec)
	epochsPerYear := blocksPerYear / float64(ps.EpochLength)
	if epochsPerYear <= 0 {
		return ps.AnnualEmission()
	}
	return uint64(float64(ps.AnnualEmission()) / epochsPerYear)
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

// DistributeBlockReward calculates and distributes this block's validator
// emission — anchored to the annual inflation cap (7% of supply by default)
// and split across validators by their progressive (anti-whale) annual reward.
//
// Emission is paid as whole tokens only: the per-block fractional amount is
// accrued and carried forward until it crosses 1.0 WAY, so no reward is lost
// to integer truncation across the ~10.5M blocks/year. An epoch cap guarantees
// the annual cap holds even when block time changes.
func (ps *ProgressiveStaking) DistributeBlockReward(height uint64) map[ValidatorID]uint64 {
	ps.CurrentBlock = height
	distribution := make(map[ValidatorID]uint64)

	// Calculate annual rewards for each validator (progressive brackets)
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

	// Total WAY owed to validators this block (fractional).
	perBlock := ps.PerBlockEmission()
	ps.accrued += perBlock

	// Epoch cap: do not exceed the per-epoch allowance.
	cap := ps.EpochCap()
	if cap > 0 && ps.epochMinted >= cap {
		// Epoch budget exhausted — mint nothing until the next epoch rollover.
		// Accrual is preserved so it resumes cleanly next epoch.
		return distribution
	}

	// Candidate whole tokens to distribute this block (carry-forward accumulator).
	available := uint64(ps.accrued)
	if available == 0 {
		return distribution
	}
	// Respect the epoch cap for this block's slice.
	if cap > 0 && ps.epochMinted+available > cap {
		available = cap - ps.epochMinted
		if available == 0 {
			return distribution
		}
	}

	// Split `available` across validators by their share of total annual reward.
	// Only tokens actually paid out are removed from the accrual — any remainder
	// (lost to integer rounding on a sub-pool) is carried forward to the next
	// block so no emission is ever destroyed.
	var paid uint64
	for id, annual := range annualRewards {
		numerator := available * annual // uint64 * uint64 — bounded by cap
		blockReward := numerator / totalAnnual
		if blockReward == 0 {
			continue
		}
		distribution[id] = blockReward
		vr := ps.ValidatorRewards[id]
		vr.Accumulated += blockReward
		paid += blockReward
	}
	if paid == 0 {
		// Whole-token pool too small to split without rounding to zero this block;
		// leave accrual intact so it compounds next block.
		return distribution
	}
	ps.accrued -= float64(paid)
	ps.epochMinted += paid

	return distribution
}

// RolloverEpoch resets the per-epoch mint counter. Call this from the consensus
// engine when a new epoch begins (height % EpochLength == 0) so the 7% annual
// cap is enforced per-epoch rather than relying solely on the annual accumulator.
func (ps *ProgressiveStaking) RolloverEpoch() {
	ps.epochMinted = 0
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

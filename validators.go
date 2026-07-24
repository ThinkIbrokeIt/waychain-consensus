// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
)

const MaxValidators = 200
const MinStake = 100
const JailThreshold = 50

// ValidatorSet manages active validators
type ValidatorSet struct {
	IDs     []ValidatorID // Active validator IDs (sorted)
	Stakes  map[ValidatorID]uint64
	Missed  map[ValidatorID]int
	Jailed  []ValidatorID
	seed    int64
}

func NewValidatorSet() *ValidatorSet {
	return &ValidatorSet{
		IDs:    make([]ValidatorID, 0, MaxValidators),
		Stakes: make(map[ValidatorID]uint64),
		Missed: make(map[ValidatorID]int),
		Jailed: make([]ValidatorID, 0),
	}
}

// Add registers and activates a validator
func (vs *ValidatorSet) Add(id ValidatorID, stake uint64) error {
	if _, exists := vs.Stakes[id]; exists {
		return fmt.Errorf("%s already registered", id.String())
	}
	if stake < MinStake {
		return fmt.Errorf("stake %d < minimum %d", stake, MinStake)
	}
	if len(vs.IDs) >= MaxValidators {
		return fmt.Errorf("max %d validators reached", MaxValidators)
	}

	vs.Stakes[id] = stake
	vs.Missed[id] = 0
	vs.IDs = append(vs.IDs, id)
	sort.Slice(vs.IDs, func(i, j int) bool {
		return string(vs.IDs[i][:]) < string(vs.IDs[j][:])
	})
	return nil
}

// AddMultiple adds validators in batch for setup
func (vs *ValidatorSet) AddMultiple(ids []ValidatorID, stakes []uint64) error {
	for i, id := range ids {
		if i < len(stakes) {
			if err := vs.Add(id, stakes[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

// Remove removes a validator from active set
func (vs *ValidatorSet) Remove(id ValidatorID) {
	for i, vid := range vs.IDs {
		if vid == id {
			vs.IDs = append(vs.IDs[:i], vs.IDs[i+1:]...)
			break
		}
	}
	delete(vs.Stakes, id)
	delete(vs.Missed, id)
}

// Jail removes and jails a validator
func (vs *ValidatorSet) Jail(id ValidatorID) {
	vs.Remove(id)
	vs.Jailed = append(vs.Jailed, id)
}

// MarkMissed increments missed counter, jails if over threshold
func (vs *ValidatorSet) MarkMissed(id ValidatorID) bool {
	vs.Missed[id]++
	if vs.Missed[id] >= JailThreshold {
		vs.Jail(id)
		fmt.Printf("  ❌ Validator %s jailed (%d missed blocks)\n", id.String(), JailThreshold)
		return true
	}
	return false
}

// TotalStake returns total WAY staked
func (vs *ValidatorSet) TotalStake() uint64 {
	var total uint64
	for _, v := range vs.IDs {
		total += vs.Stakes[v]
	}
	return total
}

// Count returns number of active validators
func (vs *ValidatorSet) Count() int {
	return len(vs.IDs)
}

// SqrtWeight returns sqrt of a validator's stake
func (vs *ValidatorSet) SqrtWeight(id ValidatorID) float64 {
	return math.Sqrt(float64(vs.Stakes[id]))
}

// TotalSqrtWeight returns sum of all sqrt weights
func (vs *ValidatorSet) TotalSqrtWeight() float64 {
	var total float64
	for _, id := range vs.IDs {
		total += math.Sqrt(float64(vs.Stakes[id]))
	}
	return total
}

// SelectProposer picks the next proposer using sqrt-weighted lottery
func (vs *ValidatorSet) SelectProposer(height uint64) ValidatorID {
	totalWeight := vs.TotalSqrtWeight()
	if totalWeight <= 0 {
		return vs.IDs[0]
	}

	vs.seed = int64(height*2654435761 + uint64(len(vs.IDs))*3141592653)
	rng := rand.New(rand.NewSource(vs.seed))
	pick := rng.Float64() * totalWeight

	var cumulative float64
	for _, id := range vs.IDs {
		cumulative += math.Sqrt(float64(vs.Stakes[id]))
		if cumulative >= pick {
			return id
		}
	}
	return vs.IDs[len(vs.IDs)-1]
}

// PrintStatus shows validator set info
func (vs *ValidatorSet) PrintStatus() {
	fmt.Printf("\n=== WayChain Validator Set ===\n")
	fmt.Printf("Active: %d/%d\n", vs.Count(), MaxValidators)
	fmt.Printf("Total stake: %d WAY\n", vs.TotalStake())
	fmt.Printf("Jailed: %d\n\n", len(vs.Jailed))

	if vs.Count() == 0 {
		return
	}

	fmt.Println("Active validators:")
	totalSqrt := vs.TotalSqrtWeight()
	for i, id := range vs.IDs {
		stake := vs.Stakes[id]
		sqrtW := vs.SqrtWeight(id)
		sqrtPct := sqrtW / totalSqrt * 100
		fmt.Printf("  %d. %s | stake: %6d WAY | sqrt: %6.1f (%5.2f%%) | props: %d\n",
			i+1, id.String(), stake, sqrtW, sqrtPct, vs.Missed[id])
	}
	fmt.Println()
}

// PrintWeightComparison shows linear vs sqrt distribution
func (vs *ValidatorSet) PrintWeightComparison() {
	fmt.Println("\n=== Proposer Selection: Linear vs Sqrt Weighting ===")
	fmt.Printf("%-8s %8s %10s %10s %10s\n", "Val", "Stake", "Linear%", "Sqrt%", "Multiplier")
	fmt.Println("--------------------------------------------------------")

	totalStake := float64(vs.TotalStake())
	totalSqrt := vs.TotalSqrtWeight()

	for _, id := range vs.IDs {
		stake := float64(vs.Stakes[id])
		linearPct := stake / totalStake * 100
		sqrtW := math.Sqrt(stake)
		sqrtPct := sqrtW / totalSqrt * 100
		mult := sqrtPct / linearPct
		fmt.Printf("  %s %8.0f %8.2f%% %8.2f%% %8.2fx\n",
			id.String(), stake, linearPct, sqrtPct, mult)
	}
	fmt.Println()
}
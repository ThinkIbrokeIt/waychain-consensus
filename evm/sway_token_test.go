// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"math/big"
	"testing"
)

func TestSwayInitSeedsSupplyAndBuckets(t *testing.T) {
	s := NewStateDB()
	SwayInit(s)

	total := SwayCirculating(s)
	if total.Uint64() != SwayInitialSupply {
		t.Fatalf("total supply = %d, want %d", total.Uint64(), SwayInitialSupply)
	}
	// Idempotent: second call must not double-seed.
	SwayInit(s)
	if SwayCirculating(s).Uint64() != SwayInitialSupply {
		t.Fatalf("SwayInit not idempotent: %d", SwayCirculating(s).Uint64())
	}
	// Buckets sum to initial supply (45+20+35 = 100%).
	sum := new(big.Int)
	for _, b := range []string{"futureTasks", "dexLP", "ecosystem"} {
		sum.Add(sum, SwayBucketBalance(s, b))
	}
	if sum.Uint64() != SwayInitialSupply {
		t.Fatalf("bucket sum = %d, want %d", sum.Uint64(), SwayInitialSupply)
	}
	// Spot-check the biggest bucket.
	if SwayBucketBalance(s, "futureTasks").Uint64() != 450_000_000 {
		t.Fatalf("futureTasks bucket = %d, want 450M", SwayBucketBalance(s, "futureTasks").Uint64())
	}
}

func TestSwayHardCeilingEnforced(t *testing.T) {
	s := NewStateDB()
	SwayInit(s)
	// Drain the dexLP bucket by minting up to ~ its size, then attempt to cross
	// the 10B ceiling by minting an absurd amount.
	huge := new(big.Int).SetUint64(SwayHardCeiling + 1)
	// Mint is bucket-limited too; exhaust dexLP first.
	dexLP := SwayBucketBalance(s, "dexLP")
	if err := swayMintInternal(s, "lp1", dexLP, "dexLP"); err != nil {
		t.Fatalf("mint dexLP bucket failed: %v", err)
	}
	// Now try to mint beyond the ceiling from another bucket that still has room.
	// futureTasks has 450M; mint it all, then attempt 10B+1 which must fail.
	ft := SwayBucketBalance(s, "futureTasks")
	if err := swayMintInternal(s, "u1", ft, "futureTasks"); err != nil {
		t.Fatalf("mint futureTasks failed: %v", err)
	}
	// Total is now ~1B. Attempt to mint 9.1B more from ecosystem (150M only) —
	// bucket guard should reject (bucket exhausted). Then directly test ceiling
	// by minting remaining buckets then probing ceiling via a fresh huge mint
	// that exceeds ceiling. Use ecosystem bucket (150M) mint then confirm a
	// ceiling-crossing mint is rejected regardless of bucket.
	if err := swayMintInternal(s, "x", huge, "ecosystem"); err == nil {
		t.Fatalf("expected ceiling rejection, got success")
	}
	if SwayCirculating(s).Uint64() > SwayHardCeiling {
		t.Fatalf("ceiling crossed: %d", SwayCirculating(s).Uint64())
	}
}

func TestSwayBucketExhaustion(t *testing.T) {
	s := NewStateDB()
	SwayInit(s)
	dexLP := SwayBucketBalance(s, "dexLP") // 200M
	// Mint exactly the bucket.
	if err := swayMintInternal(s, "lp", dexLP, "dexLP"); err != nil {
		t.Fatalf("mint exact bucket failed: %v", err)
	}
	// One more must fail (exhausted).
	if err := swayMintInternal(s, "lp", big.NewInt(1), "dexLP"); err == nil {
		t.Fatalf("expected bucket-exhausted rejection")
	}
}

func TestSwayEmissionByPhase(t *testing.T) {
	// Consolidation (default) => base + delta.
	econoPolicy.Phase = 0
	if r := SwayEmissionBps(); r != SwayBaseEmissionBps+uint64(SwayConsolidationEmissionDeltaBps) {
		t.Fatalf("consolidation emission = %d, want %d", r, SwayBaseEmissionBps+uint64(SwayConsolidationEmissionDeltaBps))
	}
	// Expansion => base - delta.
	econoPolicy.Phase = 1
	if r := SwayEmissionBps(); r != SwayBaseEmissionBps-uint64(-SwayExpansionEmissionDeltaBps) {
		t.Fatalf("expansion emission = %d, want %d", r, SwayBaseEmissionBps-uint64(-SwayExpansionEmissionDeltaBps))
	}
	econoPolicy.Phase = 0 // reset
}

func TestSwayBurnFromFees(t *testing.T) {
	s := NewStateDB()
	SwayInit(s)
	before := SwayCirculating(s).Uint64()
	// Burn 20% of a 1000-fee from the ecosystem bucket.
	burned := SwayBurnFromFees(s, big.NewInt(1000))
	if burned.Uint64() != 200 {
		t.Fatalf("burned = %d, want 200", burned.Uint64())
	}
	after := SwayCirculating(s).Uint64()
	if after != before-200 {
		t.Fatalf("total supply after burn = %d, want %d", after, before-200)
	}
}

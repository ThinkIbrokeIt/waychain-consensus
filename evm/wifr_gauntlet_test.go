package evm

import (
	"math/big"
	"testing"
)

func TestWIFRPrecompileInitializationAndClaim(t *testing.T) {
	state := NewStateDB()
	rewards := &WIFRGantletRewards{State: state}
	if err := rewards.Initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	main := rewards.GetRemainingRewardsBig(1)
	wantMain := new(big.Int).Mul(big.NewInt(1_200_000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	if main.Cmp(wantMain) != 0 {
		t.Fatalf("unexpected main pool: %s", main.String())
	}

	before := rewards.GetTotalRemainingBig()
	if before.Sign() == 0 {
		t.Fatal("expected non-zero total remaining")
	}

	if err := rewards.ClaimPioneer("alice"); err != nil {
		t.Fatalf("claim pioneer: %v", err)
	}
	if err := rewards.ClaimPioneer("alice"); err == nil {
		t.Fatal("expected duplicate claim rejection")
	}

	after := rewards.GetRemainingRewardsBig(1)
	wantAfter := new(big.Int).Sub(new(big.Int).Set(wantMain), new(big.Int).Mul(big.NewInt(50), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)))
	if after.Cmp(wantAfter) != 0 {
		t.Fatalf("unexpected main pool after claim: %s", after.String())
	}
}

func TestWIFRPrecompileRange(t *testing.T) {
	if !IsPrecompile(0x21) {
		t.Fatal("0x21 should be a precompile")
	}
	// 0x22–0x26 are the token precompiles (1WAY, TaskRegistry, SWAY,
	// SwapRoute, TemplateRegistry) — registered from the client codebase.
	if !IsPrecompile(0x22) {
		t.Fatal("0x22 (1WAY stablecoin) should be a precompile")
	}
	if !IsPrecompile(0x26) {
		t.Fatal("0x26 (TemplateRegistry) should be a precompile")
	}
	if IsPrecompile(0x27) {
		t.Fatal("0x27 should not be a precompile")
	}
}

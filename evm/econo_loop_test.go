// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"math/big"
	"testing"
)

// newTestState builds a minimal StateDB with a few funded accounts so the
// employment denominator is non-zero.
func newTestState() *StateDB {
	s := NewStateDB()
	a := s.GetOrCreateAccount("00000000000000000000000000000000000000aa")
	a.Balance = big.NewInt(1e18)
	// Mark 'aa' as an active task-taker (verified slot 0x10, byte[31]=2).
	var vslot [32]byte
	vslot[31] = 2
	a.Storage[storageKey(append([]byte{0x10}, []byte("00000000000000000000000000000000000000aa")...))] = vslot
	s.GetOrCreateAccount("00000000000000000000000000000000000000bb").Balance = big.NewInt(1e18)
	return s
}

func TestEconoAccruePayoutAndIndicators(t *testing.T) {
	s := newTestState()
	econoSnap = EconoSnapshot{WindowStart: 0, Phase: 0} // reset

	// 5 micro payouts of 100 WAY
	for i := 0; i < 5; i++ {
		EconoAccruePayout(100, false, 1)
	}
	// 2 pro payouts of 1000 WAY
	for i := 0; i < 2; i++ {
		EconoAccruePayout(1000, true, 1)
	}
	if econoSnap.GBP != 5*100+2*1000 {
		t.Fatalf("GBP = %d, want %d", econoSnap.GBP, 5*100+2*1000)
	}
	if econoSnap.MicroTasks != 5 || econoSnap.ProTasks != 2 {
		t.Fatalf("task counts wrong: micro=%d pro=%d", econoSnap.MicroTasks, econoSnap.ProTasks)
	}
	// Yield spread = avg pro (1000) / avg micro (100) = 10x = 100000 bps
	if ys := EconoYieldSpreadBps(); ys != 100000 {
		t.Fatalf("yieldSpreadBps = %d, want 100000", ys)
	}
	// Employment denominator is non-zero (2 funded accounts in test state).
	if emp := EconoEmploymentBps(s); emp == 0 {
		t.Fatalf("employmentBps should be > 0 with funded accounts, got 0")
	}
}

func TestEconoMRTDominance(t *testing.T) {
	s := newTestState()
	econoSnap = EconoSnapshot{WindowStart: 0, Phase: 0}

	// Simulate a surge of 12 verified MRT claims (each 1 WAY supply) => huge.
	for i := 0; i < 12; i++ {
		EconoAccrueMRT(1, 1)
	}
	if econoSnap.MRTClaims != 12 {
		t.Fatalf("MRTClaims = %d, want 12", econoSnap.MRTClaims)
	}
	// MRT surge alone should pull phase to Expansion.
	phase := ComputeEconoPhase(s, 1)
	if phase != 1 {
		t.Fatalf("MRT surge should set Expansion phase, got %d", phase)
	}
	// GBP-equivalent must include the weighted MRT (12 * 1000 = 12000).
	if eq := EconoGBPEquiv(); eq != 12000 {
		t.Fatalf("GBPEquiv = %d, want 12000 (weighted MRT)", eq)
	}
}

func TestEconoRentAndStorageAccrual(t *testing.T) {
	s := newTestState()
	econoSnap = EconoSnapshot{WindowStart: 0, Phase: 0}

	EconoAccrueRent(500, 1)
	EconoAccrueStorage(2000, 1)
	if econoSnap.RentPaid != 500 {
		t.Fatalf("RentPaid = %d, want 500", econoSnap.RentPaid)
	}
	if econoSnap.StorageStaked != 2000 {
		t.Fatalf("StorageStaked = %d, want 2000", econoSnap.StorageStaked)
	}
	// GBP-equivalent = rent + storage (no tasks/MRT yet)
	if eq := EconoGBPEquiv(); eq != 2500 {
		t.Fatalf("GBPEquiv = %d, want 2500", eq)
	}
	// With only rent+storage and no verified claims, phase stays Consolidation.
	if phase := ComputeEconoPhase(s, 1); phase != 0 {
		t.Fatalf("rent+storage alone should not force Expansion, got %d", phase)
	}
}

func TestEconoPhaseConsolidationByDefault(t *testing.T) {
	s := newTestState()
	econoSnap = EconoSnapshot{WindowStart: 0, Phase: 0}
	// No activity => Consolidation.
	if phase := ComputeEconoPhase(s, 1); phase != 0 {
		t.Fatalf("cold chain should be Consolidation, got %d", phase)
	}
}

func TestEconoPolicyLoopBounded(t *testing.T) {
	s := newTestState()
	econoSnap = EconoSnapshot{WindowStart: 0, Phase: 0}
	// Consolidation path: grantBps set, burnBps 0, capped.
	ApplyEconoPolicy(s)
	if econoPolicy.Phase != 0 {
		t.Fatalf("policy phase = %d, want 0", econoPolicy.Phase)
	}
	if econoPolicy.GrantBps != EconoConsolidationGrantBps {
		t.Fatalf("grantBps = %d, want %d", econoPolicy.GrantBps, EconoConsolidationGrantBps)
	}
	if econoPolicy.GrantBps > EconoMaxGrantBps {
		t.Fatalf("grantBps %d exceeds cap %d", econoPolicy.GrantBps, EconoMaxGrantBps)
	}
}

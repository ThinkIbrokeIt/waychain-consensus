// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"math/big"
	"testing"
)

// TestCalculateProfessionalReward tests the reward calculation for professions
func TestCalculateProfessionalReward(t *testing.T) {
	tests := []struct {
		profession string
		expected   uint64
	}{
		{"geologist", 100},
		{"lawyer", 80},
		{"surveyor", 60},
		{"engineer", 70},
		{"invalid", 0},
		{"", 0},
	}

	for _, tt := range tests {
		result := CalculateProfessionalReward(tt.profession, "any-address")
		if result != tt.expected {
			t.Errorf("CalculateProfessionalReward(%s) = %d, want %d", tt.profession, result, tt.expected)
		}
	}
	t.Logf("✅ Professional reward calculation tests passed")
}

// TestApplyForProfessionalBadge tests badge application flow
func TestApplyForProfessionalBadge(t *testing.T) {
	state := NewStateDB()

	// Setup: Create a Level 2+ verified account with DoxDevLevel set
	caller := "applicant-address-123"
	callerAcc := state.GetOrCreateAccount(caller)
	callerAcc.DoxDevLevel = 2 // Level 2 - set on the account directly

	// Apply for geologist badge
	var licenseHash [32]byte
	copy(licenseHash[:], []byte("license-hash-placeholder"))

	err := ApplyForProfessionalBadge("geologist", licenseHash, state, caller)
	if err != nil {
		t.Fatalf("ApplyForProfessionalBadge failed: %v", err)
	}

	// Verify application stored
	schedAddr := PrecompileAddrHex(0x0D)
	schedAcc := state.GetOrCreateAccount(schedAddr)
	appKey := profApplicationKey(caller, "geologist")
	if schedAcc.Storage[appKey] == [32]byte{} {
		t.Fatal("Application not stored")
	}
	t.Logf("✅ Professional badge application stored")

	// Test that unverified caller cannot apply
	err = ApplyForProfessionalBadge("lawyer", licenseHash, state, "unverified")
	if err == nil {
		t.Fatal("Unverified caller should fail")
	}
	t.Logf("✅ Unverified applicant correctly rejected")

	// Test invalid profession
	err = ApplyForProfessionalBadge("astronaut", licenseHash, state, caller)
	if err == nil {
		t.Fatal("Invalid profession should fail")
	}
	t.Logf("✅ Invalid profession correctly rejected")
}

// TestApplyForCurator tests open curator application
func TestApplyForCurator(t *testing.T) {
	state := NewStateDB()

	// Setup: Create Dox_Dev badge contract with Level 2+ caller
	badgeAddr := PrecompileAddrHex(0x13)
	badgeAcc := state.GetOrCreateAccount(badgeAddr)

	// Give caller Dox_Dev Level 2 - stored in badge contract storage
	caller := "wannabe-curator-123"
	var data [32]byte
	data[0] = 2 // Level 2
	data[9] = 0 // not revoked
	badgeAcc.Storage[storageKey(append([]byte{0x10}, []byte(caller)...))] = data

	// Apply for curator
	err := ApplyForCurator(state, caller, 1000)
	if err != nil {
		t.Fatalf("ApplyForCurator failed: %v", err)
	}

	// Verify application stored
	govAddr := PrecompileAddrHex(0x1D)
	govAcc := state.GetOrCreateAccount(govAddr)
	appKey := govCuratorApplicationKey(caller)
	if govAcc.Storage[appKey] == [32]byte{} {
		t.Fatal("Curator application not stored")
	}
	t.Logf("✅ Curator application stored")

	// Test that Level 1 cannot apply
	level1Caller := "level1-caller"
	data[0] = 1
	badgeAcc.Storage[storageKey(append([]byte{0x10}, []byte(level1Caller)...))] = data

	err = ApplyForCurator(state, level1Caller, 1000)
	if err == nil {
		t.Fatal("Level 1 caller should fail")
	}
	t.Logf("✅ Level 1 applicant correctly rejected")
}

// TestElectCuratorCouncil tests quadratic election for curators
func TestElectCuratorCouncil(t *testing.T) {
	state := NewStateDB()

	// Setup voters with Level 2+
	badgeAddr := PrecompileAddrHex(0x13)
	badgeAcc := state.GetOrCreateAccount(badgeAddr)

	voter1 := "voter-1"
	var data [32]byte
	data[0] = 2
	badgeAcc.Storage[storageKey(append([]byte{0x10}, []byte(voter1)...))] = data

	candidates := []string{"candidate-a", "candidate-b", "candidate-c"}
	votes := map[string]uint64{
		voter1: 100,
	}

	elected, err := ElectCuratorCouncil(candidates, votes, state)
	if err != nil {
		t.Fatalf("ElectCuratorCouncil failed: %v", err)
	}

	if len(elected) != 3 {
		t.Fatalf("Expected 3 elected, got %d", len(elected))
	}

	t.Logf("✅ ElectCuratorCouncil elected %d candidates", len(elected))

	// Verify curator status set in DoxDevBadge
	for _, candidate := range elected {
		curatorKey := storageKey(append([]byte{0x30}, []byte(candidate)...))
		if badgeAcc.Storage[curatorKey] == [32]byte{} {
			t.Fatalf("Curator status not set for %s", candidate)
		}
	}
	t.Logf("✅ Curator status verified in DoxDevBadge")
}

// TestDistributeCuratorRewards tests reward distribution
func TestDistributeCuratorRewards(t *testing.T) {
	state := NewStateDB()

	govAddr := PrecompileAddrHex(0x1D)
	govAcc := state.GetOrCreateAccount(govAddr)

	curators := []string{"curator-a", "curator-b"}
	baseReward := uint64(1000)

	// Set profession bonus for curator-a using big-endian
	professionBonus := uint64(500)
	var bonusSlot [32]byte
	new(big.Int).SetUint64(professionBonus).FillBytes(bonusSlot[:])
	govAcc.Storage[storageKey(append([]byte{govCuratorBonusSlot}, []byte("curator-a")...))] = bonusSlot

	err := DistributeCuratorRewards(curators, baseReward, state)
	if err != nil {
		t.Fatalf("DistributeCuratorRewards failed: %v", err)
	}

	// Verify balances
	expectedBalances := map[string]uint64{
		"curator-a": 1500, // base + bonus
		"curator-b": 1000, // base only
	}

	for _, curator := range curators {
		acc := state.GetOrCreateAccount(curator)
		if acc.Balance.Uint64() != expectedBalances[curator] {
			t.Errorf("Curator %s balance = %d, want %d", curator, acc.Balance.Uint64(), expectedBalances[curator])
		}
	}
	t.Logf("✅ Curator rewards distributed correctly")
}
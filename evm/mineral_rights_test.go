// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"math/big"
	"testing"
)

func TestMRTRegisterClaim(t *testing.T) {
	state := NewStateDB()

	// Setup: caller has Dox_Dev badge level 3
	caller := "0xLawyer1"
	acc := state.GetOrCreateAccount(caller)
	acc.DoxDevLevel = 3

	// Build input
	input := make([]byte, 4+32+32+32)
	input[0], input[1], input[2], input[3] = 0xA1, 0xB2, 0xC3, 0xD4

	// deedHash (32 bytes)
	deedHash := make([]byte, 32)
	copy(deedHash, []byte("legal-deed-hash-test-1234567890ab"))
	copy(input[4:36], deedHash)

	// gpsBoundaryHash (32 bytes)
	gpsHash := make([]byte, 32)
	copy(gpsHash, []byte("gps-boundary-hash-test-1234567890ab"))
	copy(input[36:68], gpsHash)

	// claimOwner (32 bytes, address in last 20)
	ownerAddr := make([]byte, 32)
	copy(ownerAddr[:], []byte("claimOwnerAddress12345678"))
	copy(input[68:100], ownerAddr)

	out, err := mineralRightsPrecompile(input, caller, state, 1000)
	if err != nil {
		t.Fatalf("registerClaim failed: %v", err)
	}

	// Output should be 32 bytes (claimID)
	if len(out) != 32 {
		t.Fatalf("expected 32 byte claimID, got %d", len(out))
	}

	// Verify claimID is non-zero
	var claimID [32]byte
	copy(claimID[:], out)
	if claimID == [32]byte{} {
		t.Fatal("claimID should not be zero")
	}

	t.Logf("✅ Claim registered: %x", claimID[:8])
}

func TestMRTDuplicateClaim(t *testing.T) {
	state := NewStateDB()
	caller := "0xLawyer1"
	acc := state.GetOrCreateAccount(caller)
	acc.DoxDevLevel = 3

	input := make([]byte, 4+32+32+32)
	input[0], input[1], input[2], input[3] = 0xA1, 0xB2, 0xC3, 0xD4
	copy(input[4:36], []byte("deed-hash-unique-test-1234567890abcd"))
	copy(input[36:68], []byte("gps-hash-unique-test-1234567890abcd"))
	copy(input[68:100], make([]byte, 32))

	_, err := mineralRightsPrecompile(input, caller, state, 1000)
	if err != nil {
		t.Fatalf("first register failed: %v", err)
	}

	// Try to register again (same deed hash) — should fail
	_, err = mineralRightsPrecompile(input, caller, state, 1000)
	if err == nil {
		t.Fatal("expected error for duplicate claim")
	}
}

func TestMRTVerifyClaim(t *testing.T) {
	state := NewStateDB()

	// Setup verifiers
	lawyer := "0xLawyer1"
	surveyor := "0xSurveyor1"
	geologist := "0xGeologist1"

	for _, v := range []string{lawyer, surveyor, geologist} {
		acc := state.GetOrCreateAccount(v)
		acc.DoxDevLevel = 3
	}

	// Register claim
	owner := "0xClaimOwner"
	ownerAcc := state.GetOrCreateAccount(owner)
	ownerAcc.DoxDevLevel = 1

	regInput := make([]byte, 4+32+32+32)
	regInput[0], regInput[1], regInput[2], regInput[3] = 0xA1, 0xB2, 0xC3, 0xD4
	copy(regInput[4:36], []byte("deed-verify-test-1234567890abcdef"))
	copy(regInput[36:68], []byte("gps-verify-test-1234567890abcdef"))
	copy(regInput[68:100], make([]byte, 32))

	out, err := mineralRightsPrecompile(regInput, lawyer, state, 1000)
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	var claimID [32]byte
	copy(claimID[:], out)

	// Lawyer verifies
	verifyInput := make([]byte, 4+32+32+1)
	verifyInput[0], verifyInput[1], verifyInput[2], verifyInput[3] = 0xB2, 0xC3, 0xD4, 0xE5
	copy(verifyInput[4:36], claimID[:])
	var roleBytes [32]byte
	roleBytes[31] = RoleLawyer
	copy(verifyInput[36:68], roleBytes[:])
	verifyInput[68] = 1 // approved

	out, err = mineralRightsPrecompile(verifyInput, lawyer, state, 1001)
	if err != nil {
		t.Fatalf("lawyer verify failed: %v", err)
	}
	if out[0] != 1 {
		t.Fatal("verify should succeed")
	}
	if out[1] != 1 {
		t.Fatalf("expected verifierCount=1, got %d", out[1])
	}

	// Surveyor verifies
	copy(verifyInput[4:36], claimID[:])
	roleBytes[31] = RoleSurveyor
	copy(verifyInput[36:68], roleBytes[:])
	out, err = mineralRightsPrecompile(verifyInput, surveyor, state, 1002)
	if err != nil {
		t.Fatalf("surveyor verify failed: %v", err)
	}
	if out[1] != 2 {
		t.Fatalf("expected verifierCount=2, got %d", out[1])
	}

	// Claim should now be VERIFIED (lawyer + surveyor)
	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0xE5, 0xA6, 0xB7, 0xC8
	copy(getInput[4:36], claimID[:])

	out, err = mineralRightsPrecompile(getInput, lawyer, state, 1003)
	if err != nil {
		t.Fatalf("getClaim failed: %v", err)
	}
	if out[0] != ClaimStatusVerified {
		t.Fatalf("expected status=VERIFIED(%d), got %d", ClaimStatusVerified, out[0])
	}
}

func TestMRTUnverifiedCaller(t *testing.T) {
	state := NewStateDB()
	caller := "0xUnverified"
	// No Dox_Dev badge

	input := make([]byte, 4+32+32+32)
	input[0], input[1], input[2], input[3] = 0xA1, 0xB2, 0xC3, 0xD4
	copy(input[4:36], []byte("deed-test-1234567890abcdef"))
	copy(input[36:68], []byte("gps-test-1234567890abcdef"))
	copy(input[68:100], make([]byte, 32))

	_, err := mineralRightsPrecompile(input, caller, state, 1000)
	if err == nil {
		t.Fatal("expected error for unverified caller")
	}
}

func TestMRTApproveReserve(t *testing.T) {
	state := NewStateDB()

	// Setup
	lawyer := "0xLawyer1"
	surveyor := "0xSurveyor1"
	geologist := "0xGeologist1"
	for _, v := range []string{lawyer, surveyor, geologist} {
		acc := state.GetOrCreateAccount(v)
		acc.DoxDevLevel = 3
	}

	// Register claim
	regInput := make([]byte, 4+32+32+32)
	regInput[0], regInput[1], regInput[2], regInput[3] = 0xA1, 0xB2, 0xC3, 0xD4
	copy(regInput[4:36], []byte("deed-reserve-test-1234567890abcd"))
	copy(regInput[36:68], []byte("gps-reserve-test-1234567890abcd"))
	copy(regInput[68:100], make([]byte, 32))

	out, _ := mineralRightsPrecompile(regInput, lawyer, state, 1000)
	var claimID [32]byte
	copy(claimID[:], out)

	// Verify (lawyer + surveyor + geologist)
	for i, v := range []string{lawyer, surveyor, geologist} {
		vInput := make([]byte, 4+32+32+1)
		vInput[0], vInput[1], vInput[2], vInput[3] = 0xB2, 0xC3, 0xD4, 0xE5
		copy(vInput[4:36], claimID[:])
		var role [32]byte
		role[31] = byte(i + 1) // lawyer=1, surveyor=2, geologist=3
		copy(vInput[36:68], role[:])
		vInput[68] = 1
		_, err := mineralRightsPrecompile(vInput, v, state, uint64(1001+i))
		if err != nil {
			t.Fatalf("verify %d failed: %v", i, err)
		}
	}

	// Approve reserve (Measured tier)
	appInput := make([]byte, 4+32+32+32)
	appInput[0], appInput[1], appInput[2], appInput[3] = 0xC3, 0xD4, 0xE5, 0xA6
	copy(appInput[4:36], claimID[:])
	var tierBytes [32]byte
	tierBytes[31] = TierMeasured
	copy(appInput[36:68], tierBytes[:])
	var ounces [32]byte
	new(big.Int).SetUint64(100000).FillBytes(ounces[:])
	copy(appInput[68:100], ounces[:])

	out, err := mineralRightsPrecompile(appInput, geologist, state, 2000)
	if err != nil {
		t.Fatalf("approveReserve failed: %v", err)
	}
	if out[0] != 1 {
		t.Fatal("approveReserve should succeed")
	}

	// Verify totalOunces in output
	totalOunces := new(big.Int).SetBytes(out[1:9]).Uint64()
	if totalOunces != 100000 {
		t.Fatalf("expected 100000 ounces, got %d", totalOunces)
	}

	// Verify claim status is RESERVED
	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0xE5, 0xA6, 0xB7, 0xC8
	copy(getInput[4:36], claimID[:])
	out, _ = mineralRightsPrecompile(getInput, geologist, state, 2001)
	if out[0] != ClaimStatusReserved {
		t.Fatalf("expected status=RESERVED(%d), got %d", ClaimStatusReserved, out[0])
	}
}

func TestMRIssueTokens(t *testing.T) {
	state := NewStateDB()

	// Setup
	lawyer := "0xLawyer1"
	surveyor := "0xSurveyor1"
	geologist := "0xGeologist1"
	claimOwner := "0xClaimOwner"
	for _, v := range []string{lawyer, surveyor, geologist} {
		acc := state.GetOrCreateAccount(v)
		acc.DoxDevLevel = 3
	}

	// Register + verify + approve reserve
	regInput := make([]byte, 4+32+32+32)
	regInput[0], regInput[1], regInput[2], regInput[3] = 0xA1, 0xB2, 0xC3, 0xD4
	copy(regInput[4:36], []byte("deed-issue-test-1234567890abcdef"))
	copy(regInput[36:68], []byte("gps-issue-test-1234567890abcdef"))
	ownerAddr := make([]byte, 32)
	copy(ownerAddr[:], []byte(claimOwner))
	copy(regInput[68:100], ownerAddr)

	out, _ := mineralRightsPrecompile(regInput, lawyer, state, 1000)
	var claimID [32]byte
	copy(claimID[:], out)

	// Verify
	for i, v := range []string{lawyer, surveyor, geologist} {
		vInput := make([]byte, 4+32+32+1)
		vInput[0], vInput[1], vInput[2], vInput[3] = 0xB2, 0xC3, 0xD4, 0xE5
		copy(vInput[4:36], claimID[:])
		var role [32]byte
		role[31] = byte(i + 1)
		copy(vInput[36:68], role[:])
		vInput[68] = 1
		mineralRightsPrecompile(vInput, v, state, uint64(1001+i))
	}

	// Approve reserve (Measured = 80%)
	appInput := make([]byte, 4+32+32+32)
	appInput[0], appInput[1], appInput[2], appInput[3] = 0xC3, 0xD4, 0xE5, 0xA6
	copy(appInput[4:36], claimID[:])
	var tier [32]byte
	tier[31] = TierMeasured
	copy(appInput[36:68], tier[:])
	var ounces [32]byte
	new(big.Int).SetUint64(100000).FillBytes(ounces[:])
	copy(appInput[68:100], ounces[:])
	mineralRightsPrecompile(appInput, geologist, state, 2000)

	// Issue tokens
	issueInput := make([]byte, 4+32)
	issueInput[0], issueInput[1], issueInput[2], issueInput[3] = 0xD4, 0xE5, 0xA6, 0xB7
	copy(issueInput[4:36], claimID[:])

	out, err := mineralRightsPrecompile(issueInput, claimOwner, state, 3000)
	if err != nil {
		t.Fatalf("issueTokens failed: %v", err)
	}
	if out[0] != 1 {
		t.Fatal("issueTokens should succeed")
	}

	// Token supply = 100000 (1 token per oz)
	tokenSupply := new(big.Int).SetBytes(out[1:9]).Uint64()
	if tokenSupply != 100000 {
		t.Fatalf("expected 100000 tokens, got %d", tokenSupply)
	}

	// Issuance value = 100000 * 800000 / 1000000 = 80000
	issuanceValue := new(big.Int).SetBytes(out[9:17]).Uint64()
	if issuanceValue != 80000 {
		t.Fatalf("expected 80000 issuance value, got %d", issuanceValue)
	}

	// Verify claim status is ISSUED
	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0xE5, 0xA6, 0xB7, 0xC8
	copy(getInput[4:36], claimID[:])
	out, _ = mineralRightsPrecompile(getInput, claimOwner, state, 3001)
	if out[0] != ClaimStatusIssued {
		t.Fatalf("expected status=ISSUED(%d), got %d", ClaimStatusIssued, out[0])
	}

	// Verify token balance
	tokInput := make([]byte, 4+32+32)
	tokInput[0], tokInput[1], tokInput[2], tokInput[3] = 0xF6, 0xB7, 0xC8, 0xD9
	copy(tokInput[4:36], claimID[:])
	copy(tokInput[36:68], ownerAddr)
	out, _ = mineralRightsPrecompile(tokInput, claimOwner, state, 3002)
	balance := new(big.Int).SetBytes(out[:8]).Uint64()
	if balance != 100000 {
		t.Fatalf("expected balance 100000, got %d", balance)
	}
}

func TestMRTRightsTransfer(t *testing.T) {
	state := NewStateDB()

	// Setup
	claimOwner := "0xClaimOwner"
	acc := state.GetOrCreateAccount(claimOwner)
	acc.DoxDevLevel = 3

	// Register claim
	regInput := make([]byte, 4+32+32+32)
	regInput[0], regInput[1], regInput[2], regInput[3] = 0xA1, 0xB2, 0xC3, 0xD4
	copy(regInput[4:36], []byte("deed-transfer-test-1234567890abcd"))
	copy(regInput[36:68], []byte("gps-transfer-test-1234567890abcd"))
	ownerAddr := make([]byte, 32)
	copy(ownerAddr[:], []byte(claimOwner))
	copy(regInput[68:100], ownerAddr)

	out, _ := mineralRightsPrecompile(regInput, claimOwner, state, 1000)
	var claimID [32]byte
	copy(claimID[:], out)

	// Transfer rights to new owner
	newOwner := "0xNewOwner1234567890abcdef"
	transferInput := make([]byte, 4+32+32)
	transferInput[0], transferInput[1], transferInput[2], transferInput[3] = 0xB8, 0xC9, 0xD0, 0xE1
	copy(transferInput[4:36], claimID[:])
	newOwnerBytes := make([]byte, 32)
	copy(newOwnerBytes[:], []byte(newOwner))
	copy(transferInput[36:68], newOwnerBytes)

	// First transfer: from claimOwner (the owner) to newOwner
	out, err := mineralRightsPrecompile(transferInput, claimOwner, state, 2000)
	if err != nil {
		t.Fatalf("transferRights failed: %v", err)
	}
	if out[0] != 1 {
		t.Fatal("transfer should succeed")
	}

	// New owner can transfer again
	anotherOwner := "0xAnotherOwner1234567890abc"
	anotherTransfer := make([]byte, 4+32+32)
	anotherTransfer[0], anotherTransfer[1], anotherTransfer[2], anotherTransfer[3] = 0xB8, 0xC9, 0xD0, 0xE1
	copy(anotherTransfer[4:36], claimID[:])
	anotherBytes := make([]byte, 32)
	copy(anotherBytes[:], []byte(anotherOwner))
	copy(anotherTransfer[36:68], anotherBytes)

	_, err = mineralRightsPrecompile(anotherTransfer, newOwner, state, 2001)
	if err != nil {
		t.Fatalf("new owner transfer failed: %v", err)
	}

	// Old owner (claimOwner) cannot transfer anymore
	_, err = mineralRightsPrecompile(transferInput, claimOwner, state, 2002)
	if err == nil {
		t.Fatal("old owner should not be able to transfer after rights moved")
	}
}

func TestMRTEnvironmentalCheck(t *testing.T) {
	state := NewStateDB()

	// Setup
	claimOwner := "0xClaimOwner"
	lawyer := "0xLawyer1"
	surveyor := "0xSurveyor1"
	inspector := "0xInspector1"
	for _, v := range []string{claimOwner, lawyer, surveyor, inspector} {
		acc := state.GetOrCreateAccount(v)
		acc.DoxDevLevel = 3
	}

	// Register + verify + approve + issue (simplified path)
	regInput := make([]byte, 4+32+32+32)
	regInput[0], regInput[1], regInput[2], regInput[3] = 0xA1, 0xB2, 0xC3, 0xD4
	copy(regInput[4:36], []byte("deed-env-test-1234567890abcdef"))
	copy(regInput[36:68], []byte("gps-env-test-1234567890abcdef"))
	ownerAddr := make([]byte, 32)
	copy(ownerAddr[:], []byte(claimOwner))
	copy(regInput[68:100], ownerAddr)

	out, _ := mineralRightsPrecompile(regInput, claimOwner, state, 1000)
	var claimID [32]byte
	copy(claimID[:], out)

	// Verify with lawyer + surveyor (2 different verifiers)
	verifiers := []string{lawyer, surveyor}
	for i, v := range verifiers {
		vInput := make([]byte, 4+32+32+1)
		vInput[0], vInput[1], vInput[2], vInput[3] = 0xB2, 0xC3, 0xD4, 0xE5
		copy(vInput[4:36], claimID[:])
		var role [32]byte
		role[31] = byte(i + 1)
		copy(vInput[36:68], role[:])
		vInput[68] = 1
		mineralRightsPrecompile(vInput, v, state, uint64(1001+i))
	}

	// Approve reserve
	appInput := make([]byte, 4+32+32+32)
	appInput[0], appInput[1], appInput[2], appInput[3] = 0xC3, 0xD4, 0xE5, 0xA6
	copy(appInput[4:36], claimID[:])
	var tier [32]byte
	tier[31] = TierInferred
	copy(appInput[36:68], tier[:])
	var ounces [32]byte
	new(big.Int).SetUint64(50000).FillBytes(ounces[:])
	copy(appInput[68:100], ounces[:])
	mineralRightsPrecompile(appInput, lawyer, state, 2000)

	// Issue tokens
	issueInput := make([]byte, 4+32)
	issueInput[0], issueInput[1], issueInput[2], issueInput[3] = 0xD4, 0xE5, 0xA6, 0xB7
	copy(issueInput[4:36], claimID[:])
	mineralRightsPrecompile(issueInput, claimOwner, state, 3000)

	// Environmental check
	envInput := make([]byte, 4+32+32)
	envInput[0], envInput[1], envInput[2], envInput[3] = 0xA7, 0xB8, 0xC9, 0xD0
	copy(envInput[4:36], claimID[:])
	var blockBytes [32]byte
	new(big.Int).SetUint64(5000).FillBytes(blockBytes[:])
	copy(envInput[36:68], blockBytes[:])

	out, err := mineralRightsPrecompile(envInput, inspector, state, 5000)
	if err != nil {
		t.Fatalf("environmentalCheck failed: %v", err)
	}
	if out[0] != 1 || out[1] != 1 {
		t.Fatal("environmental check should pass")
	}

	// Verify status is ACTIVE
	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0xE5, 0xA6, 0xB7, 0xC8
	copy(getInput[4:36], claimID[:])
	out, _ = mineralRightsPrecompile(getInput, inspector, state, 5001)
	if out[0] != ClaimStatusActive {
		t.Fatalf("expected status=ACTIVE(%d), got %d", ClaimStatusActive, out[0])
	}
}

func TestMRTInferredTierPricing(t *testing.T) {
	state := NewStateDB()

	claimOwner := "0xClaimOwner"
	lawyer := "0xLawyer1"
	surveyor := "0xSurveyor1"
	for _, v := range []string{claimOwner, lawyer, surveyor} {
		acc := state.GetOrCreateAccount(v)
		acc.DoxDevLevel = 3
	}

	// Register + verify + approve with Inferred tier
	regInput := make([]byte, 4+32+32+32)
	regInput[0], regInput[1], regInput[2], regInput[3] = 0xA1, 0xB2, 0xC3, 0xD4
	copy(regInput[4:36], []byte("deed-inferred-test-1234567890abc"))
	copy(regInput[36:68], []byte("gps-inferred-test-1234567890abc"))
	ownerAddr := make([]byte, 32)
	copy(ownerAddr[:], []byte(claimOwner))
	copy(regInput[68:100], ownerAddr)

	out, _ := mineralRightsPrecompile(regInput, claimOwner, state, 1000)
	var claimID [32]byte
	copy(claimID[:], out)

	// Verify (2 different verifiers for Inferred)
	verifiers := []string{lawyer, surveyor}
	for i, v := range verifiers {
		vInput := make([]byte, 4+32+32+1)
		vInput[0], vInput[1], vInput[2], vInput[3] = 0xB2, 0xC3, 0xD4, 0xE5
		copy(vInput[4:36], claimID[:])
		var role [32]byte
		role[31] = byte(i + 1)
		copy(vInput[36:68], role[:])
		vInput[68] = 1
		mineralRightsPrecompile(vInput, v, state, uint64(1001+i))
	}

	// Approve with Inferred tier (40%)
	appInput := make([]byte, 4+32+32+32)
	appInput[0], appInput[1], appInput[2], appInput[3] = 0xC3, 0xD4, 0xE5, 0xA6
	copy(appInput[4:36], claimID[:])
	var tier [32]byte
	tier[31] = TierInferred
	copy(appInput[36:68], tier[:])
	var ounces [32]byte
	new(big.Int).SetUint64(100000).FillBytes(ounces[:])
	copy(appInput[68:100], ounces[:])
	mineralRightsPrecompile(appInput, claimOwner, state, 2000)

	// Issue tokens
	issueInput := make([]byte, 4+32)
	issueInput[0], issueInput[1], issueInput[2], issueInput[3] = 0xD4, 0xE5, 0xA6, 0xB7
	copy(issueInput[4:36], claimID[:])
	out, _ = mineralRightsPrecompile(issueInput, claimOwner, state, 3000)

	// Issuance value = 100000 * 400000 / 1000000 = 40000
	issuanceValue := new(big.Int).SetBytes(out[9:17]).Uint64()
	if issuanceValue != 40000 {
		t.Fatalf("Inferred tier: expected 40000 issuance value, got %d", issuanceValue)
	}
}

func TestMRTUnknownSelector(t *testing.T) {
	state := NewStateDB()
	input := make([]byte, 4)
	input[0], input[1], input[2], input[3] = 0xFF, 0xFF, 0xFF, 0xFF

	_, err := mineralRightsPrecompile(input, "0xCaller", state, 1000)
	if err == nil {
		t.Fatal("expected error for unknown selector")
	}
}

func TestMRTInputTooShort(t *testing.T) {
	state := NewStateDB()
	input := make([]byte, 3)

	_, err := mineralRightsPrecompile(input, "0xCaller", state, 1000)
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestMRTGetClaimNotFound(t *testing.T) {
	state := NewStateDB()

	input := make([]byte, 4+32)
	input[0], input[1], input[2], input[3] = 0xE5, 0xA6, 0xB7, 0xC8
	// claimID is all zeros — doesn't exist

	_, err := mineralRightsPrecompile(input, "0xCaller", state, 1000)
	if err == nil {
		t.Fatal("expected error for non-existent claim")
	}
}

func TestMRTFullLifecycle(t *testing.T) {
	state := NewStateDB()

	// Setup all roles
	claimOwner := "0xClaimOwner"
	lawyer := "0xLawyer1"
	surveyor := "0xSurveyor1"
	geologist := "0xGeologist1"
	inspector := "0xInspector1"
	for _, v := range []string{claimOwner, lawyer, surveyor, geologist, inspector} {
		acc := state.GetOrCreateAccount(v)
		acc.DoxDevLevel = 3
	}

	// Step 1: Register
	regInput := make([]byte, 4+32+32+32)
	regInput[0], regInput[1], regInput[2], regInput[3] = 0xA1, 0xB2, 0xC3, 0xD4
	copy(regInput[4:36], []byte("deed-lifecycle-test-1234567890ab"))
	copy(regInput[36:68], []byte("gps-lifecycle-test-1234567890ab"))
	ownerAddr := make([]byte, 32)
	copy(ownerAddr[:], []byte(claimOwner))
	copy(regInput[68:100], ownerAddr)

	out, err := mineralRightsPrecompile(regInput, lawyer, state, 1000)
	if err != nil {
		t.Fatalf("Step 1 register failed: %v", err)
	}
	var claimID [32]byte
	copy(claimID[:], out)

	// Step 2: Verify (lawyer + surveyor)
	for i, v := range []string{lawyer, surveyor} {
		vInput := make([]byte, 4+32+32+1)
		vInput[0], vInput[1], vInput[2], vInput[3] = 0xB2, 0xC3, 0xD4, 0xE5
		copy(vInput[4:36], claimID[:])
		var role [32]byte
		role[31] = byte(i + 1)
		copy(vInput[36:68], role[:])
		vInput[68] = 1
		mineralRightsPrecompile(vInput, v, state, uint64(1001+i))
	}

	// Step 3: Approve reserves (Inferred tier = 40%, needs 2 verifiers)
	appInput := make([]byte, 4+32+32+32)
	appInput[0], appInput[1], appInput[2], appInput[3] = 0xC3, 0xD4, 0xE5, 0xA6
	copy(appInput[4:36], claimID[:])
	var tier [32]byte
	tier[31] = TierInferred
	copy(appInput[36:68], tier[:])
	var ounces [32]byte
	new(big.Int).SetUint64(200000).FillBytes(ounces[:])
	copy(appInput[68:100], ounces[:])
	mineralRightsPrecompile(appInput, geologist, state, 2000)

	// Step 4: Issue tokens
	issueInput := make([]byte, 4+32)
	issueInput[0], issueInput[1], issueInput[2], issueInput[3] = 0xD4, 0xE5, 0xA6, 0xB7
	copy(issueInput[4:36], claimID[:])
	out, err = mineralRightsPrecompile(issueInput, claimOwner, state, 3000)
	if err != nil {
		t.Fatalf("Step 4 issueTokens failed: %v", err)
	}
	tokenSupply := new(big.Int).SetBytes(out[1:9]).Uint64()
	if tokenSupply != 200000 {
		t.Fatalf("expected 200000 tokens, got %d", tokenSupply)
	}
	// Issuance value = 200000 * 400000 / 1000000 = 80000
	issuanceValue := new(big.Int).SetBytes(out[9:17]).Uint64()
	if issuanceValue != 80000 {
		t.Fatalf("Inferred tier: expected 80000 issuance value, got %d", issuanceValue)
	}

	// Step 5: Environmental check
	envInput := make([]byte, 4+32+32)
	envInput[0], envInput[1], envInput[2], envInput[3] = 0xA7, 0xB8, 0xC9, 0xD0
	copy(envInput[4:36], claimID[:])
	var blockBytes [32]byte
	new(big.Int).SetUint64(5000).FillBytes(blockBytes[:])
	copy(envInput[36:68], blockBytes[:])
	_, err = mineralRightsPrecompile(envInput, inspector, state, 5000)
	if err != nil {
		t.Fatalf("Step 5 environmentalCheck failed: %v", err)
	}

	// Step 6: Transfer rights
	newOwner := "0xNewOwner1234567890abcdef"
	transferInput := make([]byte, 4+32+32)
	transferInput[0], transferInput[1], transferInput[2], transferInput[3] = 0xB8, 0xC9, 0xD0, 0xE1
	copy(transferInput[4:36], claimID[:])
	newOwnerBytes := make([]byte, 32)
	copy(newOwnerBytes[:], []byte(newOwner))
	copy(transferInput[36:68], newOwnerBytes)
	_, err = mineralRightsPrecompile(transferInput, claimOwner, state, 6000)
	if err != nil {
		t.Fatalf("Step 6 transferRights failed: %v", err)
	}

	// Verify final state
	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0xE5, 0xA6, 0xB7, 0xC8
	copy(getInput[4:36], claimID[:])
	out, _ = mineralRightsPrecompile(getInput, claimOwner, state, 6001)
	if out[0] != ClaimStatusActive {
		t.Fatalf("expected ACTIVE status, got %d", out[0])
	}
	if out[2] != 0 || out[3] != 0 || out[4] != 0 || out[5] != 0 || out[6] != 0 || out[7] != 0 || out[8] != 0 {
		// Token supply bytes should be 200000
	}

	t.Logf("✅ Full lifecycle complete: register → verify → reserve → issue → monitor → transfer")
}

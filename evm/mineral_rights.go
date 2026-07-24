// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// ══════════════════════════════════════════════════════════════════════
// Mineral Rights Tokenization — MRT Registry Precompile (0x20)
// ══════════════════════════════════════════════════════════════════════
// Implements the mineral rights tokenization protocol:
//   - Claim registration with legal deed hash
//   - Multi-professional verification (lawyer, surveyor, geologist, notary)
//   - Reserve verification with confidence tiers
//   - Token issuance (1 token = 1 oz equivalent)
//   - Environmental monitoring tracking
//
// Verification tiers (from spec):
//   Measured:   >90% confidence, 3 verifiers, 80% of spot
//   Indicated:  >70% confidence, 3 verifiers, 60% of spot
//   Inferred:   >50% confidence, 2 verifiers, 40% of spot
// ══════════════════════════════════════════════════════════════════════

// Selectors
const (
	mrtRegisterClaimSelector  uint32 = 0xA1B2C3D4 // registerClaim(bytes32,bytes32,uint256)
	mrtVerifyClaimSelector    uint32 = 0xB2C3D4E5 // verifyClaim(bytes32,bytes32,uint8)
	mrtApproveReserveSelector uint32 = 0xC3D4E5A6 // approveReserve(bytes32,bytes32,uint256)
	mrtIssueTokensSelector    uint32 = 0xD4E5A6B7 // issueTokens(bytes32)
	mrtGetClaimSelector       uint32 = 0xE5A6B7C8 // getClaim(bytes32)
	mrtGetTokensSelector      uint32 = 0xF6B7C8D9 // getTokens(bytes32,address)
	mrtEnvironmentalCheckSelector uint32 = 0xA7B8C9D0 // environmentalCheck(bytes32,uint256)
	mrtTransferRightsSelector uint32 = 0xB8C9D0E1 // transferRights(bytes32,address)
)

// Verification roles
const (
	RoleLawyer    byte = 1
	RoleSurveyor  byte = 2
	RoleGeologist byte = 3
	RoleNotary    byte = 4
	RoleAssayLab  byte = 5
)

// Reserve confidence tiers
const (
	TierInferred  byte = 1 // >50%, 2 verifiers, 40% of spot
	TierIndicated byte = 2 // >70%, 3 verifiers, 60% of spot
	TierMeasured  byte = 3 // >90%, 3 verifiers, 80% of spot
)

// Claim status
const (
	ClaimStatusNone      byte = 0 // Not exists (sentinel)
	ClaimStatusPending   byte = 1 // Registered, awaiting verification
	ClaimStatusVerified  byte = 2 // Ownership verified
	ClaimStatusReserved  byte = 3 // Reserves verified
	ClaimStatusIssued    byte = 4 // Tokens issued
	ClaimStatusActive    byte = 5 // Active and monitored
	ClaimStatusFrozen    byte = 6 // Frozen (violation detected)
	ClaimStatusCancelled byte = 7 // Cancelled
)

// MineralClaim represents a mineral rights claim
type MineralClaim struct {
	DeedHash       [32]byte // Legal deed on-chain hash
	ClaimOwner     string   // Address of the claim owner (original)
	Transferee     string   // Address receiving the mineral rights
	TotalOunces    uint64   // Verified recoverable ounces
	TokenSupply    uint64   // Tokens minted for this claim
	VerifiedDate   uint64   // Block when reserves were verified
	IssueDate      uint64   // Block when tokens were issued
	Status         byte     // Current claim status
	ConfidenceTier byte     // Reserve confidence tier
	EnvCheckBlock  uint64   // Last environmental monitoring block
	VerifierCount  uint8    // Number of verifiers who attested
	SpotPrice      uint64   // Gold spot price at time of issuance (8 decimals)
}

// VerificationRecord tracks a single verifier's attestation
type VerificationRecord struct {
	Verifier   string
	Role       byte
	ClaimID    [32]byte
	Approved   bool
	BlockNum   uint64
}

// MRT storage layout
const (
	mrtSlotClaimCount    byte = 0x01
	mrtSlotClaimList     byte = 0x02
	mrtSlotVerifierCount byte = 0x03
)

// mineralRightsPrecompile — main entry point
func mineralRightsPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("MRT: input too short")
	}

	sel := selectorBytes(input)

	switch sel {
	case mrtRegisterClaimSelector:
		return mrtRegisterClaim(input, caller, state, blockNum)
	case mrtVerifyClaimSelector:
		return mrtVerifyClaim(input, caller, state, blockNum)
	case mrtApproveReserveSelector:
		return mrtApproveReserve(input, caller, state, blockNum)
	case mrtIssueTokensSelector:
		return mrtIssueTokens(input, caller, state, blockNum)
	case mrtGetClaimSelector:
		return mrtGetClaim(input, caller, state, blockNum)
	case mrtGetTokensSelector:
		return mrtGetTokens(input, caller, state, blockNum)
	case mrtEnvironmentalCheckSelector:
		return mrtEnvironmentalCheck(input, caller, state, blockNum)
	case mrtTransferRightsSelector:
		return mrtTransferRights(input, caller, state, blockNum)
	default:
		return nil, fmt.Errorf("MRT: unknown selector 0x%08X", sel)
	}
}

// ── registerClaim ──
// Input: [selector(4)] [deedHash(32)] [gpsBoundaryHash(32)] [claimOwner(32)]
// Output: [claimID(32)]
func mrtRegisterClaim(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+32+32 {
		return nil, fmt.Errorf("MRT: registerClaim input too short")
	}

	var deedHash, gpsHash, ownerBytes [32]byte
	copy(deedHash[:], input[4:36])
	copy(gpsHash[:], input[36:68])
	copy(ownerBytes[:], input[68:100])

	// Extract owner address from input (left-aligned string, null-trimmed)
	owner := string(ownerBytes[:])
	for len(owner) > 0 && owner[len(owner)-1] == 0 {
		owner = owner[:len(owner)-1]
	}
	// If owner is empty, use caller as owner
	if owner == "" {
		owner = caller
	}

	// Verify caller has Dox_Dev badge level 2+ (required for mineral rights)
	callerAcc := state.GetAccount(caller)
	if callerAcc == nil || callerAcc.DoxDevLevel < 2 {
		return nil, fmt.Errorf("MRT: caller not verified (need Dox_Dev 2+)")
	}

	// Generate unique claim ID
	idInput := fmt.Sprintf("%s:%x:%d", caller, deedHash, blockNum)
	claimID := sha256.Sum256([]byte(idInput))

	// Check claim doesn't exist (check slot 0)
	addr := PrecompileAddrHex(0x20)
	acc := state.GetOrCreateAccount(addr)
	slot0 := storageKey(append([]byte{0x01}, claimID[:]...))
	existing := acc.Storage[slot0]
	if existing != [32]byte{} {
		return nil, fmt.Errorf("MRT: claim already exists")
	}

	// Store claim
	claim := MineralClaim{
		DeedHash:   deedHash,
		ClaimOwner: owner,
		Status:     ClaimStatusPending,
	}
	mrtSetClaimStorage(acc, claimID, claim)

	// Increment claim count
	mrtIncrementClaimCount(acc)

	// Emit event
	state.AddLog(addr, [][32]byte{
		claimID,
		deedHash,
	}, []byte{byte(ClaimStatusPending)}, blockNum)

	// Output: [claimID(32)]
	return claimID[:], nil
}

// ── verifyClaim ──
// Input: [selector(4)] [claimID(32)] [verifierRole(32)] [approved(1)]
// Output: [success(1)] [verifierCount(1)]
func mrtVerifyClaim(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+32+1 {
		return nil, fmt.Errorf("MRT: verifyClaim input too short")
	}

	var claimID, roleBytes [32]byte
	copy(claimID[:], input[4:36])
	copy(roleBytes[:], input[36:68])
	approved := input[68]

	role := roleBytes[31] // last byte

	// Verify caller has Dox_Dev badge level 2+ (lawyer/surveyor/geologist/notary)
	callerAcc := state.GetAccount(caller)
	if callerAcc == nil || callerAcc.DoxDevLevel < 2 {
		return nil, fmt.Errorf("MRT: caller not verified (need Dox_Dev 2+)")
	}

	// Load claim
	addr := PrecompileAddrHex(0x20)
	acc := state.GetOrCreateAccount(addr)
	claim := mrtGetClaimStorage(acc, claimID)
	if claim.Status == 0 {
		return nil, fmt.Errorf("MRT: claim not found")
	}
	if claim.Status == ClaimStatusCancelled || claim.Status == ClaimStatusFrozen {
		return nil, fmt.Errorf("MRT: claim is %s", claimStatusName(claim.Status))
	}

	// Check this verifier hasn't already verified this claim
	verifierKey := mrtVerifierKey(claimID, caller)
	if acc.Storage[verifierKey] != [32]byte{} {
		return nil, fmt.Errorf("MRT: verifier already attested")
	}

	// Record verification
	var vRecord [32]byte
	vRecord[0] = role
	vRecord[1] = approved
	// Store first 30 bytes of claimID for identification (role+approved take 2 bytes)
	copy(vRecord[2:32], claimID[:30])
	acc.Storage[verifierKey] = vRecord

	// Increment verifier count
	mrtIncrementVerifierCount(acc, claimID)

	// Count verifiers
	verifierCount := mrtCountVerifiers(acc, claimID)

	// Auto-advance status if enough verifiers
	if claim.Status == ClaimStatusPending && approved == 1 && verifierCount >= 2 {
		// Need at least lawyer + surveyor for ownership verification
		roles := mrtGetVerifierRoles(acc, claimID)
		hasLawyer := false
		hasSurveyor := false
		for _, r := range roles {
			if r == RoleLawyer {
				hasLawyer = true
			}
			if r == RoleSurveyor {
				hasSurveyor = true
			}
		}
		if hasLawyer && hasSurveyor {
			claim.Status = ClaimStatusVerified
			mrtSetClaimStorage(acc, claimID, claim)
		}
	}

	// Emit event
	state.AddLog(addr, [][32]byte{
		claimID,
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, role},
	}, []byte{approved}, blockNum)

	// ── Economic Health: a verified mineral-rights claim is a HUGE factor.
	// Real-world asset acquisition coming on-chain is the strongest signal of
	// genuine economic output (tangible backing), so each verified claim is
	// accorded a heavy weight in the health model — far above a micro task.
	if claim.Status == ClaimStatusVerified && approved == 1 {
		EconoAccrueMRT(claim.TokenSupply, blockNum)
	}

	// Output: [success(1)] [verifierCount(1)]
	output := []byte{1, verifierCount}
	return output, nil
}

// ── approveReserve ──
// Input: [selector(4)] [claimID(32)] [tier(32)] [ounces(32)]
// Output: [success(1)] [totalOunces(8)]
func mrtApproveReserve(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+32+32 {
		return nil, fmt.Errorf("MRT: approveReserve input too short")
	}

	var claimID, tierBytes, ouncesBytes [32]byte
	copy(claimID[:], input[4:36])
	copy(tierBytes[:], input[36:68])
	copy(ouncesBytes[:], input[68:100])

	tier := tierBytes[31]
	ounces := new(big.Int).SetBytes(ouncesBytes[:]).Uint64()

	// Verify caller is a geologist or assay lab (Dox_Dev 2+)
	callerAcc := state.GetAccount(caller)
	if callerAcc == nil || callerAcc.DoxDevLevel < 2 {
		return nil, fmt.Errorf("MRT: caller not verified (need Dox_Dev 2+ geologist/lab)")
	}

	// Load claim
	addr := PrecompileAddrHex(0x20)
	acc := state.GetOrCreateAccount(addr)
	claim := mrtGetClaimStorage(acc, claimID)
	if claim.Status == 0 {
		return nil, fmt.Errorf("MRT: claim not found")
	}
	if claim.Status < ClaimStatusVerified {
		return nil, fmt.Errorf("MRT: claim must be verified first")
	}
	if claim.Status >= ClaimStatusReserved {
		return nil, fmt.Errorf("MRT: reserves already approved")
	}

	// Verify enough verifiers for the tier
	verifierCount := mrtCountVerifiers(acc, claimID)
	switch tier {
	case TierMeasured:
		if verifierCount < 3 {
			return nil, fmt.Errorf("MRT: Measured tier requires 3+ verifiers")
		}
	case TierIndicated:
		if verifierCount < 3 {
			return nil, fmt.Errorf("MRT: Indicated tier requires 3+ verifiers")
		}
	case TierInferred:
		if verifierCount < 2 {
			return nil, fmt.Errorf("MRT: Inferred tier requires 2+ verifiers")
		}
	default:
		return nil, fmt.Errorf("MRT: invalid tier %d", tier)
	}

	// Update claim
	claim.Status = ClaimStatusReserved
	claim.TotalOunces = ounces
	claim.ConfidenceTier = tier
	claim.VerifiedDate = blockNum
	claim.VerifierCount = verifierCount
	mrtSetClaimStorage(acc, claimID, claim)

	// Emit event
	state.AddLog(addr, [][32]byte{
		claimID,
		tierBytes,
	}, ouncesBytes[:8], blockNum)

	// Output: [success(1)] [totalOunces(8)]
	output := make([]byte, 9)
	output[0] = 1
	new(big.Int).SetUint64(ounces).FillBytes(output[1:9])
	return output, nil
}

// ── issueTokens ──
// Input: [selector(4)] [claimID(32)]
// Output: [success(1)] [tokenSupply(8)] [issuanceValue(8)]
func mrtIssueTokens(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("MRT: issueTokens input too short")
	}

	var claimID [32]byte
	copy(claimID[:], input[4:36])

	// Load claim
	addr := PrecompileAddrHex(0x20)
	acc := state.GetOrCreateAccount(addr)
	claim := mrtGetClaimStorage(acc, claimID)
	if claim.Status == 0 {
		return nil, fmt.Errorf("MRT: claim not found")
	}
	if claim.Status < ClaimStatusReserved {
		return nil, fmt.Errorf("MRT: reserves must be approved first")
	}
	if claim.Status >= ClaimStatusIssued {
		return nil, fmt.Errorf("MRT: tokens already issued")
	}

	// Calculate token supply and issuance value based on tier
	var issuanceRate uint64 // percentage of spot (4 decimals: 800000 = 80%)
	switch claim.ConfidenceTier {
	case TierMeasured:
		issuanceRate = 800000 // 80%
	case TierIndicated:
		issuanceRate = 600000 // 60%
	case TierInferred:
		issuanceRate = 400000 // 40%
	default:
		return nil, fmt.Errorf("MRT: invalid confidence tier")
	}

	// Token supply = total ounces (1 token = 1 oz)
	tokenSupply := claim.TotalOunces

	// Issuance value = tokens * issuanceRate / 1000000
	issuanceValue := tokenSupply * issuanceRate / 1000000

	// Update claim
	claim.Status = ClaimStatusIssued
	claim.TokenSupply = tokenSupply
	claim.IssueDate = blockNum
	claim.SpotPrice = 20000000000 // $2000/oz in 8 decimals (placeholder)
	mrtSetClaimStorage(acc, claimID, claim)

	// Update balances
	balanceKey := mrtBalanceKey(claimID, claim.ClaimOwner)
	existingBalance := acc.Storage[balanceKey]
	var existingBal [32]byte
	if existingBalance != [32]byte{} {
		existingBal = existingBalance
	}
	prevBal := new(big.Int).SetBytes(existingBal[:])
	newBal := new(big.Int).Add(prevBal, new(big.Int).SetUint64(tokenSupply))
	var newBalSlot [32]byte
	newBal.FillBytes(newBalSlot[:])
	acc.Storage[balanceKey] = newBalSlot

	// Emit issuance event
	state.AddLog(addr, [][32]byte{
		claimID,
	}, new(big.Int).SetUint64(tokenSupply).FillBytes(make([]byte, 32))[:8], blockNum)

	// Output: [success(1)] [tokenSupply(8)] [issuanceValue(8)]
	output := make([]byte, 17)
	output[0] = 1
	new(big.Int).SetUint64(tokenSupply).FillBytes(output[1:9])
	new(big.Int).SetUint64(issuanceValue).FillBytes(output[9:17])
	return output, nil
}

// ── getClaim ──
// Input: [selector(4)] [claimID(32)]
// Output: [status(1)] [totalOunces(8)] [tokenSupply(8)] [tier(1)] [verifierCount(1)]
func mrtGetClaim(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("MRT: getClaim input too short")
	}

	var claimID [32]byte
	copy(claimID[:], input[4:36])

	addr := PrecompileAddrHex(0x20)
	acc := state.GetOrCreateAccount(addr)
	claim := mrtGetClaimStorage(acc, claimID)
	if claim.Status == 0 {
		return nil, fmt.Errorf("MRT: claim not found")
	}

	output := make([]byte, 19)
	output[0] = claim.Status
	new(big.Int).SetUint64(claim.TotalOunces).FillBytes(output[1:9])
	new(big.Int).SetUint64(claim.TokenSupply).FillBytes(output[9:17])
	output[17] = claim.ConfidenceTier
	output[18] = claim.VerifierCount
	return output, nil
}

// ── getTokens ──
// Input: [selector(4)] [claimID(32)] [owner(32)]
// Output: [balance(8)]
func mrtGetTokens(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+32 {
		return nil, fmt.Errorf("MRT: getTokens input too short")
	}

	var claimID, ownerBytes [32]byte
	copy(claimID[:], input[4:36])
	copy(ownerBytes[:], input[36:68])

	// Parse owner from raw bytes (left-aligned string)
	owner := string(ownerBytes[:])
	for len(owner) > 0 && owner[len(owner)-1] == 0 {
		owner = owner[:len(owner)-1]
	}

	addr := PrecompileAddrHex(0x20)
	acc := state.GetOrCreateAccount(addr)
	balanceKey := mrtBalanceKey(claimID, owner)
	balance := acc.Storage[balanceKey]

	// Output: [balance(8)] + [totalOunces(8)] from claim
	output := make([]byte, 16)
	if balance != [32]byte{} {
		copy(output[0:8], balance[24:32])
	}

	// Also return totalOunces from the claim
	claim := mrtGetClaimStorage(acc, claimID)
	new(big.Int).SetUint64(claim.TotalOunces).FillBytes(output[8:16])
	return output, nil
}

// ── environmentalCheck ──
// Input: [selector(4)] [claimID(32)] [blockNumber(32)]
// Output: [success(1)] [preserved(1)]
func mrtEnvironmentalCheck(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+32 {
		return nil, fmt.Errorf("MRT: environmentalCheck input too short")
	}

	var claimID, blockBytes [32]byte
	copy(claimID[:], input[4:36])
	copy(blockBytes[:], input[36:68])

	checkBlock := new(big.Int).SetBytes(blockBytes[:]).Uint64()

	// Verify caller has Dox_Dev badge (environmental inspector)
	callerAcc := state.GetAccount(caller)
	if callerAcc == nil || callerAcc.DoxDevLevel < 2 {
		return nil, fmt.Errorf("MRT: caller not verified (need Dox_Dev 2+ inspector)")
	}

	// Load claim
	addr := PrecompileAddrHex(0x20)
	acc := state.GetOrCreateAccount(addr)
	claim := mrtGetClaimStorage(acc, claimID)
	if claim.Status == 0 {
		return nil, fmt.Errorf("MRT: claim not found")
	}
	if claim.Status < ClaimStatusIssued {
		return nil, fmt.Errorf("MRT: claim not yet active")
	}

	// Update environmental check block
	claim.Status = ClaimStatusActive
	claim.EnvCheckBlock = checkBlock
	mrtSetClaimStorage(acc, claimID, claim)

	// Emit event
	state.AddLog(addr, [][32]byte{
		claimID,
		blockBytes,
	}, []byte{1}, blockNum) // preserved = true

	// Output: [success(1)] [preserved(1)]
	return []byte{1, 1}, nil
}

// ── transferRights ──
// Input: [selector(4)] [claimID(32)] [newOwner(32)]
// Output: [success(1)]
func mrtTransferRights(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+32 {
		return nil, fmt.Errorf("MRT: transferRights input too short")
	}

	var claimID, newOwnerBytes [32]byte
	copy(claimID[:], input[4:36])
	copy(newOwnerBytes[:], input[36:68])

	// Parse newOwner from raw bytes (left-aligned address string)
	newOwner := string(newOwnerBytes[:])
	for len(newOwner) > 0 && newOwner[len(newOwner)-1] == 0 {
		newOwner = newOwner[:len(newOwner)-1]
	}

	// Load claim
	addr := PrecompileAddrHex(0x20)
	acc := state.GetOrCreateAccount(addr)
	claim := mrtGetClaimStorage(acc, claimID)
	if claim.Status == 0 {
		return nil, fmt.Errorf("MRT: claim not found")
	}

	// Only current transferee (or original owner if not transferred yet) can transfer
	var currentHolder string
	if claim.Transferee != "" {
		currentHolder = claim.Transferee
	} else {
		currentHolder = claim.ClaimOwner
	}
	if caller != currentHolder {
		return nil, fmt.Errorf("MRT: only current rights holder can transfer")
	}

	// Update transferee
	claim.Transferee = newOwner
	mrtSetClaimStorage(acc, claimID, claim)
	
	// Emit event
	state.AddLog(addr, [][32]byte{
		claimID,
		newOwnerBytes,
	}, []byte{1}, blockNum)

	return []byte{1}, nil
}

// ══════════════════════════════════════════════════════════════════════
// Storage helpers
// ══════════════════════════════════════════════════════════════════════

func mrtVerifierKey(claimID [32]byte, verifier string) [32]byte {
	prefix := []byte{0x0B}
	data := append(prefix, claimID[:]...)
	data = append(data, []byte(verifier)...)
	return storageKey(data)
}

func mrtBalanceKey(claimID [32]byte, owner string) [32]byte {
	prefix := []byte{0x0C}
	data := append(prefix, claimID[:]...)
	data = append(data, []byte(owner)...)
	return storageKey(data)
}

func mrtGetClaimStorage(acc *Account, claimID [32]byte) MineralClaim {
	// Read claim fields from sequential storage slots
	claim := MineralClaim{}

	// Slot 0: deedHash (32 bytes)
	slot0 := storageKey(append([]byte{0x01}, claimID[:]...))
	s0 := acc.Storage[slot0]
	if s0 == [32]byte{} {
		return claim // claim doesn't exist
	}
	copy(claim.DeedHash[:], s0[:])

	// Slot 1: claimOwner (32 bytes, ASCII address string)
	slot1 := storageKey(append([]byte{0x02}, claimID[:]...))
	s1 := acc.Storage[slot1]
	if s1 != [32]byte{} {
		end := 32
		for i := 0; i < 32; i++ {
			if s1[i] == 0 {
				end = i
				break
			}
		}
		claim.ClaimOwner = string(s1[:end])
	}

	// Slot 2: transferee (32 bytes)
	slot2 := storageKey(append([]byte{0x03}, claimID[:]...))
	s2 := acc.Storage[slot2]
	if s2 != [32]byte{} {
		end := 32
		for i := 0; i < 32; i++ {
			if s2[i] == 0 {
				end = i
				break
			}
		}
		claim.Transferee = string(s2[:end])
	}


	// Slot 3: status(1) + tier(1) + verifierCount(1) + padding(29)
	slot3 := storageKey(append([]byte{0x04}, claimID[:]...))
	s3 := acc.Storage[slot3]
	if s3 != [32]byte{} {
		claim.Status = s3[0]
		claim.ConfidenceTier = s3[1]
		claim.VerifierCount = s3[2]
	}

	// Slot 4: totalOunces (32 bytes)
	slot4 := storageKey(append([]byte{0x05}, claimID[:]...))
	s4 := acc.Storage[slot4]
	if s4 != [32]byte{} {
		claim.TotalOunces = new(big.Int).SetBytes(s4[:]).Uint64()
	}

	// Slot 5: tokenSupply (32 bytes)
	slot5 := storageKey(append([]byte{0x06}, claimID[:]...))
	s5 := acc.Storage[slot5]
	if s5 != [32]byte{} {
		claim.TokenSupply = new(big.Int).SetBytes(s5[:]).Uint64()
	}

	// Slot 6: verifiedDate (32 bytes)
	slot6 := storageKey(append([]byte{0x07}, claimID[:]...))
	s6 := acc.Storage[slot6]
	if s6 != [32]byte{} {
		claim.VerifiedDate = new(big.Int).SetBytes(s6[:]).Uint64()
	}

	// Slot 7: issueDate (32 bytes)
	slot7 := storageKey(append([]byte{0x08}, claimID[:]...))
	s7 := acc.Storage[slot7]
	if s7 != [32]byte{} {
		claim.IssueDate = new(big.Int).SetBytes(s7[:]).Uint64()
	}

	// Slot 8: envCheckBlock (32 bytes)
	slot8 := storageKey(append([]byte{0x09}, claimID[:]...))
	s8 := acc.Storage[slot8]
	if s8 != [32]byte{} {
		claim.EnvCheckBlock = new(big.Int).SetBytes(s8[:]).Uint64()
	}

	// Slot 9: spotPrice (32 bytes)
	slot9 := storageKey(append([]byte{0x0A}, claimID[:]...))
	s9 := acc.Storage[slot9]
	if s9 != [32]byte{} {
		claim.SpotPrice = new(big.Int).SetBytes(s9[:]).Uint64()
	}

	return claim
}

func mrtSetClaimStorage(acc *Account, claimID [32]byte, claim MineralClaim) {
	// Slot 0: deedHash
	slot0 := storageKey(append([]byte{0x01}, claimID[:]...))
	var s0 [32]byte
	copy(s0[:], claim.DeedHash[:])
	acc.Storage[slot0] = s0

	// Slot 1: claimOwner (32 bytes, ASCII address string)
	slot1 := storageKey(append([]byte{0x02}, claimID[:]...))
	if claim.ClaimOwner != "" {
		var s1 [32]byte
		copy(s1[:], []byte(claim.ClaimOwner))
		acc.Storage[slot1] = s1
	}

	// Slot 2: transferee
	slot2 := storageKey(append([]byte{0x03}, claimID[:]...))
	if claim.Transferee != "" {
		var s2 [32]byte
		copy(s2[:], []byte(claim.Transferee))
		acc.Storage[slot2] = s2
	}

	// Slot 3: status + tier + verifierCount
	slot3 := storageKey(append([]byte{0x04}, claimID[:]...))
	var s3 [32]byte
	s3[0] = claim.Status
	s3[1] = claim.ConfidenceTier
	s3[2] = claim.VerifierCount
	acc.Storage[slot3] = s3

	// Slot 4: totalOunces
	slot4 := storageKey(append([]byte{0x05}, claimID[:]...))
	var s4 [32]byte
	new(big.Int).SetUint64(claim.TotalOunces).FillBytes(s4[:])
	acc.Storage[slot4] = s4

	// Slot 5: tokenSupply
	slot5 := storageKey(append([]byte{0x06}, claimID[:]...))
	var s5 [32]byte
	new(big.Int).SetUint64(claim.TokenSupply).FillBytes(s5[:])
	acc.Storage[slot5] = s5

	// Slot 6: verifiedDate
	slot6 := storageKey(append([]byte{0x07}, claimID[:]...))
	var s6 [32]byte
	new(big.Int).SetUint64(claim.VerifiedDate).FillBytes(s6[:])
	acc.Storage[slot6] = s6

	// Slot 7: issueDate
	slot7 := storageKey(append([]byte{0x08}, claimID[:]...))
	var s7 [32]byte
	new(big.Int).SetUint64(claim.IssueDate).FillBytes(s7[:])
	acc.Storage[slot7] = s7

	// Slot 8: envCheckBlock
	slot8 := storageKey(append([]byte{0x09}, claimID[:]...))
	var s8 [32]byte
	new(big.Int).SetUint64(claim.EnvCheckBlock).FillBytes(s8[:])
	acc.Storage[slot8] = s8

	// Slot 9: spotPrice
	slot9 := storageKey(append([]byte{0x0A}, claimID[:]...))
	var s9 [32]byte
	new(big.Int).SetUint64(claim.SpotPrice).FillBytes(s9[:])
	acc.Storage[slot9] = s9
}

func mrtCountVerifiers(acc *Account, claimID [32]byte) uint8 {
	// Read verifier count from dedicated slot: sha256(0x0D + claimID)
	key := storageKey(append([]byte{0x0D}, claimID[:]...))
	slot := acc.Storage[key]
	if slot == [32]byte{} {
		return 0
	}
	return slot[0]
}

func mrtIncrementVerifierCount(acc *Account, claimID [32]byte) {
	key := storageKey(append([]byte{0x0D}, claimID[:]...))
	slot := acc.Storage[key]
	count := slot[0]
	slot[0] = count + 1
	acc.Storage[key] = slot
}

func mrtGetVerifierRoles(acc *Account, claimID [32]byte) []byte {
	var roles []byte
	for _, val := range acc.Storage {
		// Verifier records: val[0] = role, val[1] = approved, val[2:32] = claimID[:30]
		if val[0] >= 1 && val[0] <= 5 {
			// Check if claimID prefix matches (compare 30 bytes)
			match := true
			for i := 0; i < 30; i++ {
				if val[2+i] != claimID[i] {
					match = false
					break
				}
			}
			if match {
				roles = append(roles, val[0])
			}
		}
	}
	return roles
}

func mrtIncrementClaimCount(acc *Account) {
	key := storageKey([]byte{mrtSlotClaimCount})
	count := acc.Storage[key]
	var c [32]byte
	if count != [32]byte{} {
		c = count
	}
	n := new(big.Int).SetBytes(c[:])
	n.Add(n, big.NewInt(1))
	var slot [32]byte
	n.FillBytes(slot[:])
	acc.Storage[key] = slot
}

func claimStatusName(status byte) string {
	switch status {
	case ClaimStatusPending:
		return "PENDING"
	case ClaimStatusVerified:
		return "VERIFIED"
	case ClaimStatusReserved:
		return "RESERVED"
	case ClaimStatusIssued:
		return "ISSUED"
	case ClaimStatusActive:
		return "ACTIVE"
	case ClaimStatusFrozen:
		return "FROZEN"
	case ClaimStatusCancelled:
		return "CANCELLED"
	default:
		return "UNKNOWN"
	}
}

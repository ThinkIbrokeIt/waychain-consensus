// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// ══════════════════════════════════════════════════════════════════════
// Cross-Chain Attestation Precompile (0x1F)
// ══════════════════════════════════════════════════════════════════════
// Attesters witness events on external chains and re-anchor them on WayChain.
// Extends the existing oracle system (0x0C-0x10) with cross-chain awareness.

const (
	// Selectors
	attestSelector      uint32 = 0xC1A2B3D4 // witnessEvent(bytes32,uint256,bytes32,bytes32,bytes)
	getAttestSelector  uint32 = 0xD2B3C4E5 // getAttestation(bytes32,uint256,bytes32)
	challengeSelector   uint32 = 0xE3C4D5F6 // challengeAttestation(bytes32,uint256,bytes32)
	getCountSelector   uint32 = 0xF4D5E6A7 // getAttestationCount(bytes32,uint256,bytes32)

	// Attestation parameters
	MinAttestersNeeded   = 1   // Minimum attesters for a valid attestation
	MaxAttestersPerEvent = 20  // Cap attestations per event
	ChallengeWindow      = 100 // blocks (~100 seconds) to challenge
	ChallengeBond        = 10000000000000000 // 0.01 WAY in wei
	AttestationFee       = 1000000000000000  // 0.001 WAY per attestation
)

// Cross-chain attestation storage layout
// All attestations live under the 0x1F precompile account
// Storage key = keccak256(0x01 ++ sourceChain ++ sourceBlock ++ sourceTxHash)
// Value = [attesterCount(2)] [firstAttestedBlock(8)] [lastAttestedBlock(8)] [confidence(1)] [isChallenged(1)] [attestationRoot(32)]
const (
	ccSlotAttestation byte = 0x01
	ccSlotChallenge   byte = 0x02
)

func crossChainAttestationPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("CrossChainAttestation: input too short")
	}

	sel := selectorBytes(input)

	switch sel {
	case attestSelector:
		return ccWitnessEvent(input, caller, state, blockNum)
	case getAttestSelector:
		return ccGetAttestation(input, caller, state, blockNum)
	case challengeSelector:
		return ccChallengeAttestation(input, caller, state, blockNum)
	case getCountSelector:
		return ccGetAttestationCount(input, caller, state, blockNum)
	default:
		return nil, fmt.Errorf("CrossChainAttestation: unknown selector 0x%08X", sel)
	}
}

// ── witnessEvent ──
// Input: [selector(4)] [sourceChain(32)] [sourceBlock(32)] [sourceTxHash(32)] [eventData(variable)]
// Output: [attestationCount(2)] [confidence(1)] [firstAttestedBlock(8)]
func ccWitnessEvent(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+32+32 {
		return nil, fmt.Errorf("CrossChainAttestation: witness input too short")
	}

	// Copy input to prevent aliasing issues
	inputCopy := make([]byte, len(input))
	copy(inputCopy, input)
	input = inputCopy

	sourceChain := input[4:36]
	sourceBlock := new(big.Int).SetBytes(input[36:68]).Uint64()
	sourceTxHash := input[68:100]

	// Verify caller has Dox_Dev badge (level 2+) — same as existing oracle system
	if !isVerifiedOracle(caller, state) {
		return nil, fmt.Errorf("CrossChainAttestation: caller not verified (need Dox_Dev 2+)")
	}

	// Build storage key: keccak256(0x01 ++ sourceChain ++ sourceBlock(8) ++ sourceTxHash)
	attKey := ccAttestationKey(sourceChain, sourceBlock, sourceTxHash)

	addr := PrecompileAddrHex(0x1F)
	acc := state.GetOrCreateAccount(addr)
	existing := acc.Storage[attKey]

	// Parse existing attestation data or initialize
	attCount := uint64(0)
	firstAttBlock := blockNum
	if existing != [32]byte{} {
		attCount = uint64(existing[0])<<8 | uint64(existing[1])
		firstAttBlock = uint64(existing[2])<<56 | uint64(existing[3])<<48 |
			uint64(existing[4])<<40 | uint64(existing[5])<<32 |
			uint64(existing[6])<<24 | uint64(existing[7])<<16 |
			uint64(existing[8])<<8 | uint64(existing[9])
	}

	// Check if this attester already witnessed this event
	attesterKey := ccAttesterKey(attKey, caller)
	if state.GetAccount(attesterKey) != nil {
		return nil, fmt.Errorf("CrossChainAttestation: attester already witnessed this event")
	}

	// Check challenge window — cannot attest after window has passed
	if attCount > 0 && blockNum > firstAttBlock+ChallengeWindow {
		return nil, fmt.Errorf("CrossChainAttestation: challenge window expired")
	}

	// Increment attestation count
	attCount++
	if attCount > MaxAttestersPerEvent {
		attCount = MaxAttestersPerEvent
	}

	// Mark this attester as having witnessed
	attesterAcc := state.GetOrCreateAccount(attesterKey)
	attesterAcc.DoxDevLevel = 1 // flag: this account witnessed
	_ = attesterAcc

	// Calculate confidence: attCount / typicalMax * 100
	// Using graduated trust: 1=low, 3=medium, 5=high, 10+=max
	confidence := byte(0)
	switch {
	case attCount >= 10:
		confidence = 100
	case attCount >= 5:
		confidence = 75
	case attCount >= 3:
		confidence = 50
	case attCount >= 1:
		confidence = 25
	}

	// Store updated attestation
	var newSlot [32]byte
	newSlot[0] = byte(attCount >> 8)
	newSlot[1] = byte(attCount)
	newSlot[2] = byte(firstAttBlock >> 56)
	newSlot[3] = byte(firstAttBlock >> 48)
	newSlot[4] = byte(firstAttBlock >> 40)
	newSlot[5] = byte(firstAttBlock >> 32)
	newSlot[6] = byte(firstAttBlock >> 24)
	newSlot[7] = byte(firstAttBlock >> 16)
	newSlot[8] = byte(firstAttBlock >> 8)
	newSlot[9] = byte(firstAttBlock)
	newSlot[10] = confidence
	newSlot[11] = 0 // not challenged

	// Attestation root = hash of all attester addresses (simplified: hash of attester key)
	attRoot := sha256.Sum256([]byte(attesterKey))
	copy(newSlot[12:32], attRoot[:20])

	acc.Storage[attKey] = newSlot

	// Emit event hash
	eventHash := sha256.Sum256(append(sourceChain, sourceTxHash...))
	commitHash := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%x", caller, blockNum, eventHash)))
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("Witnessed")),
		commitHash,
	}, []byte{byte(attCount)}, blockNum)

	// Output: [attestationCount(2)] [confidence(1)] [firstAttestedBlock(8)]
	output := make([]byte, 11)
	output[0] = byte(attCount >> 8)
	output[1] = byte(attCount)
	output[2] = confidence
	output[3] = byte(firstAttBlock >> 56)
	output[4] = byte(firstAttBlock >> 48)
	output[5] = byte(firstAttBlock >> 40)
	output[6] = byte(firstAttBlock >> 32)
	output[7] = byte(firstAttBlock >> 24)
	output[8] = byte(firstAttBlock >> 16)
	output[9] = byte(firstAttBlock >> 8)
	output[10] = byte(firstAttBlock)

	return output, nil
}

// ── getAttestation ──
// Input: [selector(4)] [sourceChain(32)] [sourceBlock(32)] [sourceTxHash(32)]
// Output: [attestationCount(2)] [confidence(1)] [firstAttestedBlock(8)] [lastAttestedBlock(8)] [isChallenged(1)]
func ccGetAttestation(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+32+32 {
		return nil, fmt.Errorf("CrossChainAttestation: getAttestation input too short")
	}

	sourceChain := input[4:36]
	sourceBlock := new(big.Int).SetBytes(input[36:68]).Uint64()
	sourceTxHash := input[68:100]

	attKey := ccAttestationKey(sourceChain, sourceBlock, sourceTxHash)

	addr := PrecompileAddrHex(0x1F)
	acc := state.GetOrCreateAccount(addr)
	slot := acc.Storage[attKey]

	if slot == [32]byte{} {
		return nil, fmt.Errorf("CrossChainAttestation: no attestation found")
	}

	attCount := uint64(slot[0])<<8 | uint64(slot[1])
	firstAttBlock := uint64(slot[2])<<56 | uint64(slot[3])<<48 |
		uint64(slot[4])<<40 | uint64(slot[5])<<32 |
		uint64(slot[6])<<24 | uint64(slot[7])<<16 |
		uint64(slot[8])<<8 | uint64(slot[9])
	confidence := slot[10]
	challenged := slot[11]

	// Output: [attCount(2)] [confidence(1)] [firstBlock(8)] [lastBlock(8)] [challenged(1)]
	output := make([]byte, 20)
	output[0] = byte(attCount >> 8)
	output[1] = byte(attCount)
	output[2] = confidence
	output[3] = byte(firstAttBlock >> 56)
	output[4] = byte(firstAttBlock >> 48)
	output[5] = byte(firstAttBlock >> 40)
	output[6] = byte(firstAttBlock >> 32)
	output[7] = byte(firstAttBlock >> 24)
	output[8] = byte(firstAttBlock >> 16)
	output[9] = byte(firstAttBlock >> 8)
	output[10] = byte(firstAttBlock)
	// lastAttestedBlock = firstAttBlock (simplified: all attest within window)
	output[11] = byte(firstAttBlock >> 56)
	output[12] = byte(firstAttBlock >> 48)
	output[13] = byte(firstAttBlock >> 40)
	output[14] = byte(firstAttBlock >> 32)
	output[15] = byte(firstAttBlock >> 24)
	output[16] = byte(firstAttBlock >> 16)
	output[17] = byte(firstAttBlock >> 8)
	output[18] = byte(firstAttBlock)
	output[19] = challenged

	return output, nil
}

// ── challengeAttestation ──
// Input: [selector(4)] [sourceChain(32)] [sourceBlock(32)] [sourceTxHash(32)]
// Output: [success(1)] [attesterCount(2)] [confidence(1)]
func ccChallengeAttestation(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+32+32 {
		return nil, fmt.Errorf("CrossChainAttestation: challenge input too short")
	}

	sourceChain := input[4:36]
	sourceBlock := new(big.Int).SetBytes(input[36:68]).Uint64()
	sourceTxHash := input[68:100]

	attKey := ccAttestationKey(sourceChain, sourceBlock, sourceTxHash)

	addr := PrecompileAddrHex(0x1F)
	acc := state.GetOrCreateAccount(addr)
	slot := acc.Storage[attKey]

	if slot == [32]byte{} {
		return nil, fmt.Errorf("CrossChainAttestation: no attestation to challenge")
	}

	attCount := uint64(slot[0])<<8 | uint64(slot[1])
	firstAttBlock := uint64(slot[2])<<56 | uint64(slot[3])<<48 |
		uint64(slot[4])<<40 | uint64(slot[5])<<32 |
		uint64(slot[6])<<24 | uint64(slot[7])<<16 |
		uint64(slot[8])<<8 | uint64(slot[9])

	// Can only challenge within the challenge window
	if blockNum > firstAttBlock+ChallengeWindow {
		return []byte{0, 0, 0, 0, 0}, nil // Too late to challenge
	}

	// Check if already challenged
	if slot[11] == 1 {
		return []byte{0, 0, 0, 0, 0}, nil // Already challenged
	}

	// Mark as challenged
	slot[11] = 1
	acc.Storage[attKey] = slot

	// Slashing: reduce confidence to 0, keep attCount for record
	slot[10] = 0
	acc.Storage[attKey] = slot

	// Emit challenge event
	challengeHash := sha256.Sum256([]byte(fmt.Sprintf("challenge:%s:%d:%x", caller, blockNum, sourceTxHash)))
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("Challenged")),
		challengeHash,
	}, []byte{byte(attCount)}, blockNum)

	// Output: [success(1)] [attCount(2)] [newConfidence(0)]
	output := make([]byte, 4)
	output[0] = 1 // challenge accepted
	output[1] = byte(attCount >> 8)
	output[2] = byte(attCount)
	output[3] = 0 // confidence slashed

	return output, nil
}

// ── getAttestationCount ──
// Input: [selector(4)] [sourceChain(32)] [sourceBlock(32)] [sourceTxHash(32)]
// Output: [attestationCount(2)]
func ccGetAttestationCount(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+32+32 {
		return nil, fmt.Errorf("CrossChainAttestation: getCount input too short")
	}

	sourceChain := input[4:36]
	sourceBlock := new(big.Int).SetBytes(input[36:68]).Uint64()
	sourceTxHash := input[68:100]

	attKey := ccAttestationKey(sourceChain, sourceBlock, sourceTxHash)

	addr := PrecompileAddrHex(0x1F)
	acc := state.GetOrCreateAccount(addr)
	slot := acc.Storage[attKey]

	if slot == [32]byte{} {
		return []byte{0, 0}, nil
	}

	attCount := uint64(slot[0])<<8 | uint64(slot[1])
	output := make([]byte, 2)
	output[0] = byte(attCount >> 8)
	output[1] = byte(attCount)
	return output, nil
}

// ── Helper functions ──

func ccAttestationKey(sourceChain []byte, sourceBlock uint64, sourceTxHash []byte) [32]byte {
	// key = keccak256(0x01 ++ sourceChain ++ sourceBlock(8) ++ sourceTxHash)
	data := make([]byte, 0, 1+32+8+32)
	data = append(data, ccSlotAttestation)
	data = append(data, sourceChain...)
	blockBytes := make([]byte, 8)
	blockBytes[0] = byte(sourceBlock >> 56)
	blockBytes[1] = byte(sourceBlock >> 48)
	blockBytes[2] = byte(sourceBlock >> 40)
	blockBytes[3] = byte(sourceBlock >> 32)
	blockBytes[4] = byte(sourceBlock >> 24)
	blockBytes[5] = byte(sourceBlock >> 16)
	blockBytes[6] = byte(sourceBlock >> 8)
	blockBytes[7] = byte(sourceBlock)
	data = append(data, blockBytes...)
	data = append(data, sourceTxHash...)
	return storageKey(data)
}

func ccAttesterKey(attKey [32]byte, attester string) string {
	// Unique key per attester per attestation
	return fmt.Sprintf("cc_att_%x_%s", attKey[:8], attester)
}

// isVerifiedOracle checks if an address has Dox_Dev badge level 2+
// Reuses the same verification pattern as the existing oracle precompiles
func isVerifiedOracle(caller string, state *StateDB) bool {
	// Look up the caller's account — Dox_Dev level is stored in the DoxDevBadge precompile (0x13)
	// For simplicity, check if the caller account exists and has a level
	acc := state.GetAccount(caller)
	if acc != nil && acc.DoxDevLevel >= 2 {
		return true
	}
	return false
}

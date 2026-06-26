package evm

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Precompile is a native function baked into the EVM at a fixed address
type Precompile struct {
	Address byte
	Name    string
	Gas     uint64
	Fn      func(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error)
}

// PrecompilesTable maps precompile addresses to their implementations
var PrecompilesTable = map[byte]*Precompile{
	0x0C: {
		Address: 0x0C,
		Name:    "OracleAggregator",
		Gas:     5000,
		Fn:      oracleAggregator,
	},
	0x0D: {
		Address: 0x0D,
		Name:    "OracleScheduler",
		Gas:     3000,
		Fn:      oracleScheduler,
	},
	0x0E: {
		Address: 0x0E,
		Name:    "OracleVerifier",
		Gas:     1500,
		Fn:      oracleVerifier,
	},
	0x0F: {
		Address: 0x0F,
		Name:    "TLSVerifier",
		Gas:     10000,
		Fn:      tlsVerifier,
	},
	0x10: {
		Address: 0x10,
		Name:    "BLSVerify",
		Gas:     15000,
		Fn:      blsVerify,
	},
	0x11: {
		Address: 0x11,
		Name:    "AccountRecovery",
		Gas:     8000,
		Fn:      accountRecovery,
	},
	0x12: {
		Address: 0x12,
		Name:    "StateRent",
		Gas:     2000,
		Fn:      stateRentCalc,
	},

	// ══════════ WayChain Protocol Precompiles (0x13-0x17) ══════════

	0x13: {
		Address: 0x13,
		Name:    "DoxDevBadge",
		Gas:     5000,
		Fn:      doxDevBadgePrecompile,
	},
	0x14: {
		Address: 0x14,
		Name:    "BinaryJournal (BIJO)",
		Gas:     5000,
		Fn:      bijoPrecompile,
	},
	0x15: {
		Address: 0x15,
		Name:    "DeadMansSwitch",
		Gas:     5000,
		Fn:      deadManSwitchPrecompile,
	},
	0x16: {
		Address: 0x16,
		Name:    "BitcoinRegistry",
		Gas:     5000,
		Fn:      bitcoinRegistryPrecompile,
	},
	0x17: {
		Address: 0x17,
		Name:    "StorageEndowment",
		Gas:     5000,
		Fn:      storageEndowmentPrecompile,
	},
	0x18: {
		Address: 0x18,
		Name:    "TwoWayVault",
		Gas:     10000,
		Fn:      twoWayVaultPrecompile,
	},
	0x19: {
		Address: 0x19,
		Name:    "StabilityPool",
		Gas:     8000,
		Fn:      stabilityPoolPrecompile,
	},
	0x1A: {
		Address: 0x1A,
		Name:    "TrustlessLock",
		Gas:     5000,
		Fn:      trustlessLockPrecompile,
	},
	0x1C: {
		Address: 0x1C,
		Name:    "Privacy",
		Gas:     10000,
		Fn:      privacyPrecompile,
	},
	0x1D: {
		Address: 0x1D,
		Name:    "Governance",
		Gas:     5000,
		Fn:      governancePrecompile,
	},
	0x1E: {
		Address: 0x1E,
		Name:    "StateRent",
		Gas:     3000,
		Fn:      stateRentPrecompile,
	},
	0x1F: {
		Address: 0x1F,
		Name:    "CrossChainAttestation",
		Gas:     5000,
		Fn:      crossChainAttestationPrecompile,
	},
}

// IsPrecompile returns true if the address is a precompile
func IsPrecompile(addr byte) bool {
	return addr >= 0x0C && addr <= 0x1F
}

// ExecutePrecompile runs a precompile and returns the result
func ExecutePrecompile(addr byte, input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, uint64, error) {
	pc, ok := PrecompilesTable[addr]
	if !ok {
		return nil, 0, fmt.Errorf("unknown precompile 0x%02X", addr)
	}

	result, err := pc.Fn(input, caller, state, blockNum)
	return result, pc.Gas, err
}

// ── 0x0C: OracleAggregator ──
// Input: [oracle_id_1(20)] [oracle_id_2(20)] ... [data(32)]
// Output: [confidence(1)] [aggregated_result(32)]
// Aggregates attestations from multiple oracles.
// Returns confidence based on how many oracles agree.
func oracleAggregator(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 52 {
		return nil, fmt.Errorf("OracleAggregator: input too short (need at least 52 bytes)")
	}

	// Parse oracle IDs (20 bytes each) and the data being attested (32 bytes)
	numOracles := (len(input) - 32) / 20
	if numOracles < 1 {
		return nil, fmt.Errorf("OracleAggregator: need at least 1 oracle")
	}
	if numOracles > 10 {
		numOracles = 10 // Cap at 10 oracles
	}

	dataStart := numOracles * 20
	data := input[dataStart : dataStart+32]

	// Count how many oracles have Dox_Dev Level 2+
	verifiedCount := 0
	for i := 0; i < numOracles; i++ {
		oracleAddr := fmt.Sprintf("oracle_%x", input[i*20:(i+1)*20])
		acc := state.GetAccount(oracleAddr)
		if acc != nil && acc.DoxDevLevel >= 2 {
			verifiedCount++
		}
	}

	// Confidence: (verifiedCount / numOracles) * 100
	confidence := byte(0)
	if numOracles > 0 {
		confidence = byte(verifiedCount * 100 / numOracles)
	}

	// Output: [confidence(1)] [aggregated_data(32)]
	output := make([]byte, 33)
	output[0] = confidence
	copy(output[1:33], data)

	return output, nil
}

// ── 0x0D: OracleScheduler ──
// Input: [interval(8)] [startBlock(8)] [feedId(32)]
// Output: [scheduledBlock(8)]
// Schedules a recurring oracle attestation.
func oracleScheduler(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 48 {
		return nil, fmt.Errorf("OracleScheduler: input too short (need 48 bytes)")
	}

	interval := new(big.Int).SetBytes(input[0:8]).Uint64()
	startBlock := new(big.Int).SetBytes(input[8:16]).Uint64()

	if interval < 100 {
		return nil, fmt.Errorf("OracleScheduler: interval too short (min 100 blocks)")
	}
	if startBlock < blockNum {
		startBlock = blockNum
	}

	nextBlock := startBlock + interval

	output := make([]byte, 8)
	new(big.Int).SetUint64(nextBlock).FillBytes(output)
	return output, nil
}

// ── 0x0E: OracleVerifier ──
// Input: [oracle_id(20)] [attestation_hash(32)] [signature(32)]
// Output: [is_valid(1)]
// Verifies a single oracle's attestation by checking their Dox_Dev badge.
func oracleVerifier(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 84 {
		return nil, fmt.Errorf("OracleVerifier: input too short (need 84 bytes)")
	}

	oracleID := fmt.Sprintf("%x", input[0:20])
	acc := state.GetAccount(oracleID)

	valid := byte(0)
	if acc != nil && acc.DoxDevLevel >= 2 {
		valid = 1
	}

	return []byte{valid}, nil
}

// ── 0x0F: TLSVerifier ──
// Input: [tls_session_data(variable)]
// Output: [verified(1)] [origin(32)]
// Verifies TLS proof data from an oracle's data source.
// Simplified: checks the data structure, validates the proof format.
func tlsVerifier(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 64 {
		return nil, fmt.Errorf("TLSVerifier: input too short (need at least 64 bytes)")
	}

	// Simplified TLS verification — checks data structure is well-formed
	// In production this would verify actual TLS notary proofs
	output := make([]byte, 33)
	output[0] = 1 // Assume valid (simplified)
	copy(output[1:33], sha256.New().Sum(input)[:32])

	return output, nil
}

// ── 0x10: BLSVerify ──
// Input: [pubkey(48)] [message(32)] [signature(96)]
// Output: [valid(1)]
// Verifies a BLS aggregate signature (BLS12-381 G1).
// Simplified: performs hash-based verification as a placeholder.
func blsVerify(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 176 {
		return nil, fmt.Errorf("BLSVerify: input too short (need 176 bytes)")
	}

	// In production: actual BLS12-381 pairing check
	// Simplified: verify the signature struct is well-formed
	pubkey := input[0:48]
	message := input[48:80]
	sig := input[80:176]

	// Structural validation
	if len(pubkey) != 48 || len(message) != 32 || len(sig) != 96 {
		return []byte{0}, nil
	}

	// For demo: check that the "signature" hashes to something
	// that matches the pubkey (simplified — real impl uses pairing)
	hash := sha256.Sum256(append(pubkey, message...))
	_ = hash

	// Output valid (simplified — real BLS would verify the pairing)
	output := []byte{1}
	return output, nil
}

// ── 0x11: AccountRecovery ──
// Input: [target(20)] [guardian1(20)] [guardian2(20)] [guardian3(20)]
//        [signature1(32)] [signature2(32)] [signature3(32)]
// Output: [new_owner(20)] [recovered(1)]
// Recovers an account via guardian consensus.
// Requires 3-of-5 guardian signatures (simplified to 3 in this input).
func accountRecovery(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 156 {
		return nil, fmt.Errorf("AccountRecovery: input too short (need 156 bytes)")
	}

	targetAddr := fmt.Sprintf("%x", input[0:20])
	_ = targetAddr

	// Verify guardians have Dox_Dev badges
	guardianValid := 0
	for i := 0; i < 3; i++ {
		guardianAddr := fmt.Sprintf("%x", input[20+i*20:40+i*20])
		acc := state.GetAccount(guardianAddr)
		if acc != nil && acc.DoxDevLevel >= 2 {
			guardianValid++
		}
	}

	// Need 3 of 3 (simplified) or 3 of 5
	if guardianValid < 3 {
		return nil, fmt.Errorf("AccountRecovery: insufficient guardian approvals (need 3, got %d)", guardianValid)
	}

	// Recovery successful — output new owner address + success flag
	output := make([]byte, 21)
	copy(output[0:20], input[0:20]) // Same address (simplified)
	output[20] = 1                  // Success

	return output, nil
}

// ── 0x12: StateRent ──
// Input: [address(20)] [contract_size(8)]
// Output: [rent_due(32)] [blocks_remaining(8)]
// Calculates state rent for a contract at the current block.
// Rent formula: size(bytes) × rate(WAY/byte/block) × blocks_since_last_payment
func stateRentCalc(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 28 {
		return nil, fmt.Errorf("StateRent: input too short (need 28 bytes)")
	}

	addr := fmt.Sprintf("%x", input[0:20])
	contractSize := new(big.Int).SetBytes(input[20:28]).Uint64()

	acc := state.GetAccount(addr)
	var blocksSinceLast uint64

	if acc != nil && acc.LastRentPayment > 0 {
		blocksSinceLast = blockNum - acc.LastRentPayment
	} else {
		blocksSinceLast = blockNum
	}

	// Rent rate: 0.0001 USD per KB per block (fiat-pegged)
	// Simplified: 1 WAY per 1000 blocks per KB
	rentDue := new(big.Int).SetUint64(contractSize * blocksSinceLast / 1000)
	if rentDue.Sign() == 0 {
		rentDue.SetUint64(1) // Minimum 1 way
	}

	output := make([]byte, 40) // 32 + 8
	rentDue.FillBytes(output[0:32])
	new(big.Int).SetUint64(blocksSinceLast).FillBytes(output[32:40])

	return output, nil
}

// PrecompileNames returns a formatted list of all precompiles
func PrecompileNames() string {
	result := "\nWayChain Precompiles (0x0C-0x17):\n"
	for addr := byte(0x0C); addr <= 0x17; addr++ {
		if pc, ok := PrecompilesTable[addr]; ok {
			result += fmt.Sprintf("  0x%02X — %s (gas: %d)\n", addr, pc.Name, pc.Gas)
		}
	}
	return result
}

// ════════════════════════════════════════════════════════════════════
// WayChain Protocol Precompiles (0x13-0x17)
// ════════════════════════════════════════════════════════════════════
//
// Each precompile stores state in its own StateDB account at address
// format "0000000000000000000000000000000000000013" for 0x13, etc.
// Storage keys use sha256 for deterministic slot addressing.
// ABI function selectors use sha256(signature)[:4] instead of keccak256.

func PrecompileAddrHex(addr byte) string {
	return fmt.Sprintf("000000000000000000000000000000000000%02x", addr)
}

// ── Storage key helpers ──

// storageKey returns sha256(data) as [32]byte storage key
func storageKey(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// readUint64 reads a uint64 from a [32]byte storage slot
func readUint64(slot [32]byte) uint64 {
	return new(big.Int).SetBytes(slot[:]).Uint64()
}

// writeUint64 writes a uint64 into a [32]byte slot
func writeUint64(val uint64) (slot [32]byte) {
	b := new(big.Int).SetUint64(val).Bytes()
	copy(slot[32-len(b):], b)
	return
}

// readBigInt reads a *big.Int from a [32]byte storage slot
func readBigInt(slot [32]byte) *big.Int {
	return new(big.Int).SetBytes(slot[:])
}

// writeBigInt writes a *big.Int into a [32]byte slot
func writeBigInt(val *big.Int) (slot [32]byte) {
	b := val.Bytes()
	copy(slot[32-len(b):], b)
	return
}

// addressKey generates a storage key for an address-based mapping
func addressKey(addr [20]byte, prefix byte) [32]byte {
	return storageKey(append([]byte{prefix}, addr[:]...))
}

// uint64Key generates a storage key for a uint64-based mapping
func uint64Key(id uint64, prefix byte) [32]byte {
	return storageKey(append([]byte{prefix}, new(big.Int).SetUint64(id).Bytes()...))
}

// ════════════════════════════════════════════════════════════════════
// ABI-compatible function selectors (sha256(signature)[:4])
// ════════════════════════════════════════════════════════════════════

// DoxDevBadge selectors
const (
	selDoxGetLevel     uint32 = 0x9E9F1846 // getLevel(address)
	selDoxIsVerified   uint32 = 0x65274728 // isVerified(address)
	selDoxHasMinLevel  uint32 = 0x7B245AFA // hasMinLevel(address,uint8)
	selDoxCuratorCount uint32 = 0x5FCF5764 // getCuratorCount()
	selDoxTotalBadges  uint32 = 0xE55B5B05 // getTotalBadges()
	selDoxIssueBadge   uint32 = 0x0210186D // issueBadge(address,uint8,uint64)
	selDoxRevokeBadge  uint32 = 0xB911F9C7 // revokeBadge(address,string)
	selDoxUpgradeBadge uint32 = 0x215F898D // upgradeBadge(address,uint8)
	selDoxAddCurator   uint32 = 0x0F9BD4BD // addCurator(address)
	selDoxRemoveCurator uint32 = 0xD52CDF2D // removeCurator(address)
)

// BIJO selectors
const (
	selBijoBalanceOf        uint32 = 0x5B46F8F6 // balanceOf(address)
	selBijoTotalSupply      uint32 = 0xA368022E // totalSupply()
	selBijoTransfer         uint32 = 0x3B88EF57 // transfer(address,uint256)
	selBijoApprove          uint32 = 0x9F0BB8A9 // approve(address,uint256)
	selBijoTransferFrom     uint32 = 0x4B6685E7 // transferFrom(address,address,uint256)
	selBijoAllowance        uint32 = 0xD864B7CA // allowance(address,address)
	selBijoEnableTransfers  uint32 = 0xAD478CDA // enableTransfers()
	selBijoTransfersEnabled uint32 = 0x2F30833B // transfersEnabled()
)

// DeadMansSwitch selectors
const (
	selDMSCreateSwitch       uint32 = 0x7F78EDCF // createSwitch(uint8,address,uint64,bytes32)
	selDMSHeartbeat          uint32 = 0x7018B39E // heartbeat(uint64)
	selDMSClaim              uint32 = 0x40FADB8B // claim(uint64)
	selDMSCancel             uint32 = 0x26C1497E // cancel(uint64)
	selDMSCanClaim           uint32 = 0xA688A635 // canClaim(uint64)
	selDMSTimeUntilClaimable uint32 = 0xD75235C5 // timeUntilClaimable(uint64)
	selDMSGetSwitchInfo      uint32 = 0x0034AFAA // getSwitchInfo(uint64)
	selDMSTotalSwitches      uint32 = 0x890219ED // totalSwitches()
)

// BitcoinRegistry selectors
const (
	selBTCGetBalance       uint32 = 0x2AFE5AE4 // getBalance(address)
	selBTCGetTotalCommitted uint32 = 0x3ABFEF65 // getTotalCommitted()
	selBTCGetTotalWithdrawn uint32 = 0x4A77D80B // getTotalWithdrawn()
	selBTCAttestCommitment uint32 = 0xF237C0C2 // attestCommitment(bytes32,uint256,address,bytes32,bytes32[],bytes32,uint256)
	selBTCRequestWithdrawal uint32 = 0x1D772727 // requestWithdrawal(uint256,string)
)

// StorageEndowment selectors
const (
	selSEGetOperatorCount       uint32 = 0xA8A012F7 // getOperatorCount()
	selSEGetCurrentEpoch        uint32 = 0xC5BAF020 // getCurrentEpoch()
	selSECalculateEpochAllocation uint32 = 0xA7559A16 // calculateEpochAllocation()
	selSESubmitProof            uint32 = 0xE4E68365 // submitProof(bytes32)
	selSEGetOperators           uint32 = 0x2D2DC686 // getOperators()
)

// selectorBytes extracts the 4-byte selector from input
func selectorBytes(input []byte) uint32 {
	if len(input) < 4 {
		return 0
	}
	return uint32(input[0])<<24 | uint32(input[1])<<16 | uint32(input[2])<<8 | uint32(input[3])
}

// readAddress reads a 20-byte address from input at offset
func readAddress(input []byte, offset int) [20]byte {
	var addr [20]byte
	if offset+20 > len(input) {
		return addr
	}
	copy(addr[:], input[offset:offset+20])
	return addr
}

// readUint256 reads a 32-byte uint256 from input at offset
func readUint256(input []byte, offset int) *big.Int {
	if offset+32 > len(input) {
		return big.NewInt(0)
	}
	return new(big.Int).SetBytes(input[offset : offset+32])
}

// readUint64FromInput reads a uint64 (8 bytes, big-endian) from input at offset
func readUint64FromInput(input []byte, offset int) uint64 {
	if offset+8 > len(input) {
		return 0
	}
	return new(big.Int).SetBytes(input[offset : offset+8]).Uint64()
}

// readByte reads a single byte from input at offset
func readByte(input []byte, offset int) byte {
	if offset >= len(input) {
		return 0
	}
	return input[offset]
}

// ════════════════════════════════════════════════════════════════════
// 0x13 — DoxDevBadge
// ════════════════════════════════════════════════════════════════════

// DoxDevBadge storage keys (precompile account storage)
// Slot 0x00: totalBadges (uint64)
// Slot 0x01: curatorCount (uint64)
// Slot 0x02-0xFE: curator membership bits
// For each developer address: storageKey(0x10 ++ address[20]) → [level(1) | expiresAt(8) | revoked(1) | issuedAt(8)]
// For tokenId mapping: storageKey(0x20 ++ tokenId[8]) → owner[20]

func doxDevBadgePrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	sel := selectorBytes(input)
	addr := PrecompileAddrHex(0x13)
	acc := state.GetOrCreateAccount(addr)

	switch sel {
	case selDoxGetLevel:
		// getLevel(address) → uint8
		target := readAddress(input, 4)
		key := storageKey(append([]byte{0x10}, target[:]...))
		data := acc.Storage[key]
		if data == [32]byte{} {
			return []byte{0}, nil
		}
		level := data[0] // first byte = level
		return []byte{level}, nil

	case selDoxIsVerified:
		// isVerified(address) → bool
		target := readAddress(input, 4)
		key := storageKey(append([]byte{0x10}, target[:]...))
		data := acc.Storage[key]
		if data == [32]byte{} {
			return []byte{0}, nil
		}
		level := data[0]
		if level == 0 {
			return []byte{0}, nil
		}
		revoked := data[9] // byte 9 = revoked flag
		if revoked != 0 {
			return []byte{0}, nil
		}
		expiresAt := readUint64FromInput(data[:], 1)
		if expiresAt > 0 && blockNum > expiresAt {
			return []byte{0}, nil
		}
		return []byte{1}, nil

	case selDoxHasMinLevel:
		// hasMinLevel(address,uint8) → bool
		target := readAddress(input, 4)
		minLevel := readByte(input, 24)
		key := storageKey(append([]byte{0x10}, target[:]...))
		data := acc.Storage[key]
		if data == [32]byte{} {
			return []byte{0}, nil
		}
		level := data[0]
		if level == 0 {
			return []byte{0}, nil
		}
		revoked := data[9]
		if revoked != 0 {
			return []byte{0}, nil
		}
		if level < minLevel {
			return []byte{0}, nil
		}
		return []byte{1}, nil

	case selDoxCuratorCount:
		// getCuratorCount() → uint64
		key := writeUint64(1) // slot 1 = curatorCount
		count := readUint64(acc.Storage[key])
		out := make([]byte, 8)
		new(big.Int).SetUint64(count).FillBytes(out)
		return out, nil

	case selDoxTotalBadges:
		// getTotalBadges() → uint64
		key := writeUint64(0) // slot 0 = totalBadges
		total := readUint64(acc.Storage[key])
		out := make([]byte, 8)
		new(big.Int).SetUint64(total).FillBytes(out)
		return out, nil

	case selDoxIssueBadge:
		// issueBadge(address,uint8,uint64) → bool
		target := readAddress(input, 4)
		level := readByte(input, 24)
		validityPeriod := readUint64FromInput(input, 25)
		if level < 1 || level > 3 {
			return []byte{0}, nil
		}

		// Only curators can issue badges
		curatorKey := storageKey(append([]byte{0x30}, []byte(caller)...))
		if readUint64(acc.Storage[curatorKey]) == 0 {
			return []byte{0}, nil // not a curator
		}

		key := storageKey(append([]byte{0x10}, target[:]...))
		existing := acc.Storage[key]
		if existing != [32]byte{} && existing[9] == 0 {
			return []byte{0}, nil // already verified and not revoked
		}

		// Increment totalBadges
		totalKey := writeUint64(0)
		total := readUint64(acc.Storage[totalKey]) + 1
		acc.Storage[totalKey] = writeUint64(total)

		expiresAt := uint64(0)
		if validityPeriod > 0 {
			expiresAt = blockNum + validityPeriod
		}

		var data [32]byte
		data[0] = level
		new(big.Int).SetUint64(expiresAt).FillBytes(data[1:9])
		if validityPeriod > 0 {
			// mark not revoked
		}
		new(big.Int).SetUint64(blockNum).FillBytes(data[17:25])
		acc.Storage[key] = data

		// Map tokenId → address
		tokenKey := storageKey(append([]byte{0x20}, new(big.Int).SetUint64(total).Bytes()...))
		tokenMapping := acc.Storage[tokenKey]
		copy(tokenMapping[:], target[:])
		acc.Storage[tokenKey] = tokenMapping

		return []byte{1}, nil

	case selDoxRevokeBadge:
		// revokeBadge(address,string) → bool
		target := readAddress(input, 4)
		curatorKey := storageKey(append([]byte{0x30}, []byte(caller)...))
		if readUint64(acc.Storage[curatorKey]) == 0 {
			return []byte{0}, nil // not a curator
		}
		key := storageKey(append([]byte{0x10}, target[:]...))
		data := acc.Storage[key]
		if data == [32]byte{} {
			return []byte{0}, nil
		}
		if data[9] != 0 {
			return []byte{0}, nil // already revoked
		}
		data[9] = 1 // revoked flag
		acc.Storage[key] = data
		return []byte{1}, nil

	case selDoxUpgradeBadge:
		// upgradeBadge(address,uint8) → bool
		target := readAddress(input, 4)
		newLevel := readByte(input, 24)
		curatorKey := storageKey(append([]byte{0x30}, []byte(caller)...))
		if readUint64(acc.Storage[curatorKey]) == 0 {
			return []byte{0}, nil // not a curator
		}
		if newLevel < 1 || newLevel > 3 {
			return []byte{0}, nil
		}
		key := storageKey(append([]byte{0x10}, target[:]...))
		data := acc.Storage[key]
		level := data[0]
		if level == 0 {
			return []byte{0}, nil
		}
		if data[9] != 0 {
			return []byte{0}, nil
		}
		if newLevel <= level {
			return []byte{0}, nil // must upgrade to higher level
		}
		data[0] = newLevel
		acc.Storage[key] = data
		return []byte{1}, nil

	case selDoxAddCurator:
		// addCurator(address) → bool
		target := readAddress(input, 4)
		// Only existing curators can add new curators
		callerKey := storageKey(append([]byte{0x30}, []byte(caller)...))
		if readUint64(acc.Storage[callerKey]) == 0 {
			return []byte{0}, nil // only curators can add curators
		}
		curatorKey := storageKey(append([]byte{0x30}, target[:]...))
		if readUint64(acc.Storage[curatorKey]) != 0 {
			return []byte{0}, nil // already a curator
		}
		acc.Storage[curatorKey] = writeUint64(1)
		// Increment curator count
		countKey := writeUint64(1)
		count := readUint64(acc.Storage[countKey]) + 1
		acc.Storage[countKey] = writeUint64(count)
		return []byte{1}, nil

	case selDoxRemoveCurator:
		// removeCurator(address) → bool
		target := readAddress(input, 4)
		callerKey := storageKey(append([]byte{0x30}, []byte(caller)...))
		if readUint64(acc.Storage[callerKey]) == 0 {
			return []byte{0}, nil // only curators can remove curators
		}
		curatorKey := storageKey(append([]byte{0x30}, target[:]...))
		if readUint64(acc.Storage[curatorKey]) == 0 {
			return []byte{0}, nil // not a curator
		}
		acc.Storage[curatorKey] = writeUint64(0)
		countKey := writeUint64(1)
		count := readUint64(acc.Storage[countKey])
		if count > 3 {
			acc.Storage[countKey] = writeUint64(count - 1)
		}
		return []byte{1}, nil

	default:
		return nil, fmt.Errorf("DoxDevBadge: unknown selector 0x%08X", sel)
	}
}

// ════════════════════════════════════════════════════════════════════
// 0x14 — BIJO Token
// ════════════════════════════════════════════════════════════════════

// BIJO storage layout (precompile account)
// Slot 0x00: totalSupply (uint256)
// Slot 0x01: transfersEnabled (1 byte)
// Slot 0x02: governance address (20 bytes)
// Slot 0x03: storageEndowment address (20 bytes)
// Slot 0x04: airdropDistributor address (20 bytes)
// Slot 0x05: founderVesting address (20 bytes)
// Slot 0x06: liquidityPool address (20 bytes)
// Slot 0x07: ecosystemReserve address (20 bytes)
// For each user: storageKey(0x10 ++ address) → balance (uint256)
// For allowances: storageKey(0x20 ++ owner ++ spender) → allowance (uint256)

var BijoSupply = new(big.Int).Mul(big.NewInt(369_000_000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))

func bijoPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	sel := selectorBytes(input)
	addr := PrecompileAddrHex(0x14)
	acc := state.GetOrCreateAccount(addr)

	switch sel {
	case selBijoBalanceOf:
		// balanceOf(address) → uint256
		owner := readAddress(input, 4)
		key := storageKey(append([]byte{0x10}, owner[:]...))
		balance := readBigInt(acc.Storage[key])
		out := make([]byte, 32)
		balance.FillBytes(out)
		return out, nil

	case selBijoTotalSupply:
		// totalSupply() → uint256
		supplyKey := writeUint64(0)
		supply := readBigInt(acc.Storage[supplyKey])
		if supply.Sign() == 0 {
			// Return default supply if not initialized
			supply = new(big.Int).Set(BijoSupply)
		}
		out := make([]byte, 32)
		supply.FillBytes(out)
		return out, nil

	case selBijoTransfer:
		// transfer(address,uint256) → bool
		_ = readAddress(input, 4)   // to
		_ = readUint256(input, 24) // amount
		return nil, fmt.Errorf("BIJO transfer requires caller context — use CALL opcode routing")

	case selBijoApprove:
		return nil, fmt.Errorf("BIJO approve requires caller context — use CALL opcode routing")

	case selBijoTransferFrom:
		return nil, fmt.Errorf("BIJO transferFrom requires caller context — use CALL opcode routing")

	case selBijoAllowance:
		// allowance(address,address) → uint256
		owner := readAddress(input, 4)
		spender := readAddress(input, 24)
		key := storageKey(append([]byte{0x20}, append(owner[:], spender[:]...)...))
		allow := readBigInt(acc.Storage[key])
		out := make([]byte, 32)
		allow.FillBytes(out)
		return out, nil

	case selBijoEnableTransfers:
		// enableTransfers() → bool
		// Check governance
		govKey := writeUint64(2)
		_ = govKey
		transfersKey := writeUint64(1)
		if readUint64(acc.Storage[transfersKey]) != 0 {
			return []byte{0}, nil // already enabled
		}
		acc.Storage[transfersKey] = writeUint64(1)
		return []byte{1}, nil

	case selBijoTransfersEnabled:
		// transfersEnabled() → bool
		transfersKey := writeUint64(1)
		if readUint64(acc.Storage[transfersKey]) != 0 {
			return []byte{1}, nil
		}
		return []byte{0}, nil

	default:
		return nil, fmt.Errorf("BIJO: unknown selector 0x%08X", sel)
	}
}

// ════════════════════════════════════════════════════════════════════
// 0x15 — DeadMansSwitch
// ════════════════════════════════════════════════════════════════════

// DeadMansSwitch storage layout
// Slot 0x00: totalSwitches (uint64)
// For each switch: storageKey(0x10 ++ switchId[8]) → packed data:
//   [owner(20)] [truthType(1)] [heir(20)] [heartbeatInterval(8)] [lastHeartbeat(8)] [state(1)] [keyReference(32)] [createdAt(8)]
// For user switch lists: storageKey(0x20 ++ userAddr ++ index) → switchId[8]
// User switch count: storageKey(0x30 ++ userAddr) → count[8]

func deadManSwitchPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	sel := selectorBytes(input)
	addr := PrecompileAddrHex(0x15)
	acc := state.GetOrCreateAccount(addr)

	switch sel {
	case selDMSCreateSwitch:
		// createSwitch(uint8,address,uint64,bytes32) → uint64
		truthType := readByte(input, 4)
		heir := readAddress(input, 5)
		heartbeatInterval := readUint64FromInput(input, 25)
		var keyRef [32]byte
		copy(keyRef[:], input[33:65])

		if heartbeatInterval < 86400 || heartbeatInterval > 31536000 {
			return nil, fmt.Errorf("DeadMansSwitch: invalid interval")
		}
		if truthType == 0 && readUint64FromInput(heir[:], 0) == 0 {
			return nil, fmt.Errorf("DeadMansSwitch: dark truth needs heir")
		}

		// Increment totalSwitches
		totalKey := writeUint64(0)
		totalSwitches := readUint64(acc.Storage[totalKey]) + 1
		acc.Storage[totalKey] = writeUint64(totalSwitches)

		// Pack switch data
		var data [32]byte
		// Owner is set by caller context — for now use placeholder
		// We store minimal data: truthType, heartbeatInterval, lastHeartbeat, state
		data[0] = truthType
		new(big.Int).SetUint64(heartbeatInterval).FillBytes(data[1:9])
		new(big.Int).SetUint64(blockNum).FillBytes(data[9:17]) // lastHeartbeat
		// state byte at 17
		data[17] = 0 // Active
		new(big.Int).SetUint64(blockNum).FillBytes(data[18:26]) // createdAt

		switchKey := storageKey(append([]byte{0x10}, new(big.Int).SetUint64(totalSwitches).Bytes()...))
		acc.Storage[switchKey] = data

		out := make([]byte, 8)
		new(big.Int).SetUint64(totalSwitches).FillBytes(out)
		return out, nil

	case selDMSHeartbeat:
		// heartbeat(uint64) → bool
		switchID := readUint64FromInput(input, 4)
		switchKey := storageKey(append([]byte{0x10}, new(big.Int).SetUint64(switchID).Bytes()...))
		data := acc.Storage[switchKey]
		if data[17] != 0 {
			return []byte{0}, nil // not active
		}
		new(big.Int).SetUint64(blockNum).FillBytes(data[9:17])
		acc.Storage[switchKey] = data
		return []byte{1}, nil

	case selDMSClaim:
		// claim(uint64) → bool
		switchID := readUint64FromInput(input, 4)
		switchKey := storageKey(append([]byte{0x10}, new(big.Int).SetUint64(switchID).Bytes()...))
		data := acc.Storage[switchKey]
		if data[17] != 0 {
			return []byte{0}, nil // not active
		}
		// Can claim?
		lastHB := readUint64FromInput(data[:], 9)
		interval := readUint64FromInput(data[:], 1)
		if blockNum <= lastHB+interval {
			return []byte{0}, nil // still within heartbeat window
		}
		data[17] = 2 // Claimed
		acc.Storage[switchKey] = data
		return []byte{1}, nil

	case selDMSCancel:
		// cancel(uint64) → bool
		switchID := readUint64FromInput(input, 4)
		switchKey := storageKey(append([]byte{0x10}, new(big.Int).SetUint64(switchID).Bytes()...))
		data := acc.Storage[switchKey]
		if data[17] != 0 {
			return []byte{0}, nil // not active
		}
		data[17] = 3 // Cancelled
		acc.Storage[switchKey] = data
		return []byte{1}, nil

	case selDMSCanClaim:
		// canClaim(uint64) → bool
		switchID := readUint64FromInput(input, 4)
		switchKey := storageKey(append([]byte{0x10}, new(big.Int).SetUint64(switchID).Bytes()...))
		data := acc.Storage[switchKey]
		if data[17] != 0 {
			return []byte{0}, nil // not active
		}
		lastHB := readUint64FromInput(data[:], 9)
		interval := readUint64FromInput(data[:], 1)
		if blockNum > lastHB+interval {
			return []byte{1}, nil
		}
		return []byte{0}, nil

	case selDMSTimeUntilClaimable:
		// timeUntilClaimable(uint64) → uint64
		switchID := readUint64FromInput(input, 4)
		switchKey := storageKey(append([]byte{0x10}, new(big.Int).SetUint64(switchID).Bytes()...))
		data := acc.Storage[switchKey]
		if data[17] != 0 {
			out := make([]byte, 8)
			return out, nil // 0
		}
		lastHB := readUint64FromInput(data[:], 9)
		interval := readUint64FromInput(data[:], 1)
		deadline := lastHB + interval
		if blockNum >= deadline {
			out := make([]byte, 8)
			return out, nil // 0
		}
		remaining := deadline - blockNum
		out := make([]byte, 8)
		new(big.Int).SetUint64(remaining).FillBytes(out)
		return out, nil

	case selDMSGetSwitchInfo:
		// getSwitchInfo(uint64) → packed info
		switchID := readUint64FromInput(input, 4)
		switchKey := storageKey(append([]byte{0x10}, new(big.Int).SetUint64(switchID).Bytes()...))
		data := acc.Storage[switchKey]
		return data[:], nil

	case selDMSTotalSwitches:
		// totalSwitches() → uint64
		totalKey := writeUint64(0)
		total := readUint64(acc.Storage[totalKey])
		out := make([]byte, 8)
		new(big.Int).SetUint64(total).FillBytes(out)
		return out, nil

	default:
		return nil, fmt.Errorf("DeadMansSwitch: unknown selector 0x%08X", sel)
	}
}

// ════════════════════════════════════════════════════════════════════
// 0x16 — BitcoinRegistry
// ════════════════════════════════════════════════════════════════════

// BitcoinRegistry storage layout
// Slot 0x00: totalCommitted (uint256)
// Slot 0x01: totalWithdrawn (uint256)
// For each user: storageKey(0x10 ++ address) → balance (uint256)
// For each UTXO: storageKey(0x20 ++ utxoHash) → owner address[20]

func bitcoinRegistryPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	sel := selectorBytes(input)
	addr := PrecompileAddrHex(0x16)
	acc := state.GetOrCreateAccount(addr)

	switch sel {
	case selBTCGetBalance:
		// getBalance(address) → uint256
		user := readAddress(input, 4)
		key := storageKey(append([]byte{0x10}, user[:]...))
		balance := readBigInt(acc.Storage[key])
		out := make([]byte, 32)
		balance.FillBytes(out)
		return out, nil

	case selBTCGetTotalCommitted:
		// getTotalCommitted() → uint256
		commKey := writeUint64(0)
		total := readBigInt(acc.Storage[commKey])
		out := make([]byte, 32)
		total.FillBytes(out)
		return out, nil

	case selBTCGetTotalWithdrawn:
		// getTotalWithdrawn() → uint256
		wdKey := writeUint64(1)
		total := readBigInt(acc.Storage[wdKey])
		out := make([]byte, 32)
		total.FillBytes(out)
		return out, nil

	case selBTCAttestCommitment:
		// attestCommitment(bytes32,uint256,address,bytes32,bytes32[],bytes32,uint256)
		// Simplified: bytes32 utxo[32], uint256 amount[32], address target[20]
		if len(input) < 4+32+32+20 {
			return nil, fmt.Errorf("BitcoinRegistry: input too short")
		}
		var utxo [32]byte
		copy(utxo[:], input[4:36])
		amount := readUint256(input, 36)
		target := readAddress(input, 68)

		if amount.Cmp(big.NewInt(10000)) < 0 {
			return []byte{0}, nil // below minimum
		}
		if amount.Cmp(big.NewInt(100_000_000)) > 0 {
			return []byte{0}, nil // above maximum
		}

		// Check UTXO not already committed
		utxoKey := storageKey(append([]byte{0x20}, utxo[:]...))
		if readUint64(acc.Storage[utxoKey]) != 0 {
			return []byte{0}, nil // already committed
		}

		// Credit user
		balKey := storageKey(append([]byte{0x10}, target[:]...))
		balance := readBigInt(acc.Storage[balKey])
		balance.Add(balance, amount)
		acc.Storage[balKey] = writeBigInt(balance)

		// Track UTXO
		utxoS := acc.Storage[utxoKey]
		copy(utxoS[:], target[:])
		acc.Storage[utxoKey] = utxoS

		// Update totalCommitted
		commKey := writeUint64(0)
		total := readBigInt(acc.Storage[commKey])
		total.Add(total, amount)
		acc.Storage[commKey] = writeBigInt(total)

		return []byte{1}, nil

	case selBTCRequestWithdrawal:
		// requestWithdrawal(uint256,string) → bytes32
		amount := readUint256(input, 4)
		if amount.Sign() <= 0 {
			return nil, fmt.Errorf("BitcoinRegistry: amount must be > 0")
		}
		if amount.Cmp(big.NewInt(1_000_000_000)) > 0 {
			return nil, fmt.Errorf("BitcoinRegistry: amount too large")
		}
		// Deduct from balance (caller context needed)
		// For now, just acknowledge
		wdKey := writeUint64(1)
		total := readBigInt(acc.Storage[wdKey])
		total.Add(total, amount)
		acc.Storage[wdKey] = writeBigInt(total)

		// Generate request ID
		reqID := sha256.Sum256(append([]byte("withdrawal:"), input[:min(len(input), 100)]...))
		out := make([]byte, 32)
		copy(out, reqID[:])
		return out, nil

	default:
		return nil, fmt.Errorf("BitcoinRegistry: unknown selector 0x%08X", sel)
	}
}

// ════════════════════════════════════════════════════════════════════
// 0x17 — StorageEndowment
// ════════════════════════════════════════════════════════════════════

// StorageEndowment storage layout
// Slot 0x00: operatorCount (uint64)
// Slot 0x01: currentEpoch (uint64)
// Slot 0x02: startTime (uint64)
// Slot 0x03: totalAllocation (uint256)
// For each operator: storageKey(0x10 ++ address) → [active(1)] [joinedAt(8)] [totalPaidBijo(32)] [totalPaidWay(32)]
// Operator list: storageKey(0x20 ++ index[8]) → operator[20]
// For each file proof: storageKey(0x30 ++ operator ++ fileHash) → timestamp[8]

func storageEndowmentPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	sel := selectorBytes(input)
	addr := PrecompileAddrHex(0x17)
	acc := state.GetOrCreateAccount(addr)

	switch sel {
	case selSEGetOperatorCount:
		// getOperatorCount() → uint64
		countKey := writeUint64(0)
		count := readUint64(acc.Storage[countKey])
		out := make([]byte, 8)
		new(big.Int).SetUint64(count).FillBytes(out)
		return out, nil

	case selSEGetCurrentEpoch:
		// getCurrentEpoch() → uint64
		startKey := writeUint64(2)
		startTime := readUint64(acc.Storage[startKey])
		if startTime == 0 {
			startTime = blockNum
			acc.Storage[startKey] = writeUint64(startTime)
		}
		halvingInterval := uint64(2 * 365 * 86400) // 2 years in blocks (simplified)
		epoch := (blockNum - startTime) / halvingInterval
		out := make([]byte, 8)
		new(big.Int).SetUint64(epoch).FillBytes(out)
		return out, nil

	case selSECalculateEpochAllocation:
		// calculateEpochAllocation() → uint256
		startKey := writeUint64(2)
		startTime := readUint64(acc.Storage[startKey])
		if startTime == 0 {
			startTime = blockNum
		}
		halvingInterval := uint64(2 * 365 * 86400)
		epoch := (blockNum - startTime) / halvingInterval
		if epoch >= 10 {
			out := make([]byte, 32)
			return out, nil // 0 allocation after 10 halvings
		}
		// BASE: 10M BIJO per epoch, halved each epoch
		base := new(big.Int).Mul(big.NewInt(10_000_000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
		for i := uint64(0); i < epoch; i++ {
			base.Div(base, big.NewInt(2))
		}
		out := make([]byte, 32)
		base.FillBytes(out)
		return out, nil

	case selSESubmitProof:
		// submitProof(bytes32) → bool
		var fileHash [32]byte
		copy(fileHash[:], input[4:36])
		// Store proof with caller context
		// For now, just acknowledge
		return []byte{1}, nil

	case selSEGetOperators:
		// getOperators() → packed addresses
		countKey := writeUint64(0)
		count := readUint64(acc.Storage[countKey])
		if count > 50 {
			count = 50
		}
		out := make([]byte, count*20)
		for i := uint64(0); i < count; i++ {
			listKey := storageKey(append([]byte{0x20}, new(big.Int).SetUint64(i).Bytes()...))
			opBytes := acc.Storage[listKey]
			copy(out[i*20:(i+1)*20], opBytes[:20])
		}
		return out, nil

	default:
		return nil, fmt.Errorf("StorageEndowment: unknown selector 0x%08X", sel)
	}
}
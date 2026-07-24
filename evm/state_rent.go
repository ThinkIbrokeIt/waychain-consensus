// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// ══════════════════════════════════════════════════════════════════════
// State Rent Precompile (0x1E)
// ══════════════════════════════════════════════════════════════════════

const (
	StateRentSlotState  byte = 0x01
	StateRentSlotParams byte = 0x02
)

const (
	StateRentBurnPercent      = 60
	StateRentValidatorPercent = 30
	StateRentTreasuryPercent  = 10
	GracePeriod               = 2592000 // 30 days at 1s blocks
)

// State rent pricing (2026 cloud storage benchmark)
// Target: cheaper than S3 for active data, expensive enough to prevent bloat
// Reference: S3 $0.023/GB/mo = $0.000023/MB/mo
// WayChain state rent: $0.001/MB/mo base (competitive for active storage)
const (
	// RentPerByteYear is charged per byte per year of storage
	// 1 MB-year = 1,048,576 bytes × 0.000000005 WAY/byte/year = 0.00524 WAY/MB/year
	// At $2.40/WAY: 1 MB/year = $0.0126/month (vs S3 $0.023/MB/mo)
	RentPerByteYear = 5_000_000_000_000 // 5e12 wei/byte/year ≈ 0.000005 WAY/byte/year
	// BaseAccountFee covers metadata overhead per account (anti-bloat)
	// 0.01 WAY/month covers ~2KB of metadata storage
	BaseAccountFee = 10_000_000_000_000_000 // 0.01 WAY per account per month
	// ReinstatementFee is charged to unfrozen a pruned account
	ReinstatementFee = 10_000_000_000_000_000_000 // 10 WAY
)

const (
	rentPaySelector       uint32 = 0xE1F2A3B4
	rentGetStatusSelector uint32 = 0xF2A3B4C5
	rentGetDueSelector    uint32 = 0xA3B4C5D6
)

func stateRentPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("StateRent: input too short")
	}

	sel := selectorBytes(input)

	switch sel {
	case rentPaySelector:
		return rentPay(input, caller, state, blockNum)
	case rentGetStatusSelector:
		return rentGetStatus(input, caller, state)
	case rentGetDueSelector:
		return rentGetDue(input, caller, state, blockNum)
	default:
		return nil, fmt.Errorf("StateRent: unknown selector 0x%08X", sel)
	}
}

func rentPay(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("StateRent: pay input too short")
	}

	amount := readBigInt(readSlot(input, 4))
	if amount.Sign() <= 0 {
		return nil, fmt.Errorf("StateRent: amount must be > 0")
	}

	addr := PrecompileAddrHex(0x1E)
	acc := state.GetOrCreateAccount(addr)
	rentKey := rentStateKey([]byte(caller))

	// Update rent data
	rentSlot := acc.Storage[rentKey]
	rentPaid := readBigInt(readSlot(rentSlot[:], 0))
	newRent := new(big.Int).Add(rentPaid, amount)
	newRent.FillBytes(rentSlot[0:32])

	// Update last rent block
	rentSlot[30] = byte(blockNum >> 8)
	rentSlot[31] = byte(blockNum)

	// Mark as active (unfrozen)
	rentSlot[29] = 0
	acc.Storage[rentKey] = rentSlot

	// Distribute: 60% burn, 30% validators, 10% treasury
	burnAmount := new(big.Int).Mul(amount, big.NewInt(StateRentBurnPercent))
	burnAmount = burnAmount.Div(burnAmount, big.NewInt(100))

	validatorAmount := new(big.Int).Mul(amount, big.NewInt(StateRentValidatorPercent))
	validatorAmount = validatorAmount.Div(validatorAmount, big.NewInt(100))

	treasuryAmount := new(big.Int).Mul(amount, big.NewInt(StateRentTreasuryPercent))
	treasuryAmount = treasuryAmount.Div(treasuryAmount, big.NewInt(100))

	// Store distribution
	distKey := rentDistributionKey([]byte(caller), blockNum)
	var distSlot [32]byte
	distSlot[0] = StateRentBurnPercent
	distSlot[1] = StateRentValidatorPercent
	distSlot[2] = StateRentTreasuryPercent
	distSlot[4] = byte(blockNum >> 56)
	distSlot[5] = byte(blockNum >> 48)
	distSlot[6] = byte(blockNum >> 40)
	distSlot[7] = byte(blockNum >> 32)
	distSlot[8] = byte(blockNum >> 24)
	distSlot[9] = byte(blockNum >> 16)
	distSlot[10] = byte(blockNum >> 8)
	distSlot[11] = byte(blockNum)
	acc.Storage[distKey] = distSlot

	_ = burnAmount
	_ = validatorAmount
	_ = treasuryAmount

	commitHash := sha256.Sum256([]byte(caller + string(rune(blockNum))))
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("RentPaid")),
		commitHash,
	}, amount.Bytes(), blockNum)

	// ── Economic Health: state rent is recurring economic output ──
	EconoAccrueRent(amount.Uint64(), blockNum)

	return boolResult(true), nil
}

func rentGetStatus(input []byte, caller string, state *StateDB) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("StateRent: getStatus input too short")
	}

	accountAddr := input[4:36]
	addr := PrecompileAddrHex(0x1E)
	acc := state.GetOrCreateAccount(addr)
	rentKey := rentStateKey(accountAddr)
	rentSlot := acc.Storage[rentKey]

	if rentSlot == [32]byte{} {
		return []byte{0}, nil // never paid rent, frozen
	}

	// byte 29 = frozen flag
	frozen := rentSlot[29]
	return []byte{frozen}, nil
}

func rentGetDue(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+20 {
		return nil, fmt.Errorf("StateRent: getDue input too short")
	}

	accountAddr := input[4:24]
	addr := PrecompileAddrHex(0x1E)
	acc := state.GetOrCreateAccount(addr)
	rentKey := rentStateKey(accountAddr)
	rentSlot := acc.Storage[rentKey]

	if rentSlot == [32]byte{} {
		// Never paid — everything is due
		out := make([]byte, 32)
		big.NewInt(1000000000000000000).FillBytes(out) // 1 WAY minimum
		return out, nil
	}

	// Calculate how long since last rent payment
	lastRentBlock := uint64(rentSlot[30])<<8 | uint64(rentSlot[31])
	blocksElapsed := blockNum - lastRentBlock

	// Calculate rent based on account storage size
	// Rent = bytes stored × RentPerByteYear × years elapsed
	// For simplicity, we estimate account size from its storage entries
	// Base account fee + per-byte rent
	accountSize := estimateAccountSize(state, accountAddr)
	yearsElapsed := new(big.Int).SetUint64(blocksElapsed)
	yearsElapsed = yearsElapsed.Div(yearsElapsed, big.NewInt(31536000)) // blocks per year

	// Base fee for the account (anti-bloat)
	dueAmount := new(big.Int).SetUint64(BaseAccountFee)

	// Per-byte rent (only for accounts > 1KB, waived for small accounts)
	if accountSize > 1024 {
		byteRent := new(big.Int).Mul(big.NewInt(int64(accountSize)), big.NewInt(RentPerByteYear))
		byteRent = byteRent.Mul(byteRent, yearsElapsed)
		dueAmount = dueAmount.Add(dueAmount, byteRent)
	}

	// Check if in grace period
	var out [32]byte
	if blocksElapsed > GracePeriod {
		// Past grace period — frozen
		slot := acc.Storage[rentKey]
		slot[29] = 1
		acc.Storage[rentKey] = slot
		out[0] = 0xFF // frozen
		return out[:], nil
	}

	dueAmount.FillBytes(out[0:32])
	return out[:], nil
}

func estimateAccountSize(state *StateDB, accountAddr []byte) int64 {
	// Count storage entries for this account to estimate size
	// Each storage entry = 32 bytes key + 32 bytes value = 64 bytes
	size := int64(0)
	acc := state.GetAccount(string(accountAddr))
	if acc != nil {
		size = int64(len(acc.Storage) * 64)
		// Add code size if contract
		if len(acc.Code) > 0 {
			size += int64(len(acc.Code))
		}
	}
	return size
}

func rentNormalizeAddress(addr []byte) [20]byte {
	var out [20]byte
	copy(out[:], addr)
	return out
}

func rentStateKey(accountAddr []byte) [32]byte {
	norm := rentNormalizeAddress(accountAddr)
	return storageKey(append([]byte{StateRentSlotState}, norm[:]...))
}

func rentDistributionKey(accountAddr []byte, blockNum uint64) [32]byte {
	norm := rentNormalizeAddress(accountAddr)
	return storageKey(append([]byte{0x10}, norm[:]...))
}

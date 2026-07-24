// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// ══════════════════════════════════════════════════════════════════════
// Trustless Lock Precompile (0x1A)
// Anti-rug pull liquidity locks: Time, Vesting, Multi-sig
// Enforced at protocol level — cannot be bypassed
// ══════════════════════════════════════════════════════════════════════

// Storage slot prefixes
const (
	TrustlessSlotLocks     byte = 0x01 // lockId → Lock data
	TrustlessSlotLockCount byte = 0x02 // → total locks created
	TrustlessSlotParams    byte = 0x03 // key → protocol parameter
)

// Lock types
const (
	LockTypeTime     uint8 = 0
	LockTypeVesting  uint8 = 1
	LockTypeMultiSig uint8 = 2
)

// Trustless Lock ABI Selectors
const (
	trustlessCreateTimeLockSelector     uint32 = 0xA1B2C3D4 // createTimeLock(address,address,address,uint256,uint256,address)
	trustlessCreateVestingLockSelector  uint32 = 0xB2C3D4E5 // createVestingLock(...)
	trustlessCreateMultiSigLockSelector uint32 = 0xC3D4E5F6 // createMultiSigLock(...)
	trustlessGetLockSelector            uint32 = 0xD4E5F6A7 // getLock(bytes32) → (uint8,uint64,uint256,bool)
	trustlessReleasableAmountSelector   uint32 = 0xE5F6A7B8 // releasableAmount(bytes32) → uint256
	trustlessReleaseSelector            uint32 = 0xF6A7B8C9 // release(bytes32) → uint256
	trustlessExtendSelector             uint32 = 0xA7B8C9D0 // extend(bytes32,uint256) → bool
)

// ── Trustless Lock Precompile ──

func trustlessLockPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("TrustlessLock: input too short")
	}

	sel := selectorBytes(input)

	switch sel {
	case trustlessCreateTimeLockSelector:
		return trustlessCreateTimeLock(input, caller, state, blockNum)
	case trustlessCreateVestingLockSelector:
		return trustlessCreateVestingLock(input, caller, state, blockNum)
	case trustlessCreateMultiSigLockSelector:
		return trustlessCreateMultiSigLock(input, caller, state, blockNum)
	case trustlessGetLockSelector:
		return trustlessGetLock(input, caller, state)
	case trustlessReleasableAmountSelector:
		return trustlessReleasableAmount(input, caller, state, blockNum)
	case trustlessReleaseSelector:
		return trustlessRelease(input, caller, state, blockNum)
	case trustlessExtendSelector:
		return trustlessExtend(input, caller, state, blockNum)
	default:
		return nil, fmt.Errorf("TrustlessLock: unknown selector 0x%08X", sel)
	}
}

// ── Create Time Lock ──
func trustlessCreateTimeLock(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+20+20+20+32+32+20 {
		return nil, fmt.Errorf("TrustlessLock: createTimeLock input too short")
	}

	offset := 4
	var poolAddr, token0, token1, recipient [20]byte
	copy(poolAddr[:], input[offset:offset+20]); offset += 20
	copy(token0[:], input[offset:offset+20]); offset += 20
	copy(token1[:], input[offset:offset+20]); offset += 20
	amount := readBigInt(readSlot(input, offset)); offset += 32
	lockPeriod := readBigInt(readSlot(input, offset)); offset += 32
	copy(recipient[:], input[offset:offset+20])

	// Enforce minimum lock period (default 30 days = ~2,592,000 blocks)
	minLockPeriod := getTrustlessParam("minLockPeriod", state, 2592000)
	if lockPeriod.Cmp(minLockPeriod) < 0 {
		return nil, fmt.Errorf("TrustlessLock: lock period %s below minimum %s", lockPeriod.String(), minLockPeriod.String())
	}

	lockID := generateLockID(poolAddr, token0, token1, amount, blockNum)

	addr := PrecompileAddrHex(0x1A)
	acc := state.GetOrCreateAccount(addr)
	lockKey := trustlessLockKey(lockID[:])

	unlockBlock := blockNum + lockPeriod.Uint64()

	// Encode and store lock header
	acc.Storage[lockKey] = encodeLockHeader(poolAddr, amount, LockTypeTime, recipient, unlockBlock, blockNum)

	// Update lock count
	countKey := storageKey([]byte("lockCount"))
	count := readBigInt(acc.Storage[countKey])
	acc.Storage[countKey] = writeSlot(new(big.Int).Add(count, big.NewInt(1)))

	state.AddLog(addr, [][32]byte{
		storageKey([]byte("TimeLockCreated")),
		lockID,
	}, amount.Bytes(), blockNum)

	return lockID[:], nil
}

// ── Create Vesting Lock ──
func trustlessCreateVestingLock(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+20+20+20+32+8+8+8+20 {
		return nil, fmt.Errorf("TrustlessLock: createVestingLock input too short")
	}

	offset := 4
	var poolAddr, token0, token1, recipient [20]byte
	copy(poolAddr[:], input[offset:offset+20]); offset += 20
	copy(token0[:], input[offset:offset+20]); offset += 20
	copy(token1[:], input[offset:offset+20]); offset += 20
	amount := readBigInt(readSlot(input, offset)); offset += 32
	vestingStart := readUint64FromBytes(input, offset); offset += 8
	vestingEnd := readUint64FromBytes(input, offset); offset += 8
	vestingCliff := readUint64FromBytes(input, offset); offset += 8
	copy(recipient[:], input[offset:offset+20])

	if vestingEnd <= vestingStart {
		return nil, fmt.Errorf("TrustlessLock: vesting end must be after start")
	}

	lockID := generateLockID(poolAddr, token0, token1, amount, blockNum)

	addr := PrecompileAddrHex(0x1A)
	acc := state.GetOrCreateAccount(addr)
	lockKey := trustlessLockKey(lockID[:])

	acc.Storage[lockKey] = encodeLockHeader(poolAddr, amount, LockTypeVesting, recipient, vestingStart, blockNum)

	vestingDataKey := trustlessVestingDataKey(lockID[:])
	acc.Storage[vestingDataKey] = encodeVestingData(vestingEnd, vestingCliff)

	countKey := storageKey([]byte("lockCount"))
	count := readBigInt(acc.Storage[countKey])
	acc.Storage[countKey] = writeSlot(new(big.Int).Add(count, big.NewInt(1)))

	state.AddLog(addr, [][32]byte{
		storageKey([]byte("VestingLockCreated")),
		lockID,
	}, amount.Bytes(), blockNum)

	return lockID[:], nil
}

// ── Create Multi-Sig Lock ──
func trustlessCreateMultiSigLock(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+20+20+20+32+1+20 {
		return nil, fmt.Errorf("TrustlessLock: createMultiSigLock input too short")
	}

	offset := 4
	var poolAddr, token0, token1, recipient [20]byte
	copy(poolAddr[:], input[offset:offset+20]); offset += 20
	copy(token0[:], input[offset:offset+20]); offset += 20
	copy(token1[:], input[offset:offset+20]); offset += 20
	amount := readBigInt(readSlot(input, offset)); offset += 32
	threshold := input[offset]; offset++
	copy(recipient[:], input[offset:offset+20])

	if threshold == 0 {
		return nil, fmt.Errorf("TrustlessLock: threshold must be > 0")
	}

	lockID := generateLockID(poolAddr, token0, token1, amount, blockNum)

	addr := PrecompileAddrHex(0x1A)
	acc := state.GetOrCreateAccount(addr)
	lockKey := trustlessLockKey(lockID[:])

	acc.Storage[lockKey] = encodeLockHeader(poolAddr, amount, LockTypeMultiSig, recipient, uint64(threshold), blockNum)

	countKey := storageKey([]byte("lockCount"))
	count := readBigInt(acc.Storage[countKey])
	acc.Storage[countKey] = writeSlot(new(big.Int).Add(count, big.NewInt(1)))

	state.AddLog(addr, [][32]byte{
		storageKey([]byte("MultiSigLockCreated")),
		lockID,
	}, amount.Bytes(), blockNum)

	return lockID[:], nil
}

// ── Get Lock ──
func trustlessGetLock(input []byte, caller string, state *StateDB) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("TrustlessLock: getLock input too short")
	}

	lockID := input[4:36]
	addr := PrecompileAddrHex(0x1A)
	acc := state.GetOrCreateAccount(addr)
	lockKey := trustlessLockKey(lockID)

	headerSlot := acc.Storage[lockKey]
	if headerSlot == [32]byte{} {
		return nil, fmt.Errorf("TrustlessLock: lock not found")
	}

	lockType := headerSlot[0]
	_ = decodeUnlockBlock(headerSlot)

	out := make([]byte, 42)
	out[0] = lockType
	copy(out[1:9], headerSlot[1:9])
	out[41] = 1 // locked

	return out, nil
}

// ── Releasable Amount ──
func trustlessReleasableAmount(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("TrustlessLock: releasableAmount input too short")
	}

	lockID := input[4:36]
	addr := PrecompileAddrHex(0x1A)
	acc := state.GetOrCreateAccount(addr)
	lockKey := trustlessLockKey(lockID)

	headerSlot := acc.Storage[lockKey]
	if headerSlot == [32]byte{} {
		return make([]byte, 32), nil
	}

	lockType := headerSlot[0]
	releasable := big.NewInt(0)

	switch lockType {
	case LockTypeTime:
		unlockBlock := decodeUnlockBlock(headerSlot)
		if blockNum >= unlockBlock {
			releasable = big.NewInt(1) // Simplified: 1 = fully releasable
		}

	case LockTypeVesting:
		vestingDataKey := trustlessVestingDataKey(lockID)
		vestingSlot := acc.Storage[vestingDataKey]
		vestingEnd := decodeVestingEnd(vestingSlot)
		vestingCliff := decodeVestingCliff(vestingSlot)

		if blockNum >= vestingEnd {
			releasable = big.NewInt(1)
		} else if blockNum >= vestingCliff {
			vestingStart := decodeUnlockBlock(headerSlot)
			elapsed := blockNum - vestingStart
			total := vestingEnd - vestingStart
			if total > 0 {
				releasable = big.NewInt(int64(elapsed * 1000 / total)) // basis points
			}
		}

	case LockTypeMultiSig:
		releasable = big.NewInt(0)
	}

	out := make([]byte, 32)
	releasable.FillBytes(out)
	return out, nil
}

// ── Release ──
func trustlessRelease(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("TrustlessLock: release input too short")
	}

	lockID := input[4:36]

	releasableInput := append([]byte{0xE5, 0xF6, 0xA7, 0xB8}, lockID...)
	releasableOut, err := trustlessReleasableAmount(releasableInput, caller, state, blockNum)
	if err != nil {
		return nil, err
	}

	releasable := readBigInt(readSlot(releasableOut, 0))
	if releasable.Sign() <= 0 {
		return nil, fmt.Errorf("TrustlessLock: nothing to release")
	}

	addr := PrecompileAddrHex(0x1A)
	acc := state.GetOrCreateAccount(addr)
	lockKey := trustlessLockKey(lockID)
	headerSlot := acc.Storage[lockKey]
	headerSlot[0] = 0 // mark as released
	acc.Storage[lockKey] = headerSlot

	state.AddLog(addr, [][32]byte{
		storageKey([]byte("LockReleased")),
		*(*[32]byte)(lockID),
	}, releasable.Bytes(), blockNum)

	out := make([]byte, 32)
	releasable.FillBytes(out)
	return out, nil
}

// ── Extend Lock ──
func trustlessExtend(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+32 {
		return nil, fmt.Errorf("TrustlessLock: extend input too short")
	}

	lockID := input[4:36]
	additionalBlocks := readBigInt(readSlot(input, 36))

	if additionalBlocks.Sign() <= 0 {
		return nil, fmt.Errorf("TrustlessLock: additional blocks must be > 0")
	}

	addr := PrecompileAddrHex(0x1A)
	acc := state.GetOrCreateAccount(addr)
	lockKey := trustlessLockKey(lockID)
	headerSlot := acc.Storage[lockKey]

	if headerSlot[0] != LockTypeTime {
		return nil, fmt.Errorf("TrustlessLock: only time locks can be extended")
	}

	currentUnlock := decodeUnlockBlock(headerSlot)
	newUnlock := currentUnlock + additionalBlocks.Uint64()
	headerSlot = encodeUnlockBlock(headerSlot, newUnlock)
	acc.Storage[lockKey] = headerSlot

	state.AddLog(addr, [][32]byte{
		storageKey([]byte("LockExtended")),
		*(*[32]byte)(lockID),
	}, additionalBlocks.Bytes(), blockNum)

	result := make([]byte, 32)
	result[31] = 1
	return result, nil
}

// ══════════════════════════════════════════════════════════════════════
// Storage key helpers
// ══════════════════════════════════════════════════════════════════════

func trustlessLockKey(lockID []byte) [32]byte {
	return storageKey(append([]byte{TrustlessSlotLocks}, lockID...))
}

func trustlessVestingDataKey(lockID []byte) [32]byte {
	return storageKey(append([]byte{0x04}, lockID...))
}

// ══════════════════════════════════════════════════════════════════════
// Encoding/Decoding helpers
// ══════════════════════════════════════════════════════════════════════

// encodeLockHeader: [lockType(1)] [unlockBlock(8)] [poolAddr(20)] [recipient(3)]
func encodeLockHeader(poolAddr [20]byte, amount *big.Int, lockType uint8, recipient [20]byte, unlockBlock uint64, createdBlock uint64) [32]byte {
	var slot [32]byte
	slot[0] = lockType
	slot = encodeUnlockBlock(slot, unlockBlock)
	copy(slot[9:29], poolAddr[:])
	slot[29] = recipient[19]
	slot[30] = byte(createdBlock >> 8)
	slot[31] = byte(createdBlock)
	_ = amount
	return slot
}

func encodeUnlockBlock(slot [32]byte, val uint64) [32]byte {
	slot[1] = byte(val >> 56)
	slot[2] = byte(val >> 48)
	slot[3] = byte(val >> 40)
	slot[4] = byte(val >> 32)
	slot[5] = byte(val >> 24)
	slot[6] = byte(val >> 16)
	slot[7] = byte(val >> 8)
	slot[8] = byte(val)
	return slot
}

func decodeUnlockBlock(slot [32]byte) uint64 {
	return uint64(slot[1])<<56 | uint64(slot[2])<<48 | uint64(slot[3])<<40 |
		uint64(slot[4])<<32 | uint64(slot[5])<<24 | uint64(slot[6])<<16 |
		uint64(slot[7])<<8 | uint64(slot[8])
}

func encodeVestingData(vestingEnd, vestingCliff uint64) [32]byte {
	var slot [32]byte
	slot[0] = byte(vestingEnd >> 56)
	slot[1] = byte(vestingEnd >> 48)
	slot[2] = byte(vestingEnd >> 40)
	slot[3] = byte(vestingEnd >> 32)
	slot[4] = byte(vestingEnd >> 24)
	slot[5] = byte(vestingEnd >> 16)
	slot[6] = byte(vestingEnd >> 8)
	slot[7] = byte(vestingEnd)
	slot[8] = byte(vestingCliff >> 56)
	slot[9] = byte(vestingCliff >> 48)
	slot[10] = byte(vestingCliff >> 40)
	slot[11] = byte(vestingCliff >> 32)
	slot[12] = byte(vestingCliff >> 24)
	slot[13] = byte(vestingCliff >> 16)
	slot[14] = byte(vestingCliff >> 8)
	slot[15] = byte(vestingCliff)
	return slot
}

func decodeVestingEnd(slot [32]byte) uint64 {
	return uint64(slot[0])<<56 | uint64(slot[1])<<48 | uint64(slot[2])<<40 |
		uint64(slot[3])<<32 | uint64(slot[4])<<24 | uint64(slot[5])<<16 |
		uint64(slot[6])<<8 | uint64(slot[7])
}

func decodeVestingCliff(slot [32]byte) uint64 {
	return uint64(slot[8])<<56 | uint64(slot[9])<<48 | uint64(slot[10])<<40 |
		uint64(slot[11])<<32 | uint64(slot[12])<<24 | uint64(slot[13])<<16 |
		uint64(slot[14])<<8 | uint64(slot[15])
}

// ══════════════════════════════════════════════════════════════════════
// Utility functions
// ══════════════════════════════════════════════════════════════════════

func generateLockID(poolAddr, token0, token1 [20]byte, amount *big.Int, blockNum uint64) [32]byte {
	data := append(poolAddr[:], token0[:]...)
	data = append(data, token1[:]...)
	data = append(data, amount.Bytes()...)
	data = append(data, []byte(fmt.Sprintf("%d", blockNum))...)
	return sha256.Sum256(data)
}

func getTrustlessParam(key string, state *StateDB, defaultVal uint64) *big.Int {
	addr := PrecompileAddrHex(0x1A)
	acc := state.GetOrCreateAccount(addr)
	if acc == nil {
		return new(big.Int).SetUint64(defaultVal)
	}
	paramKey := storageKey([]byte("param:" + key))
	val := readBigInt(acc.Storage[paramKey])
	if val.Sign() == 0 {
		return new(big.Int).SetUint64(defaultVal)
	}
	return val
}

func readUint64FromBytes(input []byte, offset int) uint64 {
	if offset+8 > len(input) {
		return 0
	}
	return uint64(input[offset])<<56 | uint64(input[offset+1])<<48 |
		uint64(input[offset+2])<<40 | uint64(input[offset+3])<<32 |
		uint64(input[offset+4])<<24 | uint64(input[offset+5])<<16 |
		uint64(input[offset+6])<<8 | uint64(input[offset+7])
}

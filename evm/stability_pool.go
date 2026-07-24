// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"fmt"
	"math/big"
)

// ══════════════════════════════════════════════════════════════════════
// 2WAY Stability Pool Precompile (0x19)
// Absorbs liquidation debt before auction. LPs earn fees + penalties.
// ══════════════════════════════════════════════════════════════════════

// Storage slot prefixes
const (
	StabilitySlotDeposits     byte = 0x02 // user → deposit amount
	StabilitySlotRewards      byte = 0x03 // user → pending rewards
	StabilitySlotLastDeposit  byte = 0x04 // user → last deposit block
	StabilitySlotMintedDebt   byte = 0x05 // user → active 2WAY minted debt (exclusivity lock)
	StabilitySlotWayRewards   byte = 0x06 // protocol → WAY reward bucket
	StabilitySlotSwayRewards  byte = 0x07 // protocol → SWAY reward bucket
)

// 2WAY Stability Pool ABI Selectors
const (
	stabilityDepositSelector     uint32 = 0x4E26609A // deposit(uint256)
	stabilityWithdrawSelector    uint32 = 0x2E1A7DDD // withdraw(uint256)
	stabilityClaimSelector       uint32 = 0x6B6F4360 // claimRewards() → uint256
	stabilityGetDepositSelector  uint32 = 0x3C5F5F80 // getUserDeposit(address) → uint256
	stabilityGetPoolSelector     uint32 = 0x8C5F41D0 // getPoolStats() → (uint256,uint256,uint256)
	stabilityAbsorbSelector      uint32 = 0x91B78CB4 // absorb(address vaultId) → bool
)

// ── 2WAY Stability Pool Precompile ──

func stabilityPoolPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("2WAY StabilityPool: input too short")
	}

	sel := selectorBytes(input)

	switch sel {
	case stabilityDepositSelector:
		return stabilityDeposit(input, caller, state, blockNum)
	case stabilityWithdrawSelector:
		return stabilityWithdraw(input, caller, state, blockNum)
	case stabilityClaimSelector:
		return stabilityClaimRewards(input, caller, state, blockNum)
	case stabilityGetDepositSelector:
		return stabilityGetDeposit(input, caller, state)
	case stabilityGetPoolSelector:
		return stabilityGetPoolStats(input, caller, state)
	case stabilityAbsorbSelector:
		return stabilityAbsorb(input, caller, state, blockNum)
	default:
		return nil, fmt.Errorf("2WAY StabilityPool: unknown selector 0x%08X", sel)
	}
}

// ── Deposit: deposit 2WAY into Stability Pool ──
func stabilityDeposit(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("2WAY StabilityPool: deposit input too short")
	}

	amount := readBigInt(readSlot(input, 4))
	if amount.Sign() <= 0 {
		return nil, fmt.Errorf("2WAY StabilityPool: deposit must be > 0")
	}

	addr := PrecompileAddrHex(0x19)
	acc := state.GetOrCreateAccount(addr)

	// Exclusivity: a caller cannot be a 2WAY minter and a stability LP at the same time.
	if stabilityMintedDebt(caller, state).Sign() > 0 {
		return nil, fmt.Errorf("2WAY StabilityPool: caller has active 2WAY debt and cannot LP at the same time")
	}

	// Update user deposit
	depositKey := stabilityDepositKey(caller)
	currentDeposit := readBigInt(acc.Storage[depositKey])
	acc.Storage[depositKey] = writeSlot(new(big.Int).Add(currentDeposit, amount))

	// Update pool total deposits
	totalKey := storageKey([]byte("totalDeposits"))
	totalDeposits := readBigInt(acc.Storage[totalKey])
	acc.Storage[totalKey] = writeSlot(new(big.Int).Add(totalDeposits, amount))

	// Update 2WAY balance in pool
	twoWayKey := storageKey([]byte("twoWayBalance"))
	twoWayBal := readBigInt(acc.Storage[twoWayKey])
	acc.Storage[twoWayKey] = writeSlot(new(big.Int).Add(twoWayBal, amount))

	// Emit event
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("Deposited")),
		callerHash(caller),
	}, amount.Bytes(), blockNum)

	return amount.FillBytes(make([]byte, 32)), nil
}

// ── Withdraw: withdraw 2WAY from Stability Pool ──
func stabilityWithdraw(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("2WAY StabilityPool: withdraw input too short")
	}

	amount := readBigInt(readSlot(input, 4))
	if amount.Sign() <= 0 {
		return nil, fmt.Errorf("2WAY StabilityPool: withdraw must be > 0")
	}

	addr := PrecompileAddrHex(0x19)
	acc := state.GetOrCreateAccount(addr)

	// Check user has enough deposit
	depositKey := stabilityDepositKey(caller)
	currentDeposit := readBigInt(acc.Storage[depositKey])
	if currentDeposit.Cmp(amount) < 0 {
		return nil, fmt.Errorf("2WAY StabilityPool: withdraw exceeds deposit")
	}

	// Update user deposit
	newDeposit := new(big.Int).Sub(currentDeposit, amount)
	acc.Storage[depositKey] = writeSlot(newDeposit)

	// Update pool total deposits
	totalKey := storageKey([]byte("totalDeposits"))
	totalDeposits := readBigInt(acc.Storage[totalKey])
	acc.Storage[totalKey] = writeSlot(new(big.Int).Sub(totalDeposits, amount))

	// Update 2WAY balance
	twoWayKey := storageKey([]byte("twoWayBalance"))
	twoWayBal := readBigInt(acc.Storage[twoWayKey])
	acc.Storage[twoWayKey] = writeSlot(new(big.Int).Sub(twoWayBal, amount))

	// Emit event
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("Withdrawn")),
		callerHash(caller),
	}, amount.Bytes(), blockNum)

	return amount.FillBytes(make([]byte, 32)), nil
}

// ── ClaimRewards: claim accumulated stability fees + liquidation penalties ──
func stabilityClaimRewards(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	addr := PrecompileAddrHex(0x19)
	acc := state.GetOrCreateAccount(addr)

	rewardKey := stabilityRewardKey(caller)
	pendingRewards := readBigInt(acc.Storage[rewardKey])
	lpFeeKey := storageKey(append([]byte{StabilitySlotLastDeposit}, []byte(caller)...))
	mintLpRewards := readBigInt(acc.Storage[lpFeeKey])
	pendingRewards = new(big.Int).Add(pendingRewards, mintLpRewards)

	if pendingRewards.Sign() <= 0 {
		return nil, fmt.Errorf("2WAY StabilityPool: no rewards to claim")
	}

	// Reset reward balance and protocol buckets.
	acc.Storage[rewardKey] = writeSlot(big.NewInt(0))
	acc.Storage[lpFeeKey] = writeSlot(big.NewInt(0))
	acc.Storage[storageKey([]byte("totalRewards"))] = writeSlot(big.NewInt(0))
	acc.Storage[storageKey([]byte("wayRewards"))] = writeSlot(big.NewInt(0))
	acc.Storage[storageKey([]byte("swayRewards"))] = writeSlot(big.NewInt(0))

	// Emit event
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("RewardsClaimed")),
		callerHash(caller),
	}, pendingRewards.Bytes(), blockNum)

	out := make([]byte, 32)
	pendingRewards.FillBytes(out)
	return out, nil
}

// ── Absorb: absorb debt from a liquidated vault ──
func stabilityAbsorb(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("2WAY StabilityPool: absorb input too short")
	}

	vaultID := input[4:36]

	// Get vault debt from 2WAY Vault
	vaultDebt := getVaultDebt(vaultID, state)
	if vaultDebt.Sign() <= 0 {
		return nil, fmt.Errorf("2WAY StabilityPool: vault has no debt")
	}

	addr := PrecompileAddrHex(0x19)
	acc := state.GetOrCreateAccount(addr)

	// Check pool has enough 2WAY to absorb
	twoWayKey := storageKey([]byte("twoWayBalance"))
	twoWayBal := readBigInt(acc.Storage[twoWayKey])
	if twoWayBal.Cmp(vaultDebt) < 0 {
		// Return false (all zeros)
		return make([]byte, 32), nil
	}

	// Absorb debt: reduce pool's 2WAY balance
	acc.Storage[twoWayKey] = writeSlot(new(big.Int).Sub(twoWayBal, vaultDebt))

	// Distribute rewards to depositors
	totalKey := storageKey([]byte("totalDeposits"))
	totalDeposits := readBigInt(acc.Storage[totalKey])
	if totalDeposits.Sign() > 0 {
		// Reward = vaultDebt * 10% (liquidation penalty)
		reward := new(big.Int).Mul(vaultDebt, big.NewInt(1000))
		reward = reward.Div(reward, big.NewInt(10000))
		distributeRewards(totalDeposits, reward, acc)
	}

	// Emit event
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("Absorbed")),
		stringToHash(vaultID),
	}, vaultDebt.Bytes(), blockNum)

	// Return true (last byte = 0x01)
	result := make([]byte, 32)
	result[31] = 0x01
	return result, nil
}

// ── distributeRewards: accumulate rewards for distribution ──
func distributeRewards(totalDeposits *big.Int, reward *big.Int, acc *Account) {
	if reward.Sign() <= 0 || totalDeposits.Sign() <= 0 {
		return
	}
	wayReward := new(big.Int).Div(new(big.Int).Set(reward), big.NewInt(2))
	swayReward := new(big.Int).Sub(new(big.Int).Set(reward), wayReward)

	wayKey := storageKey([]byte("wayRewards"))
	swayKey := storageKey([]byte("swayRewards"))
	totalRewardKey := storageKey([]byte("totalRewards"))

	acc.Storage[wayKey] = writeSlot(new(big.Int).Add(readBigInt(acc.Storage[wayKey]), wayReward))
	acc.Storage[swayKey] = writeSlot(new(big.Int).Add(readBigInt(acc.Storage[swayKey]), swayReward))
	acc.Storage[totalRewardKey] = writeSlot(new(big.Int).Add(readBigInt(acc.Storage[totalRewardKey]), reward))
}

// ── GetDeposit: read user's deposit ──
func stabilityGetDeposit(input []byte, caller string, state *StateDB) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("2WAY StabilityPool: getDeposit input too short")
	}

	userAddr := fmt.Sprintf("%x", input[4:36])
	addr := PrecompileAddrHex(0x19)
	acc := state.GetOrCreateAccount(addr)

	depositKey := stabilityDepositKey(userAddr)
	deposit := readBigInt(acc.Storage[depositKey])

	out := make([]byte, 32)
	deposit.FillBytes(out)
	return out, nil
}

// ── GetPoolStats: read pool statistics ──
// Output: totalDeposits[32] + twoWayBalance[32] + totalRewards[32]
func stabilityGetPoolStats(input []byte, caller string, state *StateDB) ([]byte, error) {
	addr := PrecompileAddrHex(0x19)
	acc := state.GetOrCreateAccount(addr)

	totalDeposits := readBigInt(acc.Storage[storageKey([]byte("totalDeposits"))])
	twoWayBalance := readBigInt(acc.Storage[storageKey([]byte("twoWayBalance"))])
	wayRewards := readBigInt(acc.Storage[storageKey([]byte("wayRewards"))])
	swayRewards := readBigInt(acc.Storage[storageKey([]byte("swayRewards"))])
	totalRewards := new(big.Int).Add(wayRewards, swayRewards)

	out := make([]byte, 96)
	totalDeposits.FillBytes(out[0:32])
	twoWayBalance.FillBytes(out[32:64])
	totalRewards.FillBytes(out[64:96])
	return out, nil
}

// ══════════════════════════════════════════════════════════════════════
// Storage key helpers
// ══════════════════════════════════════════════════════════════════════

func stabilityDepositKey(user string) [32]byte {
	return storageKey(append([]byte{StabilitySlotDeposits}, []byte(user)...))
}

func stabilityRewardKey(user string) [32]byte {
	return storageKey(append([]byte{StabilitySlotRewards}, []byte(user)...))
}

func stabilityMintedDebtKey(user string) [32]byte {
	return storageKey(append([]byte{StabilitySlotMintedDebt}, []byte(user)...))
}

func stabilityMintedDebt(user string, state *StateDB) *big.Int {
	addr := PrecompileAddrHex(0x19)
	acc := state.GetOrCreateAccount(addr)
	if acc == nil {
		return big.NewInt(0)
	}
	return readBigInt(acc.Storage[stabilityMintedDebtKey(user)])
}

func addStabilityMintedDebt(user string, amount *big.Int, state *StateDB) {
	addr := PrecompileAddrHex(0x19)
	acc := state.GetOrCreateAccount(addr)
	key := stabilityMintedDebtKey(user)
	acc.Storage[key] = writeSlot(new(big.Int).Add(readBigInt(acc.Storage[key]), amount))
}

func reduceStabilityMintedDebt(user string, amount *big.Int, state *StateDB) {
	addr := PrecompileAddrHex(0x19)
	acc := state.GetOrCreateAccount(addr)
	key := stabilityMintedDebtKey(user)
	current := readBigInt(acc.Storage[key])
	newVal := new(big.Int).Sub(current, amount)
	if newVal.Sign() < 0 {
		newVal = big.NewInt(0)
	}
	acc.Storage[key] = writeSlot(newVal)
}

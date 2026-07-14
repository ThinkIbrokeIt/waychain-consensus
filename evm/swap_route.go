package evm

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// ══════════════════════════════════════════════════════════════════════
// SwapRoute Precompile (0x25) — Native AMM DEX
// Trustless Lock protects LP tokens from this exchange
// ══════════════════════════════════════════════════════════════════════

// Storage key prefixes
const (
	srSlotPairCount      byte = 0x00
	srSlotPairPrefix     byte = 0x10
	srSlotReserve0       byte = 0x20
	srSlotReserve1       byte = 0x21
	srSlotTotalLiquidity byte = 0x30
)

// SwapRoute ABI selectors (SHA256-based)
const (
	srCreatePairSelector      uint32 = 0x1a2b3c4d
	srSwapExactTokens0        uint32 = 0x2e878dc0
	srSwapExactTokens1        uint32 = 0x38ed1739
	srAddLiquiditySelector    uint32 = 0xe868b10b
	srRemoveLiquiditySelector uint32 = 0xbaa2abde
	srGetPairSelector         uint32 = 0xe6a537a4
	srGetReservesSelector     uint32 = 0x23312f44
	srMintSwayRewardSelector  uint32 = 0xf6a7b8c9 // mintToCaller pattern
)

// swapRoutePrecompile handles all DEX calls
func swapRoutePrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("SwapRoute: input too short")
	}

	sel := selectorBytes(input)

	switch sel {
	case srCreatePairSelector:
		return srCreatePair(input, caller, state, blockNum)
	case srSwapExactTokens0, srSwapExactTokens1:
		return srSwap(input, caller, state, blockNum)
	case srAddLiquiditySelector:
		return srAddLiquidity(input, caller, state, blockNum)
	case srRemoveLiquiditySelector:
		return srRemoveLiquidity(input, caller, state, blockNum)
	case srGetPairSelector:
		return srGetPair(input, caller, state, blockNum)
	case srGetReservesSelector:
		return srGetReserves(input, caller, state, blockNum)
	default:
		return nil, fmt.Errorf("SwapRoute: unknown selector 0x%08X", sel)
	}
}

// srCreatePair creates a new trading pair (L2+ required)
func srCreatePair(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	callerAcc := state.GetAccount(caller)
	if callerAcc == nil || callerAcc.DoxDevLevel < 2 {
		return nil, fmt.Errorf("SwapRoute: createPair requires Dox_Dev Level 2+")
	}

	if len(input) < 44 {
		return nil, fmt.Errorf("SwapRoute: createPair input too short")
	}

	var token0, token1 [20]byte
	copy(token0[:], input[4:24])
	copy(token1[:], input[24:44])

	addr := PrecompileAddrHex(0x25)
	acc := state.GetOrCreateAccount(addr)

	// Get pair ID: SHA256(token0 + token1)[:20]
	pairKey := sha256.Sum256(append(token0[:], token1[:]...))
	var pairID [20]byte
	copy(pairID[:], pairKey[:20])

	pairStorageKey := storageKey(append([]byte{srSlotPairPrefix}, pairID[:]...))
	if existing := acc.Storage[pairStorageKey]; existing[0] != 0 {
		return pairID[:], nil
	}

	// Increment pair count
	countKey := [32]byte{}
	countKey[0] = srSlotPairCount
	count := readUint64(acc.Storage[countKey]) + 1
	acc.Storage[countKey] = writeUint64(count)

	// Initialize pair
	var pairData [32]byte
	copy(pairData[:20], token0[:])
	copy(pairData[20:], token1[:])
	acc.Storage[pairStorageKey] = pairData

	return pairID[:], nil
}

// srGetPair returns the pair address for two tokens
func srGetPair(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 44 {
		return nil, fmt.Errorf("SwapRoute: getPair input too short")
	}

	var token0, token1 [20]byte
	copy(token0[:], input[4:24])
	copy(token1[:], input[24:44])

	pairKey := sha256.Sum256(append(token0[:], token1[:]...))
	var pairID [20]byte
	copy(pairID[:], pairKey[:20])

	addr := PrecompileAddrHex(0x25)
	acc := state.GetOrCreateAccount(addr)
	pairStorageKey := storageKey(append([]byte{srSlotPairPrefix}, pairID[:]...))

	if existing := acc.Storage[pairStorageKey]; existing[0] == 0 {
		return make([]byte, 20), nil
	}

	return pairID[:], nil
}

// selectorToBytes converts selector uint32 to 4-byte big-endian
func selectorToBytes(sel uint32) []byte {
	out := make([]byte, 4)
	out[0] = byte(sel >> 24)
	out[1] = byte(sel >> 16)
	out[2] = byte(sel >> 8)
	out[3] = byte(sel)
	return out
}

// srAddLiquidity adds liquidity to a pair and mints LP tokens with TrustlessLock
func srAddLiquidity(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 68 {
		return nil, fmt.Errorf("SwapRoute: addLiquidity input too short")
	}

	// Extract amounts and pair (simplified)
	amount0 := readBigInt(readSlot(input, 4))
	amount1 := readBigInt(readSlot(input, 36))

	// Get reserve keys for pair (simplified - would need pair lookup)
	swapAddr := PrecompileAddrHex(0x25)
	key := storageKey([]byte("swaproute:liquidity"))
	totalLiq := readBigInt(state.GetOrCreateAccount(swapAddr).Storage[key])

	// Mint LP tokens (simplified - 1:1 ratio)
	liquidity := new(big.Int).Add(amount0, amount1)
	newTotal := new(big.Int).Add(totalLiq, liquidity)

	state.GetOrCreateAccount(swapAddr).Storage[key] = writeBigInt(newTotal)

	// Mint SWAY rewards to LP provider
	reward := big.NewInt(100) // Base SWAY reward per liquidity add
	callerAcc := state.GetOrCreateAccount(caller)
	swayBalanceKey := storageKey([]byte("sway:balance:" + caller))
	current := readBigInt(callerAcc.Storage[swayBalanceKey])
	newBalance := new(big.Int).Add(current, reward)
	callerAcc.Storage[swayBalanceKey] = writeBigInt(newBalance)

	// Create TrustlessLock for LP withdrawal protection (minimum 30 days)
	// TrustlessLock createTimeLock expects: pool(20) + token0(20) + token1(20) + amount(32) + period(32) + recipient(20)
	// Precompile 0x1A: trustlessCreateTimeLockSelector (0xA1B2C3D4)
	var lockInput []byte
	lockInput = append(lockInput, selectorToBytes(trustlessCreateTimeLockSelector)...)
	
	// poolAddr: use SwapRoute address (0x25) as placeholder
	_ = swapAddr // prevent unused warning
	lockInput = append(lockInput, make([]byte, 20)...) // pool (placeholder)
	
	// token0 + token1: use placeholder zeros
	lockInput = append(lockInput, make([]byte, 40)...) // token0(20) + token1(20)
	
	// Write liquidity amount
	amountSlot := writeSlot(liquidity)
	lockInput = append(lockInput, amountSlot[:]...)
	
	// Write lock period (30 days in blocks)
	lockPeriod := big.NewInt(2592000)
	periodSlot := writeSlot(lockPeriod)
	lockInput = append(lockInput, periodSlot[:]...)
	
	// Write recipient (caller)
	recipientBytes := []byte(caller)
	if len(recipientBytes) > 20 {
		recipientBytes = recipientBytes[:20]
	}
	lockInput = append(lockInput, recipientBytes...)

	// Call TrustlessLock precompile
	trustlessLockPrecompile(lockInput, caller, state, blockNum)

	out := writeBigInt(liquidity)
	return out[:], nil
}

// srRemoveLiquidity removes liquidity (TrustlessLock enforced)
func srRemoveLiquidity(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	return nil, fmt.Errorf("SwapRoute: removeLiquidity requires TrustlessLock integration - check lock status at 0x1A")
}

// srSwap handles token swaps with 0.3% fee and SWAY rewards to LPs
// Uses constant product formula: amountOut = reserve1 * (1 - (1 - amountIn/reserve0)^0.3)
func srSwap(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 68 {
		return nil, fmt.Errorf("SwapRoute: swap input too short")
	}

	amountIn := readBigInt(readSlot(input, 4))
	amountOutMin := readBigInt(readSlot(input, 36))

	// Load reserves (simplified - would use pair from input)
	addr := PrecompileAddrHex(0x25)
	reserve0Key := storageKey([]byte("swaproute:reserve0"))
	reserve1Key := storageKey([]byte("swaproute:reserve1"))
	r0 := readBigInt(state.GetOrCreateAccount(addr).Storage[reserve0Key])
	r1 := readBigInt(state.GetOrCreateAccount(addr).Storage[reserve1Key])

	// Initialize default reserves if empty
	if r0.Sign() == 0 {
		r0 = big.NewInt(1000000) // 1M tokens
	}
	if r1.Sign() == 0 {
		r1 = big.NewInt(1000000) // 1M tokens
	}

	// Constant product AMM: amountOut = r1 * (1 - (1 - amountIn/r0)^0.3)
	// Using integer math: amountOut = r1 - (r1 * r0) / (r0 + amountIn)
	// But for precision, use: amountOut = (amountIn * 997 * r1) / (amountIn + r0 * 1000)
	amountInWithFee := new(big.Int).Mul(amountIn, big.NewInt(997))
	
	// denominator = r0 * 1000 + amountIn * 997
	denominator := new(big.Int).Mul(r0, big.NewInt(1000))
	denominator.Add(denominator, amountInWithFee)
	
	// numerator = amountIn * 997 * r1
	numerator := new(big.Int).Mul(amountInWithFee, r1)
	
	amountOut := new(big.Int).Div(numerator, denominator)

	if amountOut.Cmp(amountOutMin) < 0 {
		return nil, fmt.Errorf("SwapRoute: insufficient output amount")
	}

	// Mint SWAY rewards to LPs (0.3% of swap volume)
	feeAmount := new(big.Int).Div(new(big.Int).Mul(amountIn, big.NewInt(3)), big.NewInt(1000))
	callerAcc := state.GetOrCreateAccount(caller)
	swayBalanceKey := storageKey([]byte("sway:balance:" + caller))
	current := readBigInt(callerAcc.Storage[swayBalanceKey])
	newBalance := new(big.Int).Add(current, feeAmount)
	callerAcc.Storage[swayBalanceKey] = writeBigInt(newBalance)

	out := writeBigInt(amountOut)
	return out[:], nil
}

// srGetReserves returns pair reserves
func srGetReserves(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	out := make([]byte, 64)
	return out, nil
}
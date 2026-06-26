package evm

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// trimRightZeros removes trailing zero bytes
func trimRightZeros(b []byte) []byte {
	end := len(b)
	for end > 0 && b[end-1] == 0 {
		end--
	}
	return b[:end]
}

// hasPrefix checks if b starts with prefix
func hasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

// min returns the smaller of a and b
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ══════════════════════════════════════════════════════════════════════
// 2WAY Vault Precompile (0x18)
// Multi-stablecoin CDP: deposit stablecoins, mint 2WAY synthetic USD
// ══════════════════════════════════════════════════════════════════════

// Storage slot prefixes
const (
	TwoWaySlotCollateral     byte = 0x02 // vaultId+stablecoin → amount
	TwoWaySlotDebt           byte = 0x03 // vaultId → debt amount
	TwoWaySlotParams         byte = 0x04 // key → value
	TwoWaySlotVaultCount     byte = 0x05 // → total vaults count
	TwoWaySlotCollateralList byte = 0x06 // → accepted stablecoins list
)

// Collateral parameters per stablecoin
type CollateralParam struct {
	MinCRatio        uint16 // e.g., 13000 = 130%
	LiquidationRatio uint16 // e.g., 12000 = 120%
	StabilityFee     uint16 // e.g., 150 = 1.5% APR (basis points)
	MaxDebtPercent   uint16 // max % of total debt (e.g., 3000 = 30%)
	DebtFloor        uint64 // minimum debt
}

// ── 2WAY ABI Selectors (sha256[:4]) ──
const (
	twoWayDepositSelector    uint32 = 0xFBB35030 // deposit(bytes32,bytes32,uint256)
	twoWayMintSelector       uint32 = 0xD185E07F // mint(bytes32,uint256)
	twoWayWithdrawSelector   uint32 = 0xE9C4B112 // withdraw(bytes32,bytes32,uint256)
	twoWayBurnSelector       uint32 = 0x0E0C59BE // burn(bytes32,uint256)
	twoWayLiquidateSelector  uint32 = 0x5C8B7698 // liquidate(bytes32)
	twoWayGetVaultSelector   uint32 = 0x9EB29EF0 // getVault(bytes32) → (uint256,uint256)
	twoWayVaultCountSelector uint32 = 0x67A9F0F5 // vaultCount() → uint256
	selTwoWayGetPrice         uint32 = 0x7A3B4F00 // getStablecoinPrice(bytes32) → uint256
)

// ── 2WAY Vault Precompile ──

func twoWayVaultPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("2WAY: input too short")
	}

	sel := selectorBytes(input)

	switch sel {
	case twoWayDepositSelector:
		return twoWayDeposit(input, caller, state, blockNum)
	case twoWayMintSelector:
		return twoWayMint(input, caller, state, blockNum)
	case twoWayWithdrawSelector:
		return twoWayWithdraw(input, caller, state, blockNum)
	case twoWayBurnSelector:
		return twoWayBurn(input, caller, state, blockNum)
	case twoWayLiquidateSelector:
		return twoWayLiquidate(input, caller, state, blockNum)
	case twoWayGetVaultSelector:
		return twoWayGetVault(input, caller, state)
	case twoWayVaultCountSelector:
		return twoWayVaultCount(input, caller, state)
	case selTwoWayGetPrice:
		return twoWayGetStablecoinPrice(input, caller, state)
	default:
		return nil, fmt.Errorf("2WAY: unknown selector 0x%08X", sel)
	}
}

// ── helper: read [32]byte from input at offset ──
func readSlot(input []byte, offset int) [32]byte {
	var slot [32]byte
	if offset+32 <= len(input) {
		copy(slot[:], input[offset:offset+32])
	}
	return slot
}

// ── helper: write *big.Int to [32]byte slot ──
func writeSlot(val *big.Int) [32]byte {
	var slot [32]byte
	b := val.Bytes()
	copy(slot[32-len(b):], b)
	return slot
}

// ── Deposit: deposit stablecoins into vault ──
// Input: vaultId[32] + stablecoin[20] + amount[32]
func twoWayDeposit(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+20+32 {
		return nil, fmt.Errorf("2WAY: deposit input too short (%d bytes)", len(input))
	}

	vaultID := input[4:36]
	collAddr := make([]byte, 20)
	copy(collAddr, input[36:56])
	
	// Extract collateral identifier (trim trailing zeros for short names)
	collateralID := string(trimRightZeros(collAddr))
	collAmount := readBigInt(readSlot(input, 56))
	
	// Validate collateral is accepted
	if !isAcceptedCollateral(collateralID, state) {
		return nil, fmt.Errorf("2WAY: collateral %s not accepted", collateralID)
	}

	// Store collateral
	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)
	collKey := collateralKey(vaultID, collateralID)
	acc.Storage[collKey] = writeSlot(collAmount)

	// Emit event
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("Deposited")),
		stringToHash(vaultID),
		callerHash(caller),
	}, collAmount.Bytes(), blockNum)

	return vaultID, nil
}

// ── Mint: mint 2WAY against deposited collateral ──
// Input: vaultId[32] + amount[32]
func twoWayMint(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+32 {
		return nil, fmt.Errorf("2WAY: mint input too short")
	}

	vaultID := input[4:36]
	amount := readBigInt(readSlot(input, 36))

	// Get vault state
	collaterals := getVaultCollaterals(vaultID, state)
	vaultDebt := getVaultDebt(vaultID, state)

	// Check vault has collateral
	totalCollateral := big.NewInt(0)
	for _, v := range collaterals {
		totalCollateral = totalCollateral.Add(totalCollateral, v)
	}
	if totalCollateral.Sign() == 0 {
		return nil, fmt.Errorf("2WAY: vault has no collateral")
	}

	// Check C-Ratio after minting
	newDebt := new(big.Int).Add(vaultDebt, amount)
	if !isAboveMinCRatio(collaterals, newDebt, big.NewInt(0), state) {
		return nil, fmt.Errorf("2WAY: mint would violate minimum collateral ratio")
	}

	// Update debt
	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)
	acc.Storage[debtKey(vaultID)] = writeSlot(newDebt)

	// Update total debt
	addTotalDebt(amount, state)

	// Emit event
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("Minted")),
		stringToHash(vaultID),
		callerHash(caller),
	}, amount.Bytes(), blockNum)

	return vaultID, nil
}

// ── Withdraw: withdraw collateral from vault ──
// Input: vaultId[32] + stablecoin[20] + amount[32]
func twoWayWithdraw(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+20+32 {
		return nil, fmt.Errorf("2WAY: withdraw input too short")
	}

	vaultID := input[4:36]
	collAddr := make([]byte, 20)
	copy(collAddr, input[36:56])
	// Extract collateral identifier (trim trailing zeros for short names)
	collateralID := string(trimRightZeros(collAddr))
	collAmount := readBigInt(readSlot(input, 56))

	// Get vault state
	collaterals := getVaultCollaterals(vaultID, state)
	vaultDebt := getVaultDebt(vaultID, state)

	// Check withdrawal doesn't exceed deposit
	currentColl := collaterals[collateralID]
	if currentColl == nil || currentColl.Cmp(collAmount) < 0 {
		return nil, fmt.Errorf("2WAY: withdraw amount exceeds deposit")
	}

	// Check C-Ratio after withdrawal
	newCollValue := new(big.Int).Sub(currentColl, collAmount)
	collateralsAfter := make(map[string]*big.Int, len(collaterals))
	for k, v := range collaterals {
		collateralsAfter[k] = v
	}
	collateralsAfter[collateralID] = newCollValue

	if !isAboveMinCRatio(collateralsAfter, vaultDebt, big.NewInt(0), state) {
		return nil, fmt.Errorf("2WAY: withdraw would violate minimum collateral ratio")
	}

	// Update collateral
	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)
	collKey := collateralKey(vaultID, collateralID)
	acc.Storage[collKey] = writeSlot(newCollValue)

	// Emit event
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("Withdrawn")),
		stringToHash(vaultID),
		callerHash(caller),
	}, collAmount.Bytes(), blockNum)

	return vaultID, nil
}

// ── Burn: repay 2WAY debt ──
// Input: vaultId[32] + amount[32]
func twoWayBurn(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+32 {
		return nil, fmt.Errorf("2WAY: burn input too short")
	}

	vaultID := input[4:36]
	amount := readBigInt(readSlot(input, 36))

	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)

	// Reduce vault debt
	vaultDebtKey := debtKey(vaultID)
	currentDebt := readBigInt(acc.Storage[vaultDebtKey])
	newDebt := new(big.Int).Sub(currentDebt, amount)
	if newDebt.Sign() < 0 {
		newDebt = big.NewInt(0)
	}
	acc.Storage[vaultDebtKey] = writeSlot(newDebt)

	// Update total debt
	reduceTotalDebt(amount, state)

	// Emit event
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("Burned")),
		stringToHash(vaultID),
		callerHash(caller),
	}, amount.Bytes(), blockNum)

	return vaultID, nil
}

// ── Liquidate: liquidate an undercollateralized vault ──
// Input: vaultId[32]
func twoWayLiquidate(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("2WAY: liquidate input too short")
	}

	vaultID := input[4:36]

	// Get vault state
	getVaultCollaterals(vaultID, state) // populate collateral data
	vaultDebt := getVaultDebt(vaultID, state)

	// Check if vault is below liquidation ratio
	if isAboveLiquidationRatio(vaultID, vaultDebt, state) {
		return nil, fmt.Errorf("2WAY: vault is above liquidation ratio")
	}

	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)

	// Clear vault debt
	acc.Storage[debtKey(vaultID)] = writeSlot(big.NewInt(0))

	// Update total debt
	reduceTotalDebt(vaultDebt, state)

	// Emit event
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("Liquidated")),
		stringToHash(vaultID),
		callerHash(caller),
	}, vaultDebt.Bytes(), blockNum)

	return vaultID, nil
}

// ── GetVault: read vault state ──
// Input: vaultId[32] → Output: collateralValue[32] + debt[32]
func twoWayGetVault(input []byte, caller string, state *StateDB) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("2WAY: getVault input too short")
	}

	vaultID := input[4:36]
	collaterals := getVaultCollaterals(vaultID, state)
	debt := getVaultDebt(vaultID, state)

	// Return: totalCollateralValue[32] + debt[32]
	totalCollateral := big.NewInt(0)
	for _, v := range collaterals {
		totalCollateral = totalCollateral.Add(totalCollateral, v)
	}

	out := make([]byte, 64)
	totalCollateral.FillBytes(out[0:32])
	debt.FillBytes(out[32:64])
	return out, nil
}

// ── VaultCount: read total vaults ──
func twoWayVaultCount(input []byte, caller string, state *StateDB) ([]byte, error) {
	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)
	count := readBigInt(acc.Storage[storageKey([]byte("vaultCount"))])
	out := make([]byte, 32)
	count.FillBytes(out)
	return out, nil
}

// ══════════════════════════════════════════════════════════════════════
// Storage key helpers
// ══════════════════════════════════════════════════════════════════════

func collateralKey(vaultID []byte, stablecoin string) [32]byte {
	// Direct key: prefix(1) + vaultID(20) + stablecoin(11) → 32 bytes
	key := make([]byte, 32)
	key[0] = TwoWaySlotCollateral
	copy(key[1:21], vaultID[:20])
	stableBytes := []byte(stablecoin)
	copy(key[21:32], stableBytes[:min(11, len(stableBytes))])
	return *(*[32]byte)(key)
}

func debtKey(vaultID []byte) [32]byte {
	// Direct key: prefix(1) + vaultID(31) → 32 bytes
	key := make([]byte, 32)
	key[0] = TwoWaySlotDebt
	copy(key[1:32], vaultID[:31])
	return *(*[32]byte)(key)
}

func paramKey(key string) [32]byte {
	return storageKey(append([]byte{TwoWaySlotParams}, []byte(key)...))
}

// ══════════════════════════════════════════════════════════════════════
// State getters
// ══════════════════════════════════════════════════════════════════════

func getVaultDebt(vaultID []byte, state *StateDB) *big.Int {
	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)
	if acc == nil {
		return big.NewInt(0)
	}
	return readBigInt(acc.Storage[debtKey(vaultID)])
}

func getVaultCollaterals(vaultID []byte, state *StateDB) map[string]*big.Int {
	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)
	result := make(map[string]*big.Int)
	if acc == nil {
		return result
	}

	// Iterate all storage slots looking for collateral entries for this vault
	for slotKey, slotVal := range acc.Storage {
		if len(slotKey) != 32 || slotKey[0] != TwoWaySlotCollateral {
			continue
		}
		// Check if this key belongs to our vaultID (bytes 1-20)
		if hasPrefix(slotKey[1:21], vaultID[:20]) {
			// Extract stablecoin name from bytes 21-32
			nameBytes := slotKey[21:]
			collName := string(trimRightZeros(nameBytes))
			if collName != "" {
				result[collName] = readBigInt(slotVal)
			}
		}
	}

	return result
}

// getVaultCollateralValueUSD computes total collateral value using oracle prices
func getVaultCollateralValueUSD(vaultID []byte, state *StateDB) *big.Int {
	collaterals := getVaultCollaterals(vaultID, state)
	totalUSD := big.NewInt(0)

	for collName, amount := range collaterals {
		if amount.Sign() <= 0 {
			continue
		}
		// Get price from oracle (default $1.00 for stablecoins)
		priceKey := storageKey([]byte("price:" + collName))
		twoWayAddr := PrecompileAddrHex(0x18)
		acc := state.GetOrCreateAccount(twoWayAddr)
		price := readBigInt(acc.Storage[priceKey])
		if price.Sign() == 0 {
			price = new(big.Int).SetUint64(100000000) // $1.00 default
		}
		// value = amount * price / 1e8
		value := new(big.Int).Mul(amount, price)
		value = value.Div(value, big.NewInt(100000000))
		totalUSD = totalUSD.Add(totalUSD, value)
	}

	return totalUSD
}

func getCollateralParam(stablecoin string, state *StateDB) CollateralParam {
	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)
	if acc == nil {
		return DefaultCollateralParam(stablecoin)
	}

	minCRatio := readUint16(acc.Storage[paramKey(stablecoin + ":minCRatio")], 15000)
	liqRatio := readUint16(acc.Storage[paramKey(stablecoin + ":liqRatio")], 14000)
	fee := readUint16(acc.Storage[paramKey(stablecoin + ":fee")], 150)
	maxDebt := readUint16(acc.Storage[paramKey(stablecoin + ":maxDebt")], 3000)

	return CollateralParam{
		MinCRatio:        minCRatio,
		LiquidationRatio: liqRatio,
		StabilityFee:     fee,
		MaxDebtPercent:   maxDebt,
		DebtFloor:        1e18,
	}
}

func DefaultCollateralParam(stablecoin string) CollateralParam {
	switch stablecoin {
	case "USDC", "USDT":
		return CollateralParam{15000, 14000, 150, 3000, 1e18}
	default:
		return CollateralParam{13000, 12000, 150, 3000, 1e18}
	}
}

func isAcceptedCollateral(stablecoin string, state *StateDB) bool {
	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)
	if acc == nil {
		// Accept any collateral if precompile is not initialized (first call)
		return true
	}
	_, ok := acc.Storage[paramKey(stablecoin + ":minCRatio")]
	return ok
}

// ══════════════════════════════════════════════════════════════════════
// Collateral ratio checks
// ══════════════════════════════════════════════════════════════════════

func isAboveMinCRatio(collaterals map[string]*big.Int, debt *big.Int, additionalDebt *big.Int, state *StateDB) bool {
	totalCollateral := big.NewInt(0)
	for _, v := range collaterals {
		totalCollateral = totalCollateral.Add(totalCollateral, v)
	}

	totalDebt := new(big.Int).Add(debt, additionalDebt)
	if totalDebt.Sign() == 0 {
		return true
	}

	ratio := new(big.Int).Mul(totalCollateral, big.NewInt(10000))
	ratio = ratio.Div(ratio, totalDebt)

	return ratio.Cmp(big.NewInt(13000)) >= 0
}

func isAboveMinCRatioWithVault(vaultID []byte, debt *big.Int, additionalDebt *big.Int, state *StateDB) bool {
	totalCollateral := getVaultCollateralValueUSD(vaultID, state)
	totalDebt := new(big.Int).Add(debt, additionalDebt)
	if totalDebt.Sign() == 0 {
		return true
	}
	ratio := new(big.Int).Mul(totalCollateral, big.NewInt(10000))
	ratio = ratio.Div(ratio, totalDebt)
	return ratio.Cmp(big.NewInt(13000)) >= 0
}

func isAboveLiquidationRatio(vaultID []byte, debt *big.Int, state *StateDB) bool {
	totalCollateralUSD := getVaultCollateralValueUSD(vaultID, state)

	if debt.Sign() == 0 {
		return true
	}

	ratio := new(big.Int).Mul(totalCollateralUSD, big.NewInt(10000))
	ratio = ratio.Div(ratio, debt)

	return ratio.Cmp(big.NewInt(14000)) > 0
}

// ══════════════════════════════════════════════════════════════════════
// Total debt tracking
// ══════════════════════════════════════════════════════════════════════

func addTotalDebt(amount *big.Int, state *StateDB) {
	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)
	key := storageKey([]byte("totalDebt"))
	current := readBigInt(acc.Storage[key])
	acc.Storage[key] = writeSlot(new(big.Int).Add(current, amount))
}

func reduceTotalDebt(amount *big.Int, state *StateDB) {
	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)
	key := storageKey([]byte("totalDebt"))
	current := readBigInt(acc.Storage[key])
	newDebt := new(big.Int).Sub(current, amount)
	if newDebt.Sign() < 0 {
		newDebt = big.NewInt(0)
	}
	acc.Storage[key] = writeSlot(newDebt)
}

// ══════════════════════════════════════════════════════════════════════
// Utility functions
// ══════════════════════════════════════════════════════════════════════

func stringToHash(s []byte) [32]byte {
	return sha256.Sum256(s)
}

func callerHash(caller string) [32]byte {
	return sha256.Sum256([]byte(caller))
}

func readUint16(slot [32]byte, defaultVal uint16) uint16 {
	v := new(big.Int).SetBytes(slot[:]).Uint64()
	if v == 0 {
		return defaultVal
	}
	return uint16(v)
}

// ── GetStablecoinPrice: read median price from oracle attestations ──
// Input: stablecoinId[32]
// Output: price[32] (8 decimals, e.g., 100000000 = $1.00)
func twoWayGetStablecoinPrice(input []byte, caller string, state *StateDB) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("2WAY: getPrice input too short")
	}

	stablecoinID := string(trimRightZeros(input[4:36]))

	// Read price from oracle storage
	priceKey := storageKey([]byte("price:" + stablecoinID))
	twoWayAddr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(twoWayAddr)

	priceSlot := acc.Storage[priceKey]
	price := readBigInt(priceSlot)

	// If no price set, default to $1.00 (8 decimals)
	if price.Sign() == 0 {
		price = new(big.Int).SetUint64(100000000) // $1.00000000
	}

	out := make([]byte, 32)
	price.FillBytes(out)
	return out, nil
}

// ── SetStablecoinPrice: oracle submits a price attestation ──
// Input: stablecoinId[32] + price[32]
// Only verified oracles (Dox_Dev L2+) can submit
func twoWaySetStablecoinPrice(input []byte, caller string, state *StateDB) ([]byte, error) {
	if len(input) < 4+32+32 {
		return nil, fmt.Errorf("2WAY: setPrice input too short")
	}

	stablecoinID := string(trimRightZeros(input[4:36]))
	price := readBigInt(readSlot(input, 36))

	// Only verified oracles can submit prices
	callerAcc := state.GetAccount(caller)
	if callerAcc == nil || callerAcc.DoxDevLevel < 2 {
		return nil, fmt.Errorf("2WAY: caller is not a verified oracle (Dox_Dev L2+ required)")
	}

	// Store price
	priceKey := storageKey([]byte("price:" + stablecoinID))
	twoWayAddr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(twoWayAddr)
	acc.Storage[priceKey] = writeSlot(price)

	// Emit event
	state.AddLog(twoWayAddr, [][32]byte{
		storageKey([]byte("PriceUpdated")),
		stringToHash([]byte(stablecoinID)),
	}, price.Bytes(), 0)

	return price.FillBytes(make([]byte, 32)), nil
}

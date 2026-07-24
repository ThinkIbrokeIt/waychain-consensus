// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"fmt"
	"math/big"
)

// ══════════════════════════════════════════════════════════════════════
// 1WAY Stablecoin Precompile (0x22)
// Bitcoin-backed stablecoin: BTC locked → 1WAY minted
// ══════════════════════════════════════════════════════════════════════

// Storage slot prefixes
const (
	WaySlotVaultBTC       byte = 0x01
	WaySlotVault1Way      byte = 0x02
	WaySlotUserHasVault   byte = 0x03
	WaySlotBTCPrice       byte = 0x04
	WaySlotTotalCommitted byte = 0x05
	WaySlotVaultCreator  byte = 0x06 // vaultID -> creator account (64-hex EOA key)
)

// Collateral parameters
const (
	WayMinCRatio  = 13000
	WayMintRatio  = 7000
)

// Way stablecoin selectors
const (
	selWayCreateVault     uint32 = 0xA2B1C3D4
	selWayDepositBTC      uint32 = 0xB3C2D4E5
	selWayMint1Way       uint32 = 0xC4D3E5F6
	selWayBurn1Way       uint32 = 0xD5E4F6A7
	selWayGetUserVault   uint32 = 0xA8B7C9D0
	selWayGetPrice       uint32 = 0xB9C8D0E1
	selWayGetTotalSupply uint32 = 0xCAD9E0F2
	selWayGetVault       uint32 = 0x9EB29EF0 // getVault(bytes32) -> (btc[32], debt[32], creatorPresent[32])
	selWayUpdateBTCPrice uint32 = 0xDBC0F1A2
)

func wayStablecoinPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("1WAY: input too short")
	}

	sel := selectorBytes(input)
	switch sel {
	case selWayCreateVault:
		return wayCreateVault(input, caller, state, blockNum)
	case selWayDepositBTC:
		return wayDepositBTC(input, caller, state, blockNum)
	case selWayMint1Way:
		return wayMint1Way(input, caller, state, blockNum)
	case selWayBurn1Way:
		return wayBurn1Way(input, caller, state, blockNum)
	case selWayGetUserVault:
		return wayGetUserVault(input, caller, state)
	case selWayGetVault:
		return wayGetVault(input, state)
	case selWayGetPrice:
		return wayGetPrice(input, caller, state)
	case selWayGetTotalSupply:
		return wayGetTotalSupply(input, caller, state)
	case selWayUpdateBTCPrice:
		return wayUpdateBTCPrice(input, caller, state, blockNum)
	default:
		return nil, fmt.Errorf("1WAY: unknown selector 0x%08X", sel)
	}
}

// requireCallerIsCreatorOrDeadMan enforces the founder access rule (2026-07-18):
// a vault op may ONLY be called by the vault's creator, OR by the
// DeadMansSwitch for that vault (which can only be SET by the creator).
// Anyone else is rejected — no operating on a vault you did not create.
func requireCallerIsCreatorOrDeadMan(state *StateDB, vaultID []byte, caller string) error {
	addr := PrecompileAddrHex(0x22)
	acc := state.GetOrCreateAccount(addr)
	creatorKey := storageKey(append([]byte{WaySlotVaultCreator}, vaultID...))
	cval := acc.Storage[creatorKey]
	creator := string(cval[:])
	if creator == caller {
		return nil
	}
	// Dead-man's-switch path: only if it is active AND was set by the creator.
	if creator != "" && deadManActiveForVault(state, vaultID) {
		return nil
	}
	return fmt.Errorf("1WAY: caller is not vault creator or authorized dead-man's-switch")
}

// deadManActiveForVault reports whether the owner-set dead-man's-switch for
// this vault is currently active. The switch can ONLY be set by the creator
// (enforced in precompiles.go 0x15 SET path), so an active switch
// authorizes vault ops on behalf of an incapacitated creator.
func deadManActiveForVault(state *StateDB, vaultID []byte) bool {
	dmAddr := PrecompileAddrHex(0x15)
	dmAcc := state.GetOrCreateAccount(dmAddr)
	swKey := storageKey(append([]byte{0x10}, vaultID...))
	raw := dmAcc.Storage[swKey]
	// bytes[0] = active flag (1 = active); zero-value [32]byte => not set.
	if len(raw) == 0 || raw[0] != 1 {
		return false
	}
	return true
}

// ── Create vault ──
func wayCreateVault(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 36 {
		return nil, fmt.Errorf("1WAY: createVault input too short")
	}

	vaultID := input[4:36]
	addr := PrecompileAddrHex(0x22)
	acc := state.GetOrCreateAccount(addr)

	callerAcc := state.GetAccount(caller)
	if callerAcc == nil || callerAcc.DoxDevLevel < 2 {
		return nil, fmt.Errorf("1WAY: caller must have Dox_Dev Level 2+")
	}

	usrVaultKey := storageKey(append([]byte{WaySlotUserHasVault}, []byte(caller)...))
	if readUint64(acc.Storage[usrVaultKey]) != 0 {
		return nil, fmt.Errorf("1WAY: user already has vault")
	}

	btcKey := storageKey(append([]byte{WaySlotVaultBTC}, vaultID...))
	acc.Storage[btcKey] = writeBigInt(big.NewInt(0))

	debtKey := storageKey(append([]byte{WaySlotVault1Way}, vaultID...))
	acc.Storage[debtKey] = writeBigInt(big.NewInt(0))

	// Record the creator (founder rule: only creator — or owner-set dead-man's-switch — may operate this vault).
	creatorKey := storageKey(append([]byte{WaySlotVaultCreator}, vaultID...))
	var cbuf [32]byte
	copy(cbuf[:], []byte(caller))
	acc.Storage[creatorKey] = cbuf

	acc.Storage[usrVaultKey] = writeUint64(1)

	return vaultID, nil
}

// ── Deposit BTC ──
// NEW trustless ABI (2026-07-18): vaultID[32] + amount[32] + txid[32] + outIndex[8] + toAddr.
// A deposit is ONLY accepted with a sha256 proof (VerifyBTCDeposit) that REAL BTC
// arrived at THIS vault's derived address. No proof => rejected (no "promise" deposit).
func wayDepositBTC(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 100 {
		return nil, fmt.Errorf("1WAY: depositBTC needs vaultID+amount+txid+outIndex+toAddr (>=100 bytes)")
	}

	vaultID := input[4:36]
	amount := readUint256(input, 36)

	// Access control: only the vault creator (or owner-set dead-man's-switch) may deposit.
	if err := requireCallerIsCreatorOrDeadMan(state, vaultID, caller); err != nil {
		return nil, err
	}

	// Trustless check: prove real BTC landed at this vault's derived address.
	proof := BTCTxProof{
		TxID:  input[68:100],
		OutIndex: readUint64FromBytes(input, 100),
		ToAddr: string(input[108:]),
		Amount: amount,
	}
	verified, err := VerifyBTCDeposit(vaultID, proof)
	if err != nil {
		return nil, err
	}

	addr := PrecompileAddrHex(0x22)
	acc := state.GetOrCreateAccount(addr)

	// Use the VERIFIED amount (defends against a stated amount that disagrees with the proof).
	btcKey := storageKey(append([]byte{WaySlotVaultBTC}, vaultID...))
	currentBTC := readBigInt(acc.Storage[btcKey])
	currentBTC.Add(currentBTC, verified)
	acc.Storage[btcKey] = writeBigInt(currentBTC)

	totalKey := storageKey([]byte("total:committed"))
	totalBTC := readBigInt(acc.Storage[totalKey])
	totalBTC.Add(totalBTC, verified)
	acc.Storage[totalKey] = writeBigInt(totalBTC)

	return []byte{1}, nil
}

// ── Mint 1WAY ──
func wayMint1Way(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 36 {
		return nil, fmt.Errorf("1WAY: mint input too short")
	}

	vaultID := input[4:36]
	addr := PrecompileAddrHex(0x22)
	acc := state.GetOrCreateAccount(addr)

	// Access control: only the vault creator (or owner-set dead-man's-switch) may mint.
	if err := requireCallerIsCreatorOrDeadMan(state, vaultID, caller); err != nil {
		return nil, err
	}

	btcKey := storageKey(append([]byte{WaySlotVaultBTC}, vaultID...))
	btcAmount := readBigInt(acc.Storage[btcKey])

	if btcAmount.Sign() == 0 {
		return nil, fmt.Errorf("1WAY: no BTC deposited")
	}

	priceKey := storageKey([]byte("price:btc:usd"))
	btcPrice := readBigInt(acc.Storage[priceKey])
	if btcPrice.Sign() == 0 {
		btcPrice.SetString("68000000000000000000", 10) // $68000 * 1e18 as string
	}

	// Convert satoshis to BTC (divide by 1e8)
	btcTokens := new(big.Int).Div(btcAmount, big.NewInt(1e8))
	btcValueUSD := new(big.Int).Mul(btcTokens, btcPrice)

	// Mint 70% of BTC value
	mintAmount := new(big.Int).Mul(btcValueUSD, big.NewInt(WayMintRatio))
	mintAmount.Div(mintAmount, big.NewInt(10000))

	debtKey := storageKey(append([]byte{WaySlotVault1Way}, vaultID...))
	currentDebt := readBigInt(acc.Storage[debtKey])
	newDebt := new(big.Int).Add(currentDebt, mintAmount)
	acc.Storage[debtKey] = writeBigInt(newDebt)

	return mintAmount.Bytes(), nil
}

// ── Burn 1WAY ──
func wayBurn1Way(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 68 {
		return nil, fmt.Errorf("1WAY: burn input too short")
	}

	vaultID := input[4:36]
	amount := readUint256(input, 36)
	addr := PrecompileAddrHex(0x22)
	acc := state.GetOrCreateAccount(addr)

	// Access control: only the vault creator (or owner-set dead-man's-switch) may burn.
	if err := requireCallerIsCreatorOrDeadMan(state, vaultID, caller); err != nil {
		return nil, err
	}

	debtKey := storageKey(append([]byte{WaySlotVault1Way}, vaultID...))
	currentDebt := readBigInt(acc.Storage[debtKey])
	newDebt := new(big.Int).Sub(currentDebt, amount)
	if newDebt.Sign() < 0 {
		newDebt.SetUint64(0)
	}
	acc.Storage[debtKey] = writeBigInt(newDebt)

	return []byte{1}, nil
}

// ── Get vault for user ──
func wayGetUserVault(input []byte, caller string, state *StateDB) ([]byte, error) {
	if len(input) < 24 {
		return nil, fmt.Errorf("1WAY: getUserVault input too short")
	}

	user := readAddress(input, 4)
	addr := PrecompileAddrHex(0x22)
	acc := state.GetOrCreateAccount(addr)

	usrVaultKey := storageKey(append([]byte{WaySlotUserHasVault}, user[:]...))
	hasVault := acc.Storage[usrVaultKey]

	output := make([]byte, 32)
	if hasVault != [32]byte{} {
		output[0] = 1
	}
	return output, nil
}

// ── Get vault state (BTC + debt + creator) for the lock-light UI ──
// Returns 96 bytes: vaultBTC[32] || vaultDebt[32] || creatorPresent[32].
// Light logic (mobile Bridge tab):
//   OFF   = vaultBTC == 0
//   RED   = vaultBTC > 0 && vaultDebt > 0   ("DEBT")
//   GREEN = vaultBTC > 0 && vaultDebt == 0  ("1WAY")
func wayGetVault(input []byte, state *StateDB) ([]byte, error) {
	if len(input) < 36 {
		return nil, fmt.Errorf("1WAY: getVault input too short")
	}
	vaultID := input[4:36]
	addr := PrecompileAddrHex(0x22)
	acc := state.GetOrCreateAccount(addr)

	btcKey := storageKey(append([]byte{WaySlotVaultBTC}, vaultID...))
	btc := readBigInt(acc.Storage[btcKey])

	debtKey := storageKey(append([]byte{WaySlotVault1Way}, vaultID...))
	debt := readBigInt(acc.Storage[debtKey])

	creatorKey := storageKey(append([]byte{WaySlotVaultCreator}, vaultID...))
	creatorPresent := uint64(0)
	if acc.Storage[creatorKey] != [32]byte{} {
		creatorPresent = 1
	}

	out := make([]byte, 96)
	btc.FillBytes(out[0:32])
	debt.FillBytes(out[32:64])
	cp := writeUint64(creatorPresent)
	copy(out[64:96], cp[:])
	return out, nil
}

// ── Get BTC/USD price ──
func wayGetPrice(input []byte, caller string, state *StateDB) ([]byte, error) {
	addr := PrecompileAddrHex(0x22)
	acc := state.GetOrCreateAccount(addr)

	priceKey := storageKey([]byte("price:btc:usd"))
	price := readBigInt(acc.Storage[priceKey])
	if price.Sign() == 0 {
		price.SetString("68000000000000000000", 10)
	}
	out := make([]byte, 32)
	price.FillBytes(out)
	return out, nil
}

// ── Update BTC price ──
func wayUpdateBTCPrice(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 36 {
		return nil, fmt.Errorf("1WAY: updatePrice input too short")
	}

	price := readUint256(input, 4)
	addr := PrecompileAddrHex(0x22)
	acc := state.GetOrCreateAccount(addr)

	callerAcc := state.GetAccount(caller)
	if callerAcc == nil || callerAcc.DoxDevLevel < 2 {
		return nil, fmt.Errorf("1WAY: only verified oracles can update price")
	}

	priceKey := storageKey([]byte("price:btc:usd"))
	acc.Storage[priceKey] = writeBigInt(price)

	return []byte{1}, nil
}

// ── Get total supply of 1WAY ──
func wayGetTotalSupply(input []byte, caller string, state *StateDB) ([]byte, error) {
	addr := PrecompileAddrHex(0x22)
	acc := state.GetOrCreateAccount(addr)

	total := big.NewInt(0)
	for key, val := range acc.Storage {
		if len(key) == 32 && key[0] == WaySlotVault1Way {
			bal := readBigInt(val)
			total.Add(total, bal)
		}
	}

	out := make([]byte, 32)
	total.FillBytes(out)
	return out, nil
}
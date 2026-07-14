package evm

import (
	"fmt"
	"math/big"
)

// ══════════════════════════════════════════════════════════════════════
// SWAY Token (0x24) — DEX LP Incentive Token
// Liquidity providers earn SWAY for providing liquidity to the DEX
// SWAY has no intrinsic value — traded for reputation/badge unlocks
// ══════════════════════════════════════════════════════════════════════

// SWAY selectors
const (
	selSwayMint          uint32 = 0xA1B2C3E4 // mint(to[20], amount[32])
	selSwayBurn          uint32 = 0xB2C3D4F5 // burn(from[20], amount[32])
	selSwayGetBalance   uint32 = 0xC3D4E5A6 // getBalance(address[20])
	selSwayGetTotalSupply uint32 = 0xD4E5A6B7 // getTotalSupply()
	selSwaySwapFeeReward uint32 = 0xE5A6B7C8 // swapFee(address[20])
	selSwayMintToCaller  uint32 = 0xF6A7B8C9 // mintToCaller(amount[32]) - for 2WAY provider rewards
)

func swayPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("SWAY: input too short")
	}

	sel := selectorBytes(input)

	switch sel {
	case selSwayMint:
		to := readAddress(input, 4)
		amount := readBigInt(readSlot(input, 24))

		// Only DEX contract or authorized can mint
		if caller != PrecompileAddrHex(0x19) {
			return nil, fmt.Errorf("SWAY: unauthorized minter")
		}

		toAddr := fmt.Sprintf("%x", to[:])
		balanceKey := storageKey(append([]byte{0x30}, to[:]...))
		totalKey := storageKey([]byte("sway:totalSupply"))

		current := readBigInt(state.GetOrCreateAccount(toAddr).Storage[balanceKey])
		newBal := new(big.Int).Add(current, amount)
		state.GetOrCreateAccount(toAddr).Storage[balanceKey] = writeBigInt(newBal)

		total := readBigInt(state.GetAccount(PrecompileAddrHex(0x24)).Storage[totalKey])
		newTotal := new(big.Int).Add(total, amount)
		state.GetOrCreateAccount(PrecompileAddrHex(0x24)).Storage[totalKey] = writeBigInt(newTotal)

		return []byte{1}, nil

	case selSwayBurn:
		from := readAddress(input, 4)
		amount := readBigInt(readSlot(input, 24))
		fromAddr := fmt.Sprintf("%x", from[:])

		balanceKey := storageKey(append([]byte{0x30}, from[:]...))
		totalKey := storageKey([]byte("sway:totalSupply"))

		current := readBigInt(state.GetOrCreateAccount(fromAddr).Storage[balanceKey])
		if current.Cmp(amount) < 0 {
			return nil, fmt.Errorf("SWAY: insufficient balance")
		}

		newBal := new(big.Int).Sub(current, amount)
		state.GetOrCreateAccount(fromAddr).Storage[balanceKey] = writeBigInt(newBal)

		total := readBigInt(state.GetAccount(PrecompileAddrHex(0x24)).Storage[totalKey])
		newTotal := new(big.Int).Sub(total, amount)
		state.GetOrCreateAccount(PrecompileAddrHex(0x24)).Storage[totalKey] = writeBigInt(newTotal)

		return []byte{1}, nil

	case selSwayGetBalance:
		addr := readAddress(input, 4)
		balanceKey := storageKey(append([]byte{0x30}, addr[:]...))
		balance := readBigInt(state.GetAccount(fmt.Sprintf("%x", addr[:])).Storage[balanceKey])
		out := make([]byte, 32)
		balance.FillBytes(out)
		return out, nil

	case selSwayGetTotalSupply:
		totalKey := storageKey([]byte("sway:totalSupply"))
		acc := state.GetAccount(PrecompileAddrHex(0x24))
		var total *big.Int
		if acc == nil {
			total = big.NewInt(0)
		} else {
			total = readBigInt(acc.Storage[totalKey])
		}
		out := make([]byte, 32)
		total.FillBytes(out)
		return out, nil

	case selSwaySwapFeeReward:
		lpAddr := readAddress(input, 4)
		// Calculate fee reward based on pool share
		reward := big.NewInt(1) // Base reward
		balanceKey := storageKey(append([]byte{0x30}, lpAddr[:]...))
		state.GetOrCreateAccount(fmt.Sprintf("%x", lpAddr[:])).Storage[balanceKey] = writeBigInt(reward)
		return []byte{1}, nil

	case selSwayMintToCaller:
		amount := readBigInt(readSlot(input, 4))
		// Authorize 2WAY precompile (0x18) and TaskRegistry (0x23) to mint incentives
		if caller != PrecompileAddrHex(0x18) && caller != PrecompileAddrHex(0x23) {
			return nil, fmt.Errorf("SWAY: unauthorized minter")
		}
		balanceKey := storageKey(append([]byte{0x30}, []byte(caller)...))
		totalKey := storageKey([]byte("sway:totalSupply"))
		current := readBigInt(state.GetOrCreateAccount(caller).Storage[balanceKey])
		newBal := new(big.Int).Add(current, amount)
		state.GetOrCreateAccount(caller).Storage[balanceKey] = writeBigInt(newBal)
		total := readBigInt(state.GetAccount(PrecompileAddrHex(0x24)).Storage[totalKey])
		newTotal := new(big.Int).Add(total, amount)
		state.GetOrCreateAccount(PrecompileAddrHex(0x24)).Storage[totalKey] = writeBigInt(newTotal)
		return []byte{1}, nil
	}

	return nil, fmt.Errorf("SWAY: unknown selector 0x%08X", sel)
}
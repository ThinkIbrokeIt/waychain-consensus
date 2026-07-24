// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"fmt"
	"math/big"
	"strings"
)

// ════════════════════════════════════════════════════════════════════
// 0x27 — GasFaucet
//
// Drips WAY to new accounts / quest trackers so they can pay gas.
// Gas is charged in WAY (chain.go:507), so a small reserve keeps a tracker
// funded for ~100k txs. Reserve seeded from treasury 0x03 at genesis.
//
// Selectors (sha256(sig)[:4]):
//   drip()                  0x2A7AB5DA
//   getDripAmount()        0xF7C3438B
//   getLastDrip(address)   0x1DECB48C
//   getFaucetBalance()      0x1AC9C1D0
//   setDripAmount(uint256)  0x94AC47F1
//   setCooldown(uint64)     0x8567A687
// ════════════════════════════════════════════════════════════════════

// Faucet storage layout
// Slot 0x00: dripAmount (uint256, wei)
// Slot 0x01: cooldownBlocks (uint64)
// Slot 0x02: totalDripped (uint256, wei)
// Per-address last drip block: storageKey(0x10 ++ address[20]) → uint64

// Faucet defaults
const (
	FaucetDefaultDripAmount  = 1_000_000_000_000_000_000 // 1 WAY
	FaucetDefaultCooldown    = uint64(1000)               // blocks
	FaucetGenesisReserve     = 1_000_000_000_000_000_000_000_000 // 1,000,000 WAY seed
)

// Faucet selectors
const (
	selFaucetDrip          uint32 = 0x2A7AB5DA // drip()
	selFaucetGetDripAmount uint32 = 0xF7C3438B // getDripAmount()
	selFaucetGetLastDrip   uint32 = 0x1DECB48C // getLastDrip(address)
	selFaucetGetBalance    uint32 = 0x1AC9C1D0 // getFaucetBalance()
	selFaucetSetDripAmount uint32 = 0x94AC47F1 // setDripAmount(uint256)
	selFaucetSetCooldown   uint32 = 0x8567A687 // setCooldown(uint64)
)

func faucetPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	sel := selectorBytes(input)
	addr := PrecompileAddrHex(0x27)
	acc := state.GetOrCreateAccount(addr)

	// caller is the 64-hex ed25519 pubkey (per AGENTS.md) or a 40-hex
	// precompile address. The StateDB account key is the 40-hex form
	// (addrFromPubKey semantics: first 40 hex chars of the pubkey).
	callerKey := callerAccountKey(caller)
	callerAddr20 := callerKey[:20] // 20-byte form for per-address drip tracking

	switch sel {
	case selFaucetDrip:
		// Founder faucet-drip trigger (issue #155): the founder's first drip
		// fires the one-shot bulk genesis seed (all bootstrap accounts +
		// precompile reserves). SeedAllGenesis is idempotent, so repeated
		// drips are a safe no-op once everything is funded.
		if callerAccountKey(caller) == FounderAddress {
			SeedAllGenesis(state)
		}
		// rate-limit: one drip per cooldownBlocks
		cooldown := readUint64(acc.Storage[storageKey([]byte{0x01})])
		if cooldown == 0 {
			cooldown = FaucetDefaultCooldown
		}
		lastKey := storageKey(append([]byte{0x10}, callerAddr20[:]...))
		lastDrip := readUint64(acc.Storage[lastKey])
		if lastDrip != 0 && blockNum < lastDrip+cooldown {
			return []byte{0}, nil // rate-limited
		}
		drip := readBigInt(acc.Storage[storageKey([]byte{0x00})])
		if drip.Sign() == 0 {
			drip = new(big.Int).SetUint64(FaucetDefaultDripAmount)
		}
		// reserve check
		reserve := acc.Balance
		if reserve == nil {
			reserve = new(big.Int)
		}
		if reserve.Cmp(drip) < 0 {
			return []byte{0}, nil // empty
		}
		// transfer drip from faucet reserve to caller
		reserve.Sub(reserve, drip)
		acc.Balance = reserve
		recipient := state.GetOrCreateAccount(caller)
		if recipient.Balance == nil {
			recipient.Balance = new(big.Int)
		}
		recipient.Balance.Add(recipient.Balance, drip)
		// record last drip + total
		var lb [32]byte
		new(big.Int).SetUint64(blockNum).FillBytes(lb[:])
		acc.Storage[lastKey] = lb
		totalKey := storageKey([]byte{0x02})
		total := readBigInt(acc.Storage[totalKey])
		total.Add(total, drip)
		acc.Storage[totalKey] = writeBigInt(total)
		state.AddLog(addr, [][32]byte{storageKey([]byte("FaucetDrip"))}, []byte(caller), blockNum)
		return []byte{1}, nil

	case selFaucetGetDripAmount:
		drip := readBigInt(acc.Storage[storageKey([]byte{0x00})])
		if drip.Sign() == 0 {
			drip = new(big.Int).SetUint64(FaucetDefaultDripAmount)
		}
		out := make([]byte, 32)
		drip.FillBytes(out)
		return out, nil

	case selFaucetGetLastDrip:
		target := readAddress(input, 4)
		lastKey := storageKey(append([]byte{0x10}, target[:]...))
		out := make([]byte, 8)
		new(big.Int).SetUint64(readUint64(acc.Storage[lastKey])).FillBytes(out)
		return out, nil

	case selFaucetGetBalance:
		out := make([]byte, 32)
		if acc.Balance != nil {
			acc.Balance.FillBytes(out)
		}
		return out, nil

	case selFaucetSetDripAmount:
		// founder-tunable: only treasury (0x03) or a curator may set
		if !isFaucetAdmin(caller, state) {
			return nil, fmt.Errorf("GasFaucet: setDripAmount requires admin")
		}
		amt := readUint256(input, 4)
		acc.Storage[storageKey([]byte{0x00})] = writeBigInt(amt)
		return []byte{1}, nil

	case selFaucetSetCooldown:
		if !isFaucetAdmin(caller, state) {
			return nil, fmt.Errorf("GasFaucet: setCooldown requires admin")
		}
		cd := readUint64FromInput(input, 4)
		acc.Storage[storageKey([]byte{0x01})] = writeUint64(cd)
		return []byte{1}, nil

	default:
		return nil, fmt.Errorf("GasFaucet: unknown selector 0x%08X", sel)
	}
}

// callerAccountKey normalizes a caller string to the StateDB account key.
// Callers arrive as either a 64-hex ed25519 pubkey (live tx.from) or a
// precompile address. All addresses are canonical 40-char (20-byte) hex:
// user accounts via addrFromPubKey (first 40 of the 64-hex pubkey) and
// precompiles via PrecompileAddrHex (e.g. "0000…0027", 38 zeros + %02x).
// This helper must NOT pad/truncate — padding corrupts the key. So:
// 64-hex -> first 40 chars; 40 -> as-is.
// (The 38-char case is retained only for backward-compat with any pre-fix
// 2026-07-20 state; new precompile keys are 40-char.)
func callerAccountKey(caller string) string {
	s := strings.TrimPrefix(strings.ToLower(caller), "0x")
	switch {
	case len(s) >= 64:
		return s[:40] // 64-hex pubkey -> 40-char address
	case len(s) == 40, len(s) == 38:
		return s // canonical forms — pass through untouched
	default:
		return s // unknown form — do not corrupt
	}
}

// isFaucetAdmin: treasury (0x03) or a Dox_Dev L3 curator may tune the faucet.
func isFaucetAdmin(caller string, state *StateDB) bool {
	callerKey := callerAccountKey(caller)
	// treasury precompile address
	if callerKey == PrecompileAddrHex(0x03) {
		return true
	}
	// L3 curator (Dox_Dev level >= 3) — check badge precompile storage
	badgeAddr := PrecompileAddrHex(0x13)
	badgeAcc := state.GetOrCreateAccount(badgeAddr)
	levelKey := storageKey(append([]byte{0x20}, callerKey[:]...))
	level := readBigInt(badgeAcc.Storage[levelKey])
	return level.Cmp(big.NewInt(3)) >= 0
}

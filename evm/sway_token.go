// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"fmt"
	"math/big"
)

// ══════════════════════════════════════════════════════════════════════
// SWAY Token (0x24) — WayChain REWARDS Token
//
// ROLE (DECISIONS.md 2026-07-18, refined): 
//   - WAY = the PAYMENT token for the economy (pay for tasks/fees/services).
//     Genesis dev + base user got the initial WAY allocation; WAY flows to all
//     participants as payment for economic activity (e.g. task payouts from
//     treasury 0x03).
//   - SWAY = the REWARDS token. Earned by PARTICIPATION (completing tasks,
//     providing DEX liquidity, community contribution). NO insider allocation,
//     NO cliff-vesting, NO veModel. Everyone earns SWAY the same way.
//
// MONETARY POLICY (approved model):
//   - Initial supply: 1,000,000,000 (1B) = 10× WAY
//   - Hard ceiling:   10,000,000,000 (10B) = safety rail, CANNOT be crossed
//   - Base emission:  ~2–3%/yr of circulating, ADJUSTED by the econo phase
//     engine (econo_loop.go): Expansion → less emission + more burn;
//     Consolidation → more emission (stimulus for future-user rewards).
//   - Burn flywheel: swap-fee share + task-fee share → buyback & burn.
//
// This is INFLATIONARY-ADAPTIVE with a hard ceiling, NOT a rigid small cap
// (which would run out of bullets for future-user rewards) and NOT unbounded
// (which would dilute holders). The econo phase engine is the "governance knob"
// the DEX-framework literature recommends — and it already exists on WayChain.
// ══════════════════════════════════════════════════════════════════════

// SWAY monetary constants (DECISIONS.md 2026-07-18).
const (
	SwayInitialSupply uint64 = 1_000_000_000 // 1B at genesis
	SwayHardCeiling   uint64 = 5_000_000_000 // 5B safety rail (founder 2026-07-18: "cap it at 5 billion sway")

	// Allocation of the initial 1B (percent of initial supply).
	// ALL SWAY is REWARDS — earned by participation. No insider/team/backer
	// carve-out (that is the VC-world pattern; rejected — DECISIONS.md).
	SwayAllocFutureTasks uint64 = 45 // task-completion rewards
	SwayAllocDEXLP       uint64 = 20 // DEX LP rewards
	SwayAllocEcosystem   uint64 = 35 // community / grants / onboarding / contributor rewards

	// Base annual emission (basis points of circulating supply).
	SwayBaseEmissionBps uint64 = 250 // 2.5%/yr baseline

	// Emission adjustment by econo phase (basis points delta).
	SwayExpansionEmissionDeltaBps  int64 = -100 // -1.0% in Expansion
	SwayConsolidationEmissionDeltaBps int64 = +150 // +1.5% in Consolidation (stimulus)

	// Burn rate applied to fee revenue (basis points of fee collected).
	SwayBaseBurnBps uint64 = 2000 // 20% of fee revenue burned
)

// SWAY storage keys.
var (
	swayKeyTotalSupply = storageKey([]byte("sway:totalSupply"))
	swayKeyInit        = storageKey([]byte("sway:initialized"))
	swayKeyBucket      = func(b string) [32]byte { return storageKey([]byte("sway:bucket:" + b)) }
)

// SWAY selectors
const (
	selSwayMint           uint32 = 0xA1B2C3E4 // mint(to[20], amount[32])
	selSwayBurn           uint32 = 0xB2C3D4F5 // burn(from[20], amount[32])
	selSwayGetBalance     uint32 = 0xC3D4E5A6 // getBalance(address[20])
	selSwayGetTotalSupply uint32 = 0xD4E5A6B7 // getTotalSupply()
	selSwayGetEmission    uint32 = 0xE5A6B7C8 // getEmissionRate() → bps
	selSwayInit           uint32 = 0x0A1B2C3D // init() — seed initial supply + allocation
	selSwaySwapFeeReward  uint32 = 0x1A2B3C4D // swapFee(address[20])
	selSwayMintToCaller   uint32 = 0xF6A7B8C9 // mintToCaller(amount[32]) — 2WAY/TaskRegistry rewards
)

// SwayInit seeds the initial 1B supply + allocation buckets. Idempotent:
// runs once per chain (guarded by swayKeyInit). Allocation buckets are stored
// as balances under the SWAY precompile account (0x24) so the dashboard and
// emission logic can read remaining budget per bucket.
func SwayInit(state *StateDB) {
	acc := state.GetOrCreateAccount(PrecompileAddrHex(0x24))
	if readBigInt(acc.Storage[swayKeyInit]).Sign() != 0 {
		return // already initialized
	}
	total := big.NewInt(int64(SwayInitialSupply))
	acc.Storage[swayKeyTotalSupply] = writeBigInt(total)
	acc.Storage[swayKeyInit] = writeBigInt(big.NewInt(1))

	buckets := []struct {
		name string
		pct  uint64
	}{
		{"futureTasks", SwayAllocFutureTasks},
		{"dexLP", SwayAllocDEXLP},
		{"ecosystem", SwayAllocEcosystem},
	}
	for _, b := range buckets {
		amt := new(big.Int).Mul(total, new(big.Int).SetUint64(b.pct))
		amt.Div(amt, big.NewInt(100))
		acc.Storage[swayKeyBucket(b.name)] = writeBigInt(amt)
	}
}

// SwayCirculating returns total minted minus burned (== totalSupply counter).
func SwayCirculating(state *StateDB) *big.Int {
	acc := state.GetAccount(PrecompileAddrHex(0x24))
	if acc == nil {
		return big.NewInt(0)
	}
	return readBigInt(acc.Storage[swayKeyTotalSupply])
}

// SwayBucketBalance returns remaining budget in an allocation bucket.
func SwayBucketBalance(state *StateDB, name string) *big.Int {
	acc := state.GetAccount(PrecompileAddrHex(0x24))
	if acc == nil {
		return big.NewInt(0)
	}
	return readBigInt(acc.Storage[swayKeyBucket(name)])
}

// SwayEmissionBps returns the current annual emission rate in bps, adjusted by
// the econo phase. Expansion → lower; Consolidation → higher (stimulus).
func SwayEmissionBps() uint64 {
	delta := int64(0)
	switch econoPolicy.Phase {
	case 1: // Expansion
		delta = SwayExpansionEmissionDeltaBps
	default: // Consolidation
		delta = SwayConsolidationEmissionDeltaBps
	}
	rate := int64(SwayBaseEmissionBps) + delta
	if rate < 0 {
		rate = 0
	}
	return uint64(rate)
}

// SwayProjectedEmissionFromGBP is a READ-ONLY telemetry function. It computes
// what SWAY emission WOULD be if rewards were minted as `pctBps` of the
// economy's yearly earnings (GBP), using the live EconoGBPEquiv accumulator.
//
// It has NO mint authority — it is a projection only, so the founder can see
// the real numbers before any percentage is hardcoded (DECISIONS.md 2026-07-18:
// "we will need to see the numbers before that gets hard coded").
//
// Model: yearlyEarnings = EconoGBPEquiv() * epochsPerYear
//        projectedSWAY = yearlyEarnings * pctBps / 10000
// Returns projected SWAY per year at the given percentage.
func SwayProjectedEmissionFromGBP(pctBps uint64) *big.Int {
	gbpThisWindow := EconoGBPEquiv() // uint64, WAY-denominated output this epoch
	if gbpThisWindow == 0 {
		return big.NewInt(0)
	}
	// Self-contained year math (3s blocks, 10k-block epoch = consensus defaults).
	const blockTimeSec = 3
	const epochLen = 10_000
	secondsPerYear := uint64(365 * 24 * 3600)
	epochsPerYear := secondsPerYear / (blockTimeSec * epochLen)

	yearlyEarnings := new(big.Int).Mul(
		new(big.Int).SetUint64(gbpThisWindow),
		new(big.Int).SetUint64(epochsPerYear),
	)
	proj := new(big.Int).Mul(yearlyEarnings, new(big.Int).SetUint64(pctBps))
	proj.Div(proj, big.NewInt(10_000))
	return proj
}

// swayMintInternal mints `amount` SWAY to `to`, enforcing the hard ceiling and
// (when bucket != "") decrementing the named allocation bucket. Returns error
// if ceiling would be crossed or bucket is empty.
func swayMintInternal(state *StateDB, to string, amount *big.Int, bucket string) error {
	if amount.Sign() <= 0 {
		return fmt.Errorf("SWAY: amount must be positive")
	}
	acc := state.GetOrCreateAccount(PrecompileAddrHex(0x24))

	// Bucket budget check (allocation discipline).
	if bucket != "" {
		remaining := readBigInt(acc.Storage[swayKeyBucket(bucket)])
		if remaining.Cmp(amount) < 0 {
			return fmt.Errorf("SWAY: bucket %s exhausted", bucket)
		}
	}

	// Hard-ceiling check.
	total := readBigInt(acc.Storage[swayKeyTotalSupply])
	newTotal := new(big.Int).Add(total, amount)
	if newTotal.Uint64() > SwayHardCeiling {
		return fmt.Errorf("SWAY: hard ceiling %d exceeded", SwayHardCeiling)
	}

	// Credit recipient.
	toAddr := to
	balanceKey := storageKey(append([]byte{0x30}, []byte(toAddr)...))
	cur := readBigInt(state.GetOrCreateAccount(toAddr).Storage[balanceKey])
	state.GetOrCreateAccount(toAddr).Storage[balanceKey] = writeBigInt(new(big.Int).Add(cur, amount))

	acc.Storage[swayKeyTotalSupply] = writeBigInt(newTotal)
	if bucket != "" {
		acc.Storage[swayKeyBucket(bucket)] = writeBigInt(new(big.Int).Sub(readBigInt(acc.Storage[swayKeyBucket(bucket)]), amount))
	}
	return nil
}

// swayBurnInternal burns `amount` SWAY from `from`, reducing total supply.
func swayBurnInternal(state *StateDB, from string, amount *big.Int) error {
	if amount.Sign() <= 0 {
		return fmt.Errorf("SWAY: amount must be positive")
	}
	fromAddr := from
	balanceKey := storageKey(append([]byte{0x30}, []byte(fromAddr)...))
	cur := readBigInt(state.GetOrCreateAccount(fromAddr).Storage[balanceKey])
	if cur.Cmp(amount) < 0 {
		return fmt.Errorf("SWAY: insufficient balance")
	}
	state.GetOrCreateAccount(fromAddr).Storage[balanceKey] = writeBigInt(new(big.Int).Sub(cur, amount))

	acc := state.GetOrCreateAccount(PrecompileAddrHex(0x24))
	total := readBigInt(acc.Storage[swayKeyTotalSupply])
	acc.Storage[swayKeyTotalSupply] = writeBigInt(new(big.Int).Sub(total, amount))
	return nil
}

// SwayBurnFromFees burns `feeAmount` SWAY-equivalent to realize the
// deflationary sink. The fee may be collected in another token; the protocol
// burns SWAY from the ecosystem bucket reserve, decrementing total supply.
// Returns the amount actually burned (0 if the ecosystem bucket is empty).
func SwayBurnFromFees(state *StateDB, feeAmount *big.Int) *big.Int {
	burn := new(big.Int).Mul(feeAmount, new(big.Int).SetUint64(SwayBaseBurnBps))
	burn.Div(burn, big.NewInt(10_000))
	if burn.Sign() == 0 {
		return big.NewInt(0)
	}
	acc := state.GetOrCreateAccount(PrecompileAddrHex(0x24))
	eco := readBigInt(acc.Storage[swayKeyBucket("ecosystem")])
	if eco.Cmp(burn) < 0 {
		burn = eco // burn what's available
	}
	if burn.Sign() == 0 {
		return big.NewInt(0)
	}
	// Decrement ecosystem bucket + total supply (the deflationary sink).
	acc.Storage[swayKeyBucket("ecosystem")] = writeBigInt(new(big.Int).Sub(eco, burn))
	total := readBigInt(acc.Storage[swayKeyTotalSupply])
	acc.Storage[swayKeyTotalSupply] = writeBigInt(new(big.Int).Sub(total, burn))
	return burn
}

func swayPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("SWAY: input too short")
	}
	sel := selectorBytes(input)

	switch sel {
	case selSwayInit:
		SwayInit(state)
		return []byte{1}, nil

	case selSwayMint:
		to := readAddress(input, 4)
		amount := readBigInt(readSlot(input, 24))
		// Only the DEX (SwapRoute 0x25) or StabilityPool (0x19) may mint LP
		// rewards, drawn from the dexLP allocation bucket.
		if caller != PrecompileAddrHex(0x25) && caller != PrecompileAddrHex(0x19) {
			return nil, fmt.Errorf("SWAY: unauthorized minter")
		}
		if err := swayMintInternal(state, fmt.Sprintf("%x", to[:]), amount, "dexLP"); err != nil {
			return nil, err
		}
		return []byte{1}, nil

	case selSwayMintToCaller:
		amount := readBigInt(readSlot(input, 4))
		// 2WAY (0x18) + TaskRegistry (0x23) reward future users from buckets.
		switch caller {
		case PrecompileAddrHex(0x18):
			if err := swayMintInternal(state, caller, amount, "dexLP"); err != nil {
				return nil, err
			}
		case PrecompileAddrHex(0x23):
			if err := swayMintInternal(state, caller, amount, "futureTasks"); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("SWAY: unauthorized minter")
		}
		return []byte{1}, nil

	case selSwayBurn:
		from := readAddress(input, 4)
		amount := readBigInt(readSlot(input, 24))
		if err := swayBurnInternal(state, fmt.Sprintf("%x", from[:]), amount); err != nil {
			return nil, err
		}
		return []byte{1}, nil

	case selSwayGetBalance:
		addr := readAddress(input, 4)
		balanceKey := storageKey(append([]byte{0x30}, addr[:]...))
		balance := readBigInt(state.GetAccount(fmt.Sprintf("%x", addr[:])).Storage[balanceKey])
		out := make([]byte, 32)
		balance.FillBytes(out)
		return out, nil

	case selSwayGetTotalSupply:
		acc := state.GetAccount(PrecompileAddrHex(0x24))
		var total *big.Int
		if acc == nil {
			total = big.NewInt(0)
		} else {
			total = readBigInt(acc.Storage[swayKeyTotalSupply])
		}
		out := make([]byte, 32)
		total.FillBytes(out)
		return out, nil

	case selSwayGetEmission:
		out := make([]byte, 32)
		new(big.Int).SetUint64(SwayEmissionBps()).FillBytes(out)
		return out, nil

	case selSwaySwapFeeReward:
		lpAddr := readAddress(input, 4)
		reward := big.NewInt(1)
		balanceKey := storageKey(append([]byte{0x30}, lpAddr[:]...))
		state.GetOrCreateAccount(fmt.Sprintf("%x", lpAddr[:])).Storage[balanceKey] = writeBigInt(reward)
		return []byte{1}, nil
	}

	return nil, fmt.Errorf("SWAY: unknown selector 0x%08X", sel)
}

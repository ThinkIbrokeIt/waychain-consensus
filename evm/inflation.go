// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import "fmt"

// ── Protocol-wide inflation control (WayChain tokenomics) ──
//
// The annual validator emission is a fraction of total supply. Founders and
// governance may adjust it, but ONLY within a hard bounds window so the chain
// can never be tuned to hyperinflation or zero-emission by a single proposal.
//
// Bounds: 3%–9% per year (founder decision, 2026-07-17). Default 7%.
//
// The value lives at package scope (not in chain state) so both the consensus
// emission math (package main) and the Governance precompile (package evm) can
// read/write it without threading *StateDB through every emission call. It is
// seeded at genesis via SetInflationPct and thereafter mutable by governance.

const (
	// DefaultAnnualInflationPct: starting emission if governance hasn't moved it.
	DefaultAnnualInflationPct = 7.0

	// MinAnnualInflationPct / MaxAnnualInflationPct: hard bounds on the
	// adjustable annual emission (3%–9% per year).
	MinAnnualInflationPct = 3.0
	MaxAnnualInflationPct = 9.0
)

// activeInflationPct is the live annual emission rate (fraction of supply).
var activeInflationPct = DefaultAnnualInflationPct

// GetInflationPct returns the current annual inflation percentage.
func GetInflationPct() float64 {
	return activeInflationPct
}

// SetInflationPct sets the annual inflation percentage, clamped to the
// hard bounds [MinAnnualInflationPct, MaxAnnualInflationPct]. Returns the
// value actually applied. Out-of-range input is clamped (never rejected
// silently) so callers cannot accidentally disable emission or blow it up.
func SetInflationPct(pct float64) float64 {
	if pct < MinAnnualInflationPct {
		pct = MinAnnualInflationPct
	}
	if pct > MaxAnnualInflationPct {
		pct = MaxAnnualInflationPct
	}
	activeInflationPct = pct
	return activeInflationPct
}

// InflationPctToCalldata / CalldataToInflationPct: encode the % as a uint32
// of (pct*100) so it fits in the 32-byte governance calldata slot.
func InflationPctToCalldata(pct float64) uint32 {
	return uint32(pct * 100)
}

// CalldataToInflationPct decodes a uint32 (pct*100) back to a float %.
// Returns an error if the encoded value is outside the hard bounds (so the
// governance finalize path can reject absurd proposals before clamping).
func CalldataToInflationPct(encoded uint32) (float64, error) {
	pct := float64(encoded) / 100.0
	if pct < MinAnnualInflationPct || pct > MaxAnnualInflationPct {
		return 0, fmt.Errorf("inflation %v%% outside bounds [%.0f, %.0f]", pct, MinAnnualInflationPct, MaxAnnualInflationPct)
	}
	return pct, nil
}

// uint32ToBytes big-endian encodes a uint32 into a 32-byte log payload.
func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 32)
	b[28] = byte(v >> 24)
	b[29] = byte(v >> 16)
	b[30] = byte(v >> 8)
	b[31] = byte(v)
	return b
}

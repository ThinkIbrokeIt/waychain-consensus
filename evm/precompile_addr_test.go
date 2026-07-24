// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import "testing"

// TestPrecompileAddrHexIs40Chars is the #143 regression guard: the bug was
// PrecompileAddrHex emitting 38 chars, so genesis-seeded precompile reserves
// (GasFaucet 0x27) were stored under a key client lookups (40-char 0x address)
// missed -> way_getBalance returned 0x0 despite the reserve being seeded.
// A correct 20-byte address is exactly 40 hex chars.
func TestPrecompileAddrHexIs40Chars(t *testing.T) {
	for _, addr := range []byte{0x03, 0x13, 0x27} {
		got := PrecompileAddrHex(addr)
		if len(got) != 40 {
			t.Fatalf("PrecompileAddrHex(0x%02x) = %q len=%d, want 40 hex chars", addr, got, len(got))
		}
		// sanity: last two chars are the byte, rest zero
		want := "00000000000000000000000000000000000000"
		want += hexDigits(addr)
		if got != want {
			t.Fatalf("PrecompileAddrHex(0x%02x) = %q, want %q", addr, got, want)
		}
	}
}

func hexDigits(b byte) string {
	const h = "0123456789abcdef"
	return string(h[b>>4]) + string(h[b&0x0f])
}

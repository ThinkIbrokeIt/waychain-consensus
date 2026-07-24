// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"fmt"
	"golang.org/x/crypto/sha3"
	"math/big"
)

// Keccak256 precompile (0x21) — app-layer hashing bridge.
//
// Per REPO_LAW Article X (ratified #59/#60): the WayChain CORE protocol uses
// sha256 for all native precompile selectors and dispatch. The Solidity app
// layer, by contrast, speaks keccak256 (Ethereum-compatible). To let on-chain
// Solidity contracts and the app layer compute keccak256 deterministically
// (and derive keccak selectors the way the Solidity side expects), the core
// exposes this precompile. It was ALWAYS intended to be 0x21 (July 4 session
// plan); the address was temporarily occupied by WIFRGantletRewards, which is
// now removed — its reward function is subsumed by the wifr-bridge quest
// (TaskRegistry 0x23) paying from the treasury (0x03). See issues #61/#62/#63.
//
// Selectors follow the CORE convention (sha256(sig)[:4]), NOT keccak, so they
// stay collision-checked against the other 158 core selectors. The keccak work
// itself happens INSIDE the precompile body.
const (
	keccakHashSel  = 0x1901A39A // sha256("hash(bytes)")[:4]
	keccakHash4Sel = 0x6963203C // sha256("hash4(bytes)")[:4]
)

// keccak256Precompile exposes keccak256 hashing to the app layer.
//   - hash(bytes)   -> bytes32 : keccak256(input[4:])
//   - hash4(bytes)  -> bytes4  : first 4 bytes of keccak256(input[4:])
//
// The bytes argument is the payload to hash (input[4:]); selectors are 4-byte
// core-prefixed. Gas is 1000 (fixed, matches sibling token precompiles).
func keccak256Precompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("0x21: input too short")
	}
	sel := selectorBytes(input)

	switch sel {
	case keccakHashSel: // hash(bytes)
		return keccakBytes(input[4:]), nil

	case keccakHash4Sel: // hash4(bytes) — selector computation for the app layer
		h := keccakBytes(input[4:])
		out := make([]byte, 4)
		copy(out, h[:4])
		return out, nil
	}
	return nil, fmt.Errorf("0x21: unknown selector %x", sel)
}

// keccakBytes returns the keccak256 (legacy/Ethereum) digest of b.
func keccakBytes(b []byte) []byte {
	k := sha3.NewLegacyKeccak256()
	k.Write(b)
	return k.Sum(nil)
}

// ensure big is referenced (kept for future variable-length amount params if
// the app layer later needs keccak of a uint). No-op today but avoids an
// unused-import churn if math/big is dropped.
var _ = big.NewInt

package evm

import (
	"encoding/hex"
	"math/big"
)

// ═════════════════════════════════════════════════════════════════════
// Read-only precompile surfaces for the mobile wallet P3 panels.
// These expose existing precompile storage WITHOUT going through eth_call
// (which the public RPC blocks for precompiles). They are pure reads.
// ═════════════════════════════════════════════════════════════════════

// GetTwoWayStats reads total vault count + total debt from the 0x18 precompile.
// Mirrors twoWayVaultCount / addTotalDebt storage keys exactly.
func GetTwoWayStats(s *StateDB) (vaultCount, totalDebt *big.Int) {
	acc := s.GetOrCreateAccount(PrecompileAddrHex(0x18))
	vaultCount = readBigInt(acc.Storage[storageKey([]byte("vaultCount"))])
	totalDebt = readBigInt(acc.Storage[storageKey([]byte("totalDebt"))])
	if vaultCount == nil {
		vaultCount = big.NewInt(0)
	}
	if totalDebt == nil {
		totalDebt = big.NewInt(0)
	}
	return
}

// GetBridgeStats reads total committed / withdrawn BTC from the 0x16 BitcoinRegistry.
// Keys use writeUint64(0) / writeUint64(1) — must match bitcoinRegistryPrecompile.
func GetBridgeStats(s *StateDB) (committed, withdrawn *big.Int) {
	acc := s.GetOrCreateAccount(PrecompileAddrHex(0x16))
	committed = readBigInt(acc.Storage[writeUint64(0)])
	withdrawn = readBigInt(acc.Storage[writeUint64(1)])
	if committed == nil {
		committed = big.NewInt(0)
	}
	if withdrawn == nil {
		withdrawn = big.NewInt(0)
	}
	return
}

// GovernanceListProposals enumerates on-chain proposals via the proposal_index
// maintained by govCreateProposal. Returns an empty slice when no proposals
// exist yet (pre-index proposals are not retro-enumerated — honest).
func GovernanceListProposals(s *StateDB) []map[string]interface{} {
	acc := s.GetOrCreateAccount(PrecompileAddrHex(0x1D))
	count := readBigInt(acc.Storage[storageKey([]byte("proposal_count"))])
	out := []map[string]interface{}{}
	for i := int64(0); i < count.Int64(); i++ {
		idKey := storageKey(append([]byte("pid_"), []byte(big.NewInt(i).Text(10))...))
		idSlot := acc.Storage[idKey]
		if idSlot == ([32]byte{}) {
			continue
		}
		propKey := govProposalKey(idSlot[:])
		propSlot := acc.Storage[propKey]
		if propSlot == ([32]byte{}) {
			continue
		}
		out = append(out, map[string]interface{}{
			"id":        "0x" + hex.EncodeToString(idSlot[:]),
			"voteType":  int(propSlot[0]),
			"status":    int(propSlot[1]),
			"titleHash": "0x" + hex.EncodeToString(propSlot[2:32]),
		})
	}
	return out
}

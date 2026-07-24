// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"fmt"
	"math/big"
	"testing"
)

// TestGovernanceListProposalsAfterCreate verifies the proposal index is
// maintained when a proposal is created via the governance precompile,
// and that GovernanceListProposals enumerates it.
func TestGovernanceListProposalsAfterCreate(t *testing.T) {
	state := NewStateDB()
	caller := "0x9338a1f1e31dae7fdbc072ddf7b3c0c21bf45b7703dfccf90ded6e21a6f2840a"
	titleHash := make([]byte, 32)
	descHash := make([]byte, 32)
	target := make([]byte, 20)
	calldata := []byte("dummy")

	// Build createProposal calldata: selector(4) + voteType(1) + titleHash(32)
	// + descHash(32) + target(20) + calldataLen(32) + calldata
	input := append([]byte{0xD1, 0xE2, 0xF3, 0xA4}, byte(0)) // govCreateProposalSelector + voteType=Direct
	input = append(input, titleHash...)
	input = append(input, descHash...)
	input = append(input, target...)
	cdLen := make([]byte, 32)
	new(big.Int).SetUint64(uint64(len(calldata))).FillBytes(cdLen)
	input = append(input, cdLen...)
	input = append(input, calldata...)

	res, err := governancePrecompile(input, caller, state, 100)
	if err != nil {
		t.Fatalf("createProposal failed: %v", err)
	}
	if len(res) != 32 {
		t.Fatalf("expected 32-byte proposal id, got %d", len(res))
	}

	list := GovernanceListProposals(state)
	if len(list) != 1 {
		t.Fatalf("expected 1 proposal after create, got %d", len(list))
	}
	if list[0]["status"] != 1 { // ProposalStatusActive
		t.Fatalf("expected active status, got %v", list[0]["status"])
	}
	fmt.Printf("  ✅ proposal indexed: id=%s status=%v\n", list[0]["id"], list[0]["status"])
}

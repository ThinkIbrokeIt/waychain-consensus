// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"math/big"
	"testing"

	"github.com/ThinkIbrokeIt/waychain-consensus/evm"
)

// TestWayTaskStatusRPC — proves the exported helpers the RPC handlers
// (way_taskStatus / way_questPoolRemaining / getTaskReward) rely on resolve
// against live state. The mobile/web clients depend on these for real quest
// status; the public RPC allows way_* reads (eth_call to precompiles is
// blocked). The claim→verify payout cycle itself is covered in evm package
// tests; here we confirm the read surface the RPC exposes.
func TestWayTaskStatusRPC(t *testing.T) {
	state := evm.NewStateDB()
	// Fund treasury 0x03 (the paying pool the RPC reports).
	tr := state.GetOrCreateAccount(evm.PrecompileAddrHex(0x03))
	tr.Balance = big.NewInt(1_100_000)
	// Seed live supply like genesis (cap = 5% of 100M = 5M).
	evm.QuestAddSupply(state, big.NewInt(100_000_000))

	claimer := "00000000000000000000000000000000000000aa"

	task := make([]byte, 32)
	copy(task, []byte("1way-mint"))

	// Before any claim, status is none and reward is known.
	if got := evm.TaskStatusOf(state, task, claimer); got != "none" {
		t.Fatalf("status = %q, want none", got)
	}
	if r := evm.GetTaskReward(task).Uint64(); r != 300 {
		t.Fatalf("getTaskReward = %d, want 300", r)
	}
	// Pool reflects the dynamic cap: 5% of 100M seeded supply = 5,000,000.
	if rem := evm.QuestPoolRemaining(state).Uint64(); rem != 5_000_000 {
		t.Fatalf("pool remaining = %d, want 5,000,000", rem)
	}

	// Unknown task pays 0 (guard against UI/chain drift).
	unknown := make([]byte, 32)
	copy(unknown, []byte("nope"))
	if r := evm.GetTaskReward(unknown).Uint64(); r != 0 {
		t.Fatalf("unknown task reward = %d, want 0", r)
	}
}

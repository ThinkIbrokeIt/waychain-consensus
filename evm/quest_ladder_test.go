package evm

import (
	"testing"
)

// TestTopTierLadder verifies the full validator(72h) → gov-proposal → oracle-bond
// ladder records rank + pays the top-tier bonus on-chain.
func TestTopTierLadder(t *testing.T) {
	state := NewStateDB()
	caller := "topTierCandidate"
	// Give caller funds + Dox_Dev L2 so 1WAY/oracle paths are realistic.
	acc := state.GetOrCreateAccount(caller)
	acc.Balance.SetUint64(1_000_000)
	acc.DoxDevLevel = 2

	// 1) Simulate 72h of active-set uptime (block time ~5s → ~51840 blocks).
	for i := 0; i < 52000; i++ {
		IncrementValidatorUptime(state, caller)
	}
	if GetValidatorUptime(state, caller) < 72*3600/5 {
		t.Fatalf("uptime not accrued: %d", GetValidatorUptime(state, caller))
	}

	// 2) Record governance proposal via taskClaim("gov-propose").
	govTaskID := make([]byte, 32)
	copy(govTaskID[:], "gov-propose")
	if _, err := taskRegistryPrecompile(append(selectorBytesFromUint32(0xA1B2C3D4), govTaskID...), caller, state, 1); err != nil {
		t.Fatalf("gov-propose claim failed: %v", err)
	}

	// 3) Bond 5000 WAY as oracle bond.
	bondAmt := uint64ToBytes(5000)
	if _, err := taskRegistryPrecompile(append(selectorBytesFromUint32(0x8AB2C3D4), bondAmt...), caller, state, 1); err != nil {
		t.Fatalf("bondOracle failed: %v", err)
	}

	// Fund the DEDICATED quest treasury (not 0x03) so payouts can draw from it.
	dep := uint64ToBytes(250_000)
	if _, err := taskRegistryPrecompile(append(selectorBytesFromUint32(0xD1E2F3A4), dep...), caller, state, 1); err != nil {
		t.Fatalf("questDeposit failed: %v", err)
	}

	// 4) Record top-tier — should assign rank 1 + pay bonus.
	out, err := taskRegistryPrecompile(selectorBytesFromUint32(0x6FA1B2C3), caller, state, 1)
	if err != nil {
		t.Fatalf("recordTopTier failed: %v", err)
	}
	rank := bytesToUint64(out)
	if rank != 1 {
		t.Fatalf("expected rank 1, got %d", rank)
	}
	if state.GetAccount(caller).Balance.Uint64() != 746000 {
		t.Fatalf("top-tier bonus not paid correctly; balance=%d (want 746000 = 1M - 250k deposit - 5k bond + 1k bonus)", state.GetAccount(caller).Balance.Uint64())
	}
	// Quest treasury should now hold 249k (250k deposited - 1k top-tier bonus paid).
	qtOut, err := taskRegistryPrecompile(selectorBytesFromUint32(0xE2F3A4B5), caller, state, 1)
	if err != nil {
		t.Fatalf("getQuestTreasury failed: %v", err)
	}
	if bytesToUint64(qtOut) != 249000 {
		t.Fatalf("quest treasury balance = %d, want 249000", bytesToUint64(qtOut))
	}

	// Idempotent: recording again returns same rank, no double pay.
	out2, err := taskRegistryPrecompile(selectorBytesFromUint32(0x6FA1B2C3), caller, state, 1)
	if err != nil {
		t.Fatalf("recordTopTier 2nd failed: %v", err)
	}
	if bytesToUint64(out2) != 1 {
		t.Fatalf("expected idempotent rank 1, got %d", bytesToUint64(out2))
	}
}

// TestTaskRewardAmountFoundation confirms the foundation quest rewards are wired.
func TestTaskRewardAmountFoundation(t *testing.T) {
	cases := map[string]uint64{
		"wallet-setup": 100, "first-transfer": 10, "governance-vote": 25,
		"gov-propose": 25, "quest-feedback": 50, "doxdev-badge": 100,
		"1way-mint": 300, "oracle-setup": 150, "validator-setup": 500,
	}
	for id, want := range cases {
		got := taskRewardAmount([]byte(id)).Uint64()
		if got != want {
			t.Errorf("reward[%q] = %d, want %d", id, got, want)
		}
	}
}

// helpers (mirror precompiles.go internal encoders)
func selectorBytesFromUint32(u uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(u >> 24)
	b[1] = byte(u >> 16)
	b[2] = byte(u >> 8)
	b[3] = byte(u)
	return b
}

func uint64ToBytes(v uint64) []byte {
	b := make([]byte, 32)
	b[24] = byte(v >> 56)
	b[25] = byte(v >> 48)
	b[26] = byte(v >> 40)
	b[27] = byte(v >> 32)
	b[28] = byte(v >> 24)
	b[29] = byte(v >> 16)
	b[30] = byte(v >> 8)
	b[31] = byte(v)
	return b
}

func bytesToUint64(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

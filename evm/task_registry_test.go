// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// encodeTaskID mirrors the mobile app's left-aligned 32-byte encoding of a
// taskId string (matches taskClaim which copies input[4:36] into slot[0:32]).
func encodeTaskID(t string) []byte {
	out := make([]byte, 32)
	copy(out, []byte(t))
	return out
}

// TestTaskRewardAmountCanonical — every quest ID the UI promises must pay a
// non-zero, correct WAY amount. This is the guard against the mobile/chain
// drift bug: if a UI quest ID is missing here, the test fails loudly.
func TestTaskRewardAmountCanonical(t *testing.T) {
	want := map[string]uint64{
		// Track A — Onboard
		"wallet-setup": 100, "first-transfer": 10, "faucet-claim": 10,
		"receive-way": 10, "governance-vote": 25,
		// Track B — Identity
		"doxdev-badge": 100, "badge-curate": 200,
		// Track C — Governance
		"gov-propose": 25,
		// Track D — DeFi
		"1way-mint": 300, "1way-burn": 150, "2way-open": 25, "first-swap": 10,
		"add-liquidity": 10, "stability-deposit": 50, "btc-bridge": 25,
		"sway-stake": 50,
		// Track E — Native applications
		"bijo-journal": 100, "lock-time": 25, "lock-vesting": 50, "mrt-claim": 150,
		"dms-setup": 150,
		// Track F — Infrastructure
		"oracle-feed": 150, "account-recovery": 50, "privacy-proof": 100,
		"staterent-pay": 50, "xchain-attest": 100, "template-deploy": 100,
		"validator-72h": 100,
	}
	if len(want) != 28 {
		t.Fatalf("expected 28 canonical quests, got %d", len(want))
	}
	for id, amt := range want {
		got := taskRewardAmount(encodeTaskID(id)).Uint64()
		if got != amt {
			t.Errorf("taskRewardAmount(%q) = %d, want %d", id, got, amt)
		}
	}
	// Unknown ID pays 0.
	if taskRewardAmount(encodeTaskID("does-not-exist")).Uint64() != 0 {
		t.Error("unknown taskId should pay 0")
	}
}

// TestQuestVerifyPayout — full claim→verify cycle pays WAY from treasury 0x03
// and marks the claimant verified.
func TestQuestVerifyPayout(t *testing.T) {
	state := NewStateDB()
	// Fund the paying treasury (0x03) with 1_100_000 WAY.
	treasury := state.GetOrCreateAccount(PrecompileAddrHex(0x03))
	treasury.Balance = big.NewInt(1_100_000)
	// Seed live supply like genesis (cap = 5% of 100M = 5M, well above payout).
	QuestAddSupply(state, big.NewInt(100_000_000))

	claimer := "00000000000000000000000000000000000000aa"
	verifier := "00000000000000000000000000000000000000bb"
	// Verifier needs Dox_Dev L2+ to verify.
	vAcc := state.GetOrCreateAccount(verifier)
	vAcc.DoxDevLevel = 2

	task := encodeTaskID("1way-mint") // 300 WAY
	// taskClaim
	if _, err := taskRegistryPrecompile(append([]byte{0xA1, 0xB2, 0xC3, 0xD4}, task...), claimer, state, 1); err != nil {
		t.Fatalf("taskClaim: %v", err)
	}
	if TaskStatusOf(state, task, claimer) != "claimed" {
		t.Fatal("expected claimed after taskClaim")
	}
	// taskVerify (verifier, claimant)
	input := append([]byte{0xB2, 0xC3, 0xD4, 0xE5}, task...)
	input = append(input, hexDecodeAddress(claimer)...)
	if _, err := taskRegistryPrecompile(input, verifier, state, 1); err != nil {
		t.Fatalf("taskVerify: %v", err)
	}
	if TaskStatusOf(state, task, claimer) != "verified" {
		t.Fatal("expected verified after taskVerify")
	}
	got := state.GetAccount(claimer).Balance.Uint64()
	if got != 300 {
		t.Errorf("claimer balance = %d, want 300", got)
	}
	rem := QuestPoolRemaining(state).Uint64()
	// Dynamic cap: 5% of 100M seeded supply = 5,000,000; minus 300 paid.
	if rem != 5_000_000-300 {
		t.Errorf("pool remaining = %d, want %d", rem, 5_000_000-300)
	}
}

// TestQuestPoolRemainingZeroWhenUnfunded — guards against silent payouts when
// the treasury has no funds.
func TestQuestPoolRemainingZeroWhenUnfunded(t *testing.T) {
	state := NewStateDB()
	if QuestPoolRemaining(state).Uint64() != 0 {
		t.Error("unfunded pool should report 0")
	}
}

func hexDecodeAddress(a string) []byte {
	out := make([]byte, 20)
	b, err := hex.DecodeString(a)
	if err != nil || len(b) == 0 {
		return out
	}
	copy(out[20-len(b):], b)
	return out
}

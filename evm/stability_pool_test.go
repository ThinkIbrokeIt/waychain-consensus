// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"bytes"
	"math/big"
	"testing"
)

// TestStabilityPoolDeposit tests depositing 2WAY into the pool
func TestStabilityPoolDeposit(t *testing.T) {
	state := NewStateDB()

	depositAmt := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	depInput := make([]byte, 4+32)
	depInput[0], depInput[1], depInput[2], depInput[3] = 0x4E, 0x26, 0x60, 0x9A
	depositAmt.FillBytes(depInput[4:36])

	_, err := stabilityPoolPrecompile(depInput, "0xUser1", state, 100)
	if err != nil {
		t.Fatalf("Deposit failed: %v", err)
	}

	// Check pool stats
	poolInput := make([]byte, 4)
	poolInput[0], poolInput[1], poolInput[2], poolInput[3] = 0x8C, 0x5F, 0x41, 0xD0
	out, err := stabilityPoolPrecompile(poolInput, "0xUser1", state, 0)
	if err != nil {
		t.Fatalf("GetPoolStats failed: %v", err)
	}

	totalDeposits := readBigInt(readSlot(out, 0))
	twoWayBalance := readBigInt(readSlot(out, 32))

	if totalDeposits.Cmp(depositAmt) != 0 {
		t.Fatalf("Expected totalDeposits %s, got %s", depositAmt.String(), totalDeposits.String())
	}
	if twoWayBalance.Cmp(depositAmt) != 0 {
		t.Fatalf("Expected twoWayBalance %s, got %s", depositAmt.String(), twoWayBalance.String())
	}
}

// TestStabilityPoolWithdraw tests withdrawing from the pool
func TestStabilityPoolWithdraw(t *testing.T) {
	state := NewStateDB()

	// Deposit first
	depAmt := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	depInput := make([]byte, 4+32)
	depInput[0], depInput[1], depInput[2], depInput[3] = 0x4E, 0x26, 0x60, 0x9A
	depAmt.FillBytes(depInput[4:36])
	stabilityPoolPrecompile(depInput, "0xUser1", state, 100)

	// Withdraw 400
	withdrawAmt := new(big.Int).Mul(big.NewInt(400), big.NewInt(1e18))
	withdrawInput := make([]byte, 4+32)
	withdrawInput[0], withdrawInput[1], withdrawInput[2], withdrawInput[3] = 0x2E, 0x1A, 0x7D, 0xDD
	withdrawAmt.FillBytes(withdrawInput[4:36])

	_, err := stabilityPoolPrecompile(withdrawInput, "0xUser1", state, 101)
	if err != nil {
		t.Fatalf("Withdraw failed: %v", err)
	}

	// Check remaining = 600
	poolInput := make([]byte, 4)
	poolInput[0], poolInput[1], poolInput[2], poolInput[3] = 0x8C, 0x5F, 0x41, 0xD0
	out, _ := stabilityPoolPrecompile(poolInput, "0xUser1", state, 0)
	remaining := readBigInt(readSlot(out, 0))
	expected := new(big.Int).Mul(big.NewInt(600), big.NewInt(1e18))
	if remaining.Cmp(expected) != 0 {
		t.Fatalf("Expected remaining %s, got %s", expected.String(), remaining.String())
	}
}

// TestStabilityPoolOverWithdraw fails when withdrawing more than deposited
func TestStabilityPoolOverWithdraw(t *testing.T) {
	state := NewStateDB()

	// Deposit 500
	depAmt := new(big.Int).Mul(big.NewInt(500), big.NewInt(1e18))
	depInput := make([]byte, 4+32)
	depInput[0], depInput[1], depInput[2], depInput[3] = 0x4E, 0x26, 0x60, 0x9A
	depAmt.FillBytes(depInput[4:36])
	stabilityPoolPrecompile(depInput, "0xUser1", state, 100)

	// Try to withdraw 600 — should fail
	overWithdraw := new(big.Int).Mul(big.NewInt(600), big.NewInt(1e18))
	withdrawInput := make([]byte, 4+32)
	withdrawInput[0], withdrawInput[1], withdrawInput[2], withdrawInput[3] = 0x2E, 0x1A, 0x7D, 0xDD
	overWithdraw.FillBytes(withdrawInput[4:36])

	_, err := stabilityPoolPrecompile(withdrawInput, "0xUser1", state, 101)
	if err == nil {
		t.Fatal("Over-withdraw should fail but succeeded")
	}
}

// TestStabilityPoolAbsorb tests absorbing vault debt during liquidation
func TestStabilityPoolAbsorb(t *testing.T) {
	state := NewStateDB()

	// Set up 2WAY Vault with collateral first
	collateralID := "USD"
	vaultID := bytes.Repeat([]byte{0x05}, 32)
	vaultAddr := PrecompileAddrHex(0x18)
	vaultAcc := state.GetOrCreateAccount(vaultAddr)
	vaultAcc.Storage[paramKey(collateralID+":minCRatio")] = writeSlot(big.NewInt(13000))
	vaultAcc.Storage[paramKey(collateralID+":liqRatio")] = writeSlot(big.NewInt(12000))

	// Deposit collateral into vault
	collAddr := make([]byte, 20)
	copy(collAddr, collateralID)
	depAmt := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	depInput := make([]byte, 4+32+20+32)
	depInput[0], depInput[1], depInput[2], depInput[3] = 0xFB, 0xB3, 0x50, 0x30
	copy(depInput[4:36], vaultID)
	copy(depInput[36:56], collAddr)
	depAmt.FillBytes(depInput[56:88])
	twoWayVaultPrecompile(depInput, "0xUser1", state, 1)

	// Mint 500 2WAY (creates debt for liquidation)
	mintAmt := new(big.Int).Mul(big.NewInt(500), big.NewInt(1e18))
	mintInput := make([]byte, 4+32+32)
	mintInput[0], mintInput[1], mintInput[2], mintInput[3] = 0xD1, 0x85, 0xE0, 0x7F
	copy(mintInput[4:36], vaultID)
	mintAmt.FillBytes(mintInput[36:68])
	twoWayVaultPrecompile(mintInput, "0xUser1", state, 2)

	// Deposit into Stability Pool (more than vault debt)
	poolDepAmt := new(big.Int).Mul(big.NewInt(2000), big.NewInt(1e18))
	poolDepInput := make([]byte, 4+32)
	poolDepInput[0], poolDepInput[1], poolDepInput[2], poolDepInput[3] = 0x4E, 0x26, 0x60, 0x9A
	poolDepAmt.FillBytes(poolDepInput[4:36])
	stabilityPoolPrecompile(poolDepInput, "0xLP", state, 2)

	// Absorb vault debt
	absorbInput := make([]byte, 4+32)
	absorbInput[0], absorbInput[1], absorbInput[2], absorbInput[3] = 0x91, 0xB7, 0x8C, 0xB4
	copy(absorbInput[4:36], vaultID)

	out, err := stabilityPoolPrecompile(absorbInput, "0xLiquidator", state, 3)
	if err != nil {
		t.Fatalf("Absorb failed: %v", err)
	}

	// Check return value (true = last byte is 0x01)
	if out[31] != 0x01 {
		t.Fatal("Absorb should return true")
	}

	// Check pool balance decreased
	poolInput := make([]byte, 4)
	poolInput[0], poolInput[1], poolInput[2], poolInput[3] = 0x8C, 0x5F, 0x41, 0xD0
	stats, _ := stabilityPoolPrecompile(poolInput, "0xUser1", state, 0)
	twoWayBal := readBigInt(readSlot(stats, 32))
	if twoWayBal.Sign() <= 0 {
		t.Fatalf("Pool 2WAY balance should be > 0 after partial absorb, got %s", twoWayBal.String())
	}
}

// TestStabilityPoolClaimRewards tests claiming accumulated rewards
func TestStabilityPoolClaimRewards(t *testing.T) {
	state := NewStateDB()

	// Deposit into pool
	depAmt := new(big.Int).Mul(big.NewInt(500), big.NewInt(1e18))
	depInput := make([]byte, 4+32)
	depInput[0], depInput[1], depInput[2], depInput[3] = 0x4E, 0x26, 0x60, 0x9A
	depAmt.FillBytes(depInput[4:36])
	stabilityPoolPrecompile(depInput, "0xLP", state, 1)

	// Manually set rewards (simulating liquidation penalty distribution)
	addr := PrecompileAddrHex(0x19)
	acc := state.GetOrCreateAccount(addr)
	rewardKey := stabilityRewardKey("0xLP")
	acc.Storage[rewardKey] = writeSlot(new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18)))

	// Claim rewards
	claimInput := make([]byte, 4)
	claimInput[0], claimInput[1], claimInput[2], claimInput[3] = 0x6B, 0x6F, 0x43, 0x60

	out, err := stabilityPoolPrecompile(claimInput, "0xLP", state, 2)
	if err != nil {
		t.Fatalf("Claim failed: %v", err)
	}

	rewards := readBigInt(readSlot(out, 0))
	expected := new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18))
	if rewards.Cmp(expected) != 0 {
		t.Fatalf("Expected rewards %s, got %s", expected.String(), rewards.String())
	}
}

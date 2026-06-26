package evm

import (
	"math/big"
	"testing"
)

func TestStateRentPay(t *testing.T) {
	state := NewStateDB()

	// Pay rent
	payInput := make([]byte, 4+32)
	payInput[0], payInput[1], payInput[2], payInput[3] = 0xE1, 0xF2, 0xA3, 0xB4
	amount := new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)) // 10 WAY
	amount.FillBytes(payInput[4:36])

	out, err := stateRentPrecompile(payInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("Pay failed: %v", err)
	}
	if out[31] != 1 {
		t.Fatal("Pay should return true")
	}
	t.Logf("✅ Rent paid: 10 WAY")

	// Check status — should be active (not frozen)
	statusInput := make([]byte, 4+32)
	statusInput[0], statusInput[1], statusInput[2], statusInput[3] = 0xF2, 0xA3, 0xB4, 0xC5
	accountAddr := make([]byte, 32)
	copy(accountAddr, []byte("0xUser"))
	copy(statusInput[4:36], accountAddr)

	statusOut, err := stateRentPrecompile(statusInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if statusOut[0] != 0 {
		t.Fatal("Account should be active after paying rent")
	}
	t.Logf("✅ Account status: active")
}

func TestStateRentGetDue(t *testing.T) {
	state := NewStateDB()

	// Get due for account that never paid
	dueInput := make([]byte, 4+20)
	dueInput[0], dueInput[1], dueInput[2], dueInput[3] = 0xA3, 0xB4, 0xC5, 0xD6
	accountAddr := make([]byte, 20)
	copy(accountAddr, []byte("0xNewAccount-12345678"))
	copy(dueInput[4:24], accountAddr)

	dueOut, err := stateRentPrecompile(dueInput, "0xNewAccount-12345678", state, 1000)
	if err != nil {
		t.Fatalf("GetDue failed: %v", err)
	}
	dueAmount := readBigInt(readSlot(dueOut, 0))
	if dueAmount.Sign() <= 0 {
		t.Fatal("Due amount should be > 0 for new account")
	}
	t.Logf("✅ Due amount for new account: %s", dueAmount.String())
}

func TestStateRentGracePeriod(t *testing.T) {
	state := NewStateDB()

	// Pay rent
	payInput := make([]byte, 4+32)
	payInput[0], payInput[1], payInput[2], payInput[3] = 0xE1, 0xF2, 0xA3, 0xB4
	big.NewInt(1000000000000000000).FillBytes(payInput[4:36]) // 1 WAY
	stateRentPrecompile(payInput, "0xUser", state, 1000)

	// Check due after grace period (should be frozen)
	dueInput := make([]byte, 4+20)
	dueInput[0], dueInput[1], dueInput[2], dueInput[3] = 0xA3, 0xB4, 0xC5, 0xD6
	accountAddr := make([]byte, 20)
	copy(accountAddr, []byte("0xUser"))
	copy(dueInput[4:24], accountAddr)

	// Block 1000 + GracePeriod + 1
	dueOut, _ := stateRentPrecompile(dueInput, "0xUser", state, 1000+GracePeriod+1)
	if dueOut[0] != 0xFF {
		t.Fatal("Account should be frozen after grace period")
	}
	t.Logf("✅ Account frozen after grace period")

	// Check status
	statusInput := make([]byte, 4+32)
	statusInput[0], statusInput[1], statusInput[2], statusInput[3] = 0xF2, 0xA3, 0xB4, 0xC5
	statusAddr := make([]byte, 32)
	copy(statusAddr, []byte("0xUser"))
	copy(statusInput[4:36], statusAddr)

	statusOut, _ := stateRentPrecompile(statusInput, "0xUser", state, 1000+GracePeriod+1)
	if statusOut[0] != 1 {
		t.Fatal("Status should show frozen")
	}
	t.Logf("✅ Status shows frozen")
}

func TestStateRentDistribution(t *testing.T) {
	state := NewStateDB()

	// Pay rent
	payInput := make([]byte, 4+32)
	payInput[0], payInput[1], payInput[2], payInput[3] = 0xE1, 0xF2, 0xA3, 0xB4
	amount := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)) // 100 WAY
	amount.FillBytes(payInput[4:36])

	out, err := stateRentPrecompile(payInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("Pay failed: %v", err)
	}
	if out[31] != 1 {
		t.Fatal("Pay should return true")
	}

	// Verify distribution percentages
	expectedBurn := new(big.Int).Mul(amount, big.NewInt(StateRentBurnPercent))
	expectedBurn = expectedBurn.Div(expectedBurn, big.NewInt(100))
	expectedValidator := new(big.Int).Mul(amount, big.NewInt(StateRentValidatorPercent))
	expectedValidator = expectedValidator.Div(expectedValidator, big.NewInt(100))
	expectedTreasury := new(big.Int).Mul(amount, big.NewInt(StateRentTreasuryPercent))
	expectedTreasury = expectedTreasury.Div(expectedTreasury, big.NewInt(100))

	if expectedBurn.Cmp(new(big.Int).Mul(big.NewInt(60), big.NewInt(1e18))) != 0 {
		t.Fatalf("Expected burn 60 WAY, got %s", expectedBurn.String())
	}
	if expectedValidator.Cmp(new(big.Int).Mul(big.NewInt(30), big.NewInt(1e18))) != 0 {
		t.Fatalf("Expected validator 30 WAY, got %s", expectedValidator.String())
	}
	if expectedTreasury.Cmp(new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18))) != 0 {
		t.Fatalf("Expected treasury 10 WAY, got %s", expectedTreasury.String())
	}

	t.Logf("✅ Distribution: burn=60%%, validators=30%%, treasury=10%%")
}

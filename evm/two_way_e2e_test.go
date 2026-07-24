// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"bytes"
	"math/big"
	"testing"
)

// TestTwoWayEndToEnd_FullLifecycle tests the complete stablecoin flow:
// 1. Oracle sets price
// 2. User deposits collateral
// 3. User mints 2WAY
// 4. User burns 2WAY (partial repay)
// 5. User withdraws collateral
// 6. Liquidation: vault falls below C-Ratio, Stability Pool absorbs
func TestTwoWayEndToEnd_FullLifecycle(t *testing.T) {
	state := NewStateDB()

	// ═══ Step 1: Oracle sets price ═══
	oracleAddr := "oracle1"
	oracleAcc := state.GetOrCreateAccount(oracleAddr)
	oracleAcc.DoxDevLevel = 2

	priceInput := make([]byte, 4+32+32)
	priceInput[0], priceInput[1], priceInput[2], priceInput[3] = 0x7A, 0x3B, 0x4F, 0x00
	stablecoinID := make([]byte, 32)
	copy(stablecoinID, []byte("USD"))
	copy(priceInput[4:36], stablecoinID)
	price := new(big.Int).SetUint64(100000000) // $1.00
	price.FillBytes(priceInput[36:68])
	_, err := twoWaySetStablecoinPrice(priceInput, oracleAddr, state)
	if err != nil {
		t.Fatalf("Step 1: Set price failed: %v", err)
	}
	t.Logf("✅ Step 1: Oracle set USD price = $1.00")

	// ═══ Step 2: User deposits collateral ═══
	vaultID := bytes.Repeat([]byte{0xA0}, 32)
	vaultAddr := PrecompileAddrHex(0x18)
	vaultAcc := state.GetOrCreateAccount(vaultAddr)
	vaultAcc.Storage[paramKey("USD:minCRatio")] = writeSlot(big.NewInt(13000))
	vaultAcc.Storage[paramKey("USD:liqRatio")] = writeSlot(big.NewInt(12000))

	collAddr := make([]byte, 20)
	copy(collAddr, []byte("USD"))
	depAmt := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	depInput := make([]byte, 4+32+20+32)
	depInput[0], depInput[1], depInput[2], depInput[3] = 0xFB, 0xB3, 0x50, 0x30
	copy(depInput[4:36], vaultID)
	copy(depInput[36:56], collAddr)
	depAmt.FillBytes(depInput[56:88])

	_, err = twoWayVaultPrecompile(depInput, "0xUser1", state, 100)
	if err != nil {
		t.Fatalf("Step 2: Deposit failed: %v", err)
	}
	t.Logf("✅ Step 2: Deposited 1000 USD collateral")

	// ═══ Step 3: User mints 2WAY ═══
	mintAmt := new(big.Int).Mul(big.NewInt(700), big.NewInt(1e18)) // 700 2WAY at 142% C-Ratio
	mintInput := make([]byte, 4+32+32)
	mintInput[0], mintInput[1], mintInput[2], mintInput[3] = 0xD1, 0x85, 0xE0, 0x7F
	copy(mintInput[4:36], vaultID)
	mintAmt.FillBytes(mintInput[36:68])

	_, err = twoWayVaultPrecompile(mintInput, "0xUser1", state, 101)
	if err != nil {
		t.Fatalf("Step 3: Mint failed: %v", err)
	}
	t.Logf("✅ Step 3: Minted 700 2WAY")

	// Verify vault state
	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0x9E, 0xB2, 0x9E, 0xF0
	copy(getInput[4:36], vaultID)
	out, _ := twoWayVaultPrecompile(getInput, "0xUser1", state, 0)
	collateral := readBigInt(readSlot(out, 0))
	debt := readBigInt(readSlot(out, 32))
	if collateral.Cmp(depAmt) != 0 {
		t.Fatalf("Expected collateral 1000, got %s", collateral.String())
	}
	if debt.Cmp(mintAmt) != 0 {
		t.Fatalf("Expected debt 700, got %s", debt.String())
	}

	// ═══ Step 4: User burns 2WAY (partial repay) ═══
	burnAmt := new(big.Int).Mul(big.NewInt(300), big.NewInt(1e18))
	burnInput := make([]byte, 4+32+32)
	burnInput[0], burnInput[1], burnInput[2], burnInput[3] = 0x0E, 0x0C, 0x59, 0xBE
	copy(burnInput[4:36], vaultID)
	burnAmt.FillBytes(burnInput[36:68])
	_, err = twoWayVaultPrecompile(burnInput, "0xUser1", state, 102)
	if err != nil {
		t.Fatalf("Step 4: Burn failed: %v", err)
	}
	expectedDebt := new(big.Int).Mul(big.NewInt(400), big.NewInt(1e18)) // 700 - 300
	out, _ = twoWayVaultPrecompile(getInput, "0xUser1", state, 0)
	debt = readBigInt(readSlot(out, 32))
	if debt.Cmp(expectedDebt) != 0 {
		t.Fatalf("Expected debt 400 after burn, got %s", debt.String())
	}
	t.Logf("✅ Step 4: Burned 300 2WAY, remaining debt = 400")

	// ═══ Step 5: User withdraws collateral ═══
	withdrawAmt := new(big.Int).Mul(big.NewInt(200), big.NewInt(1e18))
	withdrawInput := make([]byte, 4+32+20+32)
	withdrawInput[0], withdrawInput[1], withdrawInput[2], withdrawInput[3] = 0xE9, 0xC4, 0xB1, 0x12
	copy(withdrawInput[4:36], vaultID)
	copy(withdrawInput[36:56], collAddr)
	withdrawAmt.FillBytes(withdrawInput[56:88])
	_, err = twoWayVaultPrecompile(withdrawInput, "0xUser1", state, 103)
	if err != nil {
		t.Fatalf("Step 5: Withdraw failed: %v", err)
	}
	expectedCollateral := new(big.Int).Mul(big.NewInt(800), big.NewInt(1e18)) // 1000 - 200
	out, _ = twoWayVaultPrecompile(getInput, "0xUser1", state, 0)
	collateral = readBigInt(readSlot(out, 0))
	if collateral.Cmp(expectedCollateral) != 0 {
		t.Fatalf("Expected collateral 800 after withdraw, got %s", collateral.String())
	}
	t.Logf("✅ Step 5: Withdrew 200 USD, remaining collateral = 800")

	// ═══ Step 6: Liquidation — price drops, vault becomes undercollateralized ═══
	// Simulate USD depeg to $0.50 (collateral value drops 50%)
	depegPrice := new(big.Int).SetUint64(50000000) // $0.50
	depegInput := make([]byte, 4+32+32)
	depegInput[0], depegInput[1], depegInput[2], depegInput[3] = 0x7A, 0x3B, 0x4F, 0x00
	copy(depegInput[4:36], stablecoinID)
	depegPrice.FillBytes(depegInput[36:68])
	_, err = twoWaySetStablecoinPrice(depegInput, oracleAddr, state)
	if err != nil {
		t.Fatalf("Step 6: Set depeg price failed: %v", err)
	}
	t.Logf("✅ Step 6: USD price dropped to $0.50 (depeg)")

	// Vault should now be undercollateralized:
	// Collateral value = 800 * $0.50 = $400
	// Debt = 400 2WAY = $400
	// C-Ratio = 400/400 = 100% (below 130% minimum, below 120% liquidation)

	// Deposit into Stability Pool for absorption
	poolAddr := PrecompileAddrHex(0x19)
	poolAcc := state.GetOrCreateAccount(poolAddr)
	poolAcc.Storage[storageKey([]byte("totalDeposits"))] = writeSlot(new(big.Int).Mul(big.NewInt(2000), big.NewInt(1e18)))
	poolAcc.Storage[storageKey([]byte("twoWayBalance"))] = writeSlot(new(big.Int).Mul(big.NewInt(2000), big.NewInt(1e18)))

	// Liquidate vault
	liquidateInput := make([]byte, 4+32)
	liquidateInput[0], liquidateInput[1], liquidateInput[2], liquidateInput[3] = 0x5C, 0x8B, 0x76, 0x98
	copy(liquidateInput[4:36], vaultID)
	_, err = twoWayVaultPrecompile(liquidateInput, "0xLiquidator", state, 104)
	if err != nil {
		t.Fatalf("Step 6: Liquidate failed: %v", err)
	}

	// Verify vault debt is cleared
	out, _ = twoWayVaultPrecompile(getInput, "0xUser1", state, 0)
	debt = readBigInt(readSlot(out, 32))
	if debt.Sign() != 0 {
		t.Fatalf("Expected debt 0 after liquidation, got %s", debt.String())
	}
	t.Logf("✅ Step 6: Vault liquidated, debt cleared")

	t.Logf("═══ 2WAY End-to-End Lifecycle: ALL PASSED ═══")
}

// TestTwoWayEndToEnd_DepositMintBurnWithdraw tests the happy path without liquidation
func TestTwoWayEndToEnd_DepositMintBurnWithdraw(t *testing.T) {
	state := NewStateDB()

	// Setup oracle
	oracleAddr := "oracle1"
	oracleAcc := state.GetOrCreateAccount(oracleAddr)
	oracleAcc.DoxDevLevel = 2
	priceInput := make([]byte, 4+32+32)
	priceInput[0], priceInput[1], priceInput[2], priceInput[3] = 0x7A, 0x3B, 0x4F, 0x00
	stablecoinID := make([]byte, 32)
	copy(stablecoinID, []byte("USD"))
	copy(priceInput[4:36], stablecoinID)
	new(big.Int).SetUint64(100000000).FillBytes(priceInput[36:68])
	twoWaySetStablecoinPrice(priceInput, oracleAddr, state)

	// Setup vault
	vaultID := bytes.Repeat([]byte{0xB0}, 32)
	vaultAddr := PrecompileAddrHex(0x18)
	vaultAcc := state.GetOrCreateAccount(vaultAddr)
	vaultAcc.Storage[paramKey("USD:minCRatio")] = writeSlot(big.NewInt(13000))
	vaultAcc.Storage[paramKey("USD:liqRatio")] = writeSlot(big.NewInt(12000))

	collAddr := make([]byte, 20)
	copy(collAddr, []byte("USD"))

	// Deposit 500
	depAmt := new(big.Int).Mul(big.NewInt(500), big.NewInt(1e18))
	depInput := make([]byte, 4+32+20+32)
	depInput[0], depInput[1], depInput[2], depInput[3] = 0xFB, 0xB3, 0x50, 0x30
	copy(depInput[4:36], vaultID)
	copy(depInput[36:56], collAddr)
	depAmt.FillBytes(depInput[56:88])
	twoWayVaultPrecompile(depInput, "0xUser", state, 1)

	// Mint 300 (166% C-Ratio)
	mintAmt := new(big.Int).Mul(big.NewInt(300), big.NewInt(1e18))
	mintInput := make([]byte, 4+32+32)
	mintInput[0], mintInput[1], mintInput[2], mintInput[3] = 0xD1, 0x85, 0xE0, 0x7F
	copy(mintInput[4:36], vaultID)
	mintAmt.FillBytes(mintInput[36:68])
	twoWayVaultPrecompile(mintInput, "0xUser", state, 2)

	// Burn all 300
	burnAmt := new(big.Int).Mul(big.NewInt(300), big.NewInt(1e18))
	burnInput := make([]byte, 4+32+32)
	burnInput[0], burnInput[1], burnInput[2], burnInput[3] = 0x0E, 0x0C, 0x59, 0xBE
	copy(burnInput[4:36], vaultID)
	burnAmt.FillBytes(burnInput[36:68])
	twoWayVaultPrecompile(burnInput, "0xUser", state, 3)

	// Verify debt = 0
	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0x9E, 0xB2, 0x9E, 0xF0
	copy(getInput[4:36], vaultID)
	out, _ := twoWayVaultPrecompile(getInput, "0xUser", state, 0)
	debt := readBigInt(readSlot(out, 32))
	if debt.Sign() != 0 {
		t.Fatalf("Expected debt 0 after full burn, got %s", debt.String())
	}

	// Withdraw all 500
	withdrawAmt := new(big.Int).Mul(big.NewInt(500), big.NewInt(1e18))
	withdrawInput := make([]byte, 4+32+20+32)
	withdrawInput[0], withdrawInput[1], withdrawInput[2], withdrawInput[3] = 0xE9, 0xC4, 0xB1, 0x12
	copy(withdrawInput[4:36], vaultID)
	copy(withdrawInput[36:56], collAddr)
	withdrawAmt.FillBytes(withdrawInput[56:88])
	_, err := twoWayVaultPrecompile(withdrawInput, "0xUser", state, 4)
	if err != nil {
		t.Fatalf("Withdraw all failed: %v", err)
	}

	// Verify collateral = 0
	out, _ = twoWayVaultPrecompile(getInput, "0xUser", state, 0)
	collateral := readBigInt(readSlot(out, 0))
	if collateral.Sign() != 0 {
		t.Fatalf("Expected collateral 0 after full withdraw, got %s", collateral.String())
	}

	t.Logf("✅ Deposit→Mint→Burn→Withdraw: full lifecycle without liquidation")
}

// TestTwoWayEndToEnd_MultipleUsers tests multiple users interacting with the protocol
func TestTwoWayEndToEnd_MultipleUsers(t *testing.T) {
	state := NewStateDB()

	// Setup oracle
	oracleAddr := "oracle1"
	oracleAcc := state.GetOrCreateAccount(oracleAddr)
	oracleAcc.DoxDevLevel = 2
	priceInput := make([]byte, 4+32+32)
	priceInput[0], priceInput[1], priceInput[2], priceInput[3] = 0x7A, 0x3B, 0x4F, 0x00
	stablecoinID := make([]byte, 32)
	copy(stablecoinID, []byte("USD"))
	copy(priceInput[4:36], stablecoinID)
	new(big.Int).SetUint64(100000000).FillBytes(priceInput[36:68])
	twoWaySetStablecoinPrice(priceInput, oracleAddr, state)

	// Setup vault
	vaultAddr := PrecompileAddrHex(0x18)
	vaultAcc := state.GetOrCreateAccount(vaultAddr)
	vaultAcc.Storage[paramKey("USD:minCRatio")] = writeSlot(big.NewInt(13000))
	vaultAcc.Storage[paramKey("USD:liqRatio")] = writeSlot(big.NewInt(12000))

	collAddr := make([]byte, 20)
	copy(collAddr, []byte("USD"))

	// User1 deposits 500, mints 300
	vaultID1 := bytes.Repeat([]byte{0xC1}, 32)
	depAmt1 := new(big.Int).Mul(big.NewInt(500), big.NewInt(1e18))
	depInput1 := make([]byte, 4+32+20+32)
	depInput1[0], depInput1[1], depInput1[2], depInput1[3] = 0xFB, 0xB3, 0x50, 0x30
	copy(depInput1[4:36], vaultID1)
	copy(depInput1[36:56], collAddr)
	depAmt1.FillBytes(depInput1[56:88])
	twoWayVaultPrecompile(depInput1, "0xUser1", state, 1)

	mintAmt1 := new(big.Int).Mul(big.NewInt(300), big.NewInt(1e18))
	mintInput1 := make([]byte, 4+32+32)
	mintInput1[0], mintInput1[1], mintInput1[2], mintInput1[3] = 0xD1, 0x85, 0xE0, 0x7F
	copy(mintInput1[4:36], vaultID1)
	mintAmt1.FillBytes(mintInput1[36:68])
	twoWayVaultPrecompile(mintInput1, "0xUser1", state, 2)

	// User2 deposits 1000, mints 600
	vaultID2 := bytes.Repeat([]byte{0xC2}, 32)
	depAmt2 := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	depInput2 := make([]byte, 4+32+20+32)
	depInput2[0], depInput2[1], depInput2[2], depInput2[3] = 0xFB, 0xB3, 0x50, 0x30
	copy(depInput2[4:36], vaultID2)
	copy(depInput2[36:56], collAddr)
	depAmt2.FillBytes(depInput2[56:88])
	twoWayVaultPrecompile(depInput2, "0xUser2", state, 3)

	mintAmt2 := new(big.Int).Mul(big.NewInt(600), big.NewInt(1e18))
	mintInput2 := make([]byte, 4+32+32)
	mintInput2[0], mintInput2[1], mintInput2[2], mintInput2[3] = 0xD1, 0x85, 0xE0, 0x7F
	copy(mintInput2[4:36], vaultID2)
	mintAmt2.FillBytes(mintInput2[36:68])
	twoWayVaultPrecompile(mintInput2, "0xUser2", state, 4)

	// Verify User1
	getInput1 := make([]byte, 4+32)
	getInput1[0], getInput1[1], getInput1[2], getInput1[3] = 0x9E, 0xB2, 0x9E, 0xF0
	copy(getInput1[4:36], vaultID1)
	out1, _ := twoWayVaultPrecompile(getInput1, "0xUser1", state, 0)
	if readBigInt(readSlot(out1, 0)).Cmp(depAmt1) != 0 {
		t.Fatalf("User1 collateral mismatch")
	}
	if readBigInt(readSlot(out1, 32)).Cmp(mintAmt1) != 0 {
		t.Fatalf("User1 debt mismatch")
	}

	// Verify User2
	getInput2 := make([]byte, 4+32)
	getInput2[0], getInput2[1], getInput2[2], getInput2[3] = 0x9E, 0xB2, 0x9E, 0xF0
	copy(getInput2[4:36], vaultID2)
	out2, _ := twoWayVaultPrecompile(getInput2, "0xUser2", state, 0)
	if readBigInt(readSlot(out2, 0)).Cmp(depAmt2) != 0 {
		t.Fatalf("User2 collateral mismatch")
	}
	if readBigInt(readSlot(out2, 32)).Cmp(mintAmt2) != 0 {
		t.Fatalf("User2 debt mismatch")
	}

	// Verify total debt in protocol
	totalDebt := readBigInt(vaultAcc.Storage[storageKey([]byte("totalDebt"))])
	expectedTotal := new(big.Int).Add(mintAmt1, mintAmt2) // 900
	if totalDebt.Cmp(expectedTotal) != 0 {
		t.Fatalf("Expected total debt 900, got %s", totalDebt.String())
	}

	t.Logf("✅ Multiple users: User1 (500 dep/300 mint), User2 (1000 dep/600 mint), total debt = 900")
}

// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"bytes"
	"math/big"
	"testing"
)

// ═══ 2WAY Vault Tests ═══

func TestTwoWayDeposit(t *testing.T) {
	state := NewStateDB()
	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)
	acc.Storage[paramKey("USD:minCRatio")] = writeSlot(big.NewInt(13000))
	acc.Storage[paramKey("USD:liqRatio")] = writeSlot(big.NewInt(12000))

	vaultID := make([]byte, 32)
	copy(vaultID, []byte("test-vault-001"))
	collateralAddr := make([]byte, 20)
	copy(collateralAddr, []byte("USD"))
	depositAmount := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))

	depInput := make([]byte, 4+32+20+32)
	depInput[0], depInput[1], depInput[2], depInput[3] = 0xFB, 0xB3, 0x50, 0x30
	copy(depInput[4:36], vaultID)
	copy(depInput[36:56], collateralAddr)
	depositAmount.FillBytes(depInput[56:88])

	_, err := twoWayVaultPrecompile(depInput, "0xUser", state, 100)
	if err != nil {
		t.Fatalf("Deposit failed: %v", err)
	}

	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0x9E, 0xB2, 0x9E, 0xF0
	copy(getInput[4:36], vaultID)
	out, err := twoWayVaultPrecompile(getInput, "0xUser", state, 0)
	if err != nil {
		t.Fatalf("GetVault failed: %v", err)
	}
	collateral := readBigInt(readSlot(out, 0))
	debt := readBigInt(readSlot(out, 32))
	if collateral.Cmp(depositAmount) != 0 {
		t.Fatalf("Expected collateral %s, got %s", depositAmount.String(), collateral.String())
	}
	if debt.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("Expected debt 0, got %s", debt.String())
	}
}

func TestTwoWayMint(t *testing.T) {
	state := NewStateDB()
	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)
	acc.Storage[paramKey("USD:minCRatio")] = writeSlot(big.NewInt(13000))
	acc.Storage[paramKey("USD:liqRatio")] = writeSlot(big.NewInt(12000))

	vaultID := bytes.Repeat([]byte{0x01}, 32)
	collAddr := make([]byte, 20)
	copy(collAddr, []byte("USD"))

	depAmt := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	depInput := make([]byte, 4+32+20+32)
	depInput[0], depInput[1], depInput[2], depInput[3] = 0xFB, 0xB3, 0x50, 0x30
	copy(depInput[4:36], vaultID)
	copy(depInput[36:56], collAddr)
	depAmt.FillBytes(depInput[56:88])
	twoWayVaultPrecompile(depInput, "0xUser", state, 1)

	mintAmt := new(big.Int).Mul(big.NewInt(500), big.NewInt(1e18))
	mintInput := make([]byte, 4+32+32)
	mintInput[0], mintInput[1], mintInput[2], mintInput[3] = 0xD1, 0x85, 0xE0, 0x7F
	copy(mintInput[4:36], vaultID)
	mintAmt.FillBytes(mintInput[36:68])

	_, err := twoWayVaultPrecompile(mintInput, "0xUser", state, 2)
	if err != nil {
		t.Fatalf("Mint should succeed: %v", err)
	}

	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0x9E, 0xB2, 0x9E, 0xF0
	copy(getInput[4:36], vaultID)
	out, _ := twoWayVaultPrecompile(getInput, "0xUser", state, 0)
	debt := readBigInt(readSlot(out, 32))
	if debt.Cmp(big.NewInt(0)) <= 0 {
		t.Fatalf("Expected debt > 0 after mint")
	}
}

func TestTwoWayOverMintFails(t *testing.T) {
	state := NewStateDB()
	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)
	acc.Storage[paramKey("USD:minCRatio")] = writeSlot(big.NewInt(13000))

	vaultID := bytes.Repeat([]byte{0x02}, 32)
	collAddr := make([]byte, 20)
	copy(collAddr, []byte("USD"))

	depAmt := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	depInput := make([]byte, 4+32+20+32)
	depInput[0], depInput[1], depInput[2], depInput[3] = 0xFB, 0xB3, 0x50, 0x30
	copy(depInput[4:36], vaultID)
	copy(depInput[36:56], collAddr)
	depAmt.FillBytes(depInput[56:88])
	twoWayVaultPrecompile(depInput, "0xUser", state, 1)

	overMint := new(big.Int).Mul(big.NewInt(2000), big.NewInt(1e18))
	mintInput := make([]byte, 4+32+32)
	mintInput[0], mintInput[1], mintInput[2], mintInput[3] = 0xD1, 0x85, 0xE0, 0x7F
	copy(mintInput[4:36], vaultID)
	overMint.FillBytes(mintInput[36:68])

	_, err := twoWayVaultPrecompile(mintInput, "0xUser", state, 2)
	if err == nil {
		t.Fatal("Over-mint should fail but succeeded")
	}
}

func TestTwoWayBurn(t *testing.T) {
	state := NewStateDB()
	addr := PrecompileAddrHex(0x18)
	acc := state.GetOrCreateAccount(addr)
	acc.Storage[paramKey("USD:minCRatio")] = writeSlot(big.NewInt(13000))

	vaultID := bytes.Repeat([]byte{0x03}, 32)
	collAddr := make([]byte, 20)
	copy(collAddr, []byte("USD"))

	depAmt := new(big.Int).Mul(big.NewInt(500), big.NewInt(1e18))
	depInput := make([]byte, 4+32+20+32)
	depInput[0], depInput[1], depInput[2], depInput[3] = 0xFB, 0xB3, 0x50, 0x30
	copy(depInput[4:36], vaultID)
	copy(depInput[36:56], collAddr)
	depAmt.FillBytes(depInput[56:88])
	twoWayVaultPrecompile(depInput, "0xUser", state, 1)

	mintAmt := new(big.Int).Mul(big.NewInt(300), big.NewInt(1e18))
	mintInput := make([]byte, 4+32+32)
	mintInput[0], mintInput[1], mintInput[2], mintInput[3] = 0xD1, 0x85, 0xE0, 0x7F
	copy(mintInput[4:36], vaultID)
	mintAmt.FillBytes(mintInput[36:68])
	twoWayVaultPrecompile(mintInput, "0xUser", state, 2)

	burnAmt := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	burnInput := make([]byte, 4+32+32)
	burnInput[0], burnInput[1], burnInput[2], burnInput[3] = 0x0E, 0x0C, 0x59, 0xBE
	copy(burnInput[4:36], vaultID)
	burnAmt.FillBytes(burnInput[36:68])
	_, err := twoWayVaultPrecompile(burnInput, "0xUser", state, 3)
	if err != nil {
		t.Fatalf("Burn failed: %v", err)
	}

	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0x9E, 0xB2, 0x9E, 0xF0
	copy(getInput[4:36], vaultID)
	out, _ := twoWayVaultPrecompile(getInput, "0xUser", state, 0)
	remainingDebt := readBigInt(readSlot(out, 32))
	expected := new(big.Int).Mul(big.NewInt(200), big.NewInt(1e18))
	if remainingDebt.Cmp(expected) != 0 {
		t.Fatalf("Expected debt %s, got %s", expected.String(), remainingDebt.String())
	}
}

// ═══ Price Oracle Tests ═══

func TestTwoWayPriceOracle(t *testing.T) {
	state := NewStateDB()
	oracleAddr := "oracle_verified_1"
	oracleAcc := state.GetOrCreateAccount(oracleAddr)
	oracleAcc.DoxDevLevel = 2

	priceInput := make([]byte, 4+32+32)
	priceInput[0], priceInput[1], priceInput[2], priceInput[3] = 0x7A, 0x3B, 0x4F, 0x00
	stablecoinID := make([]byte, 32)
	copy(stablecoinID, []byte("USD"))
	copy(priceInput[4:36], stablecoinID)
	price := new(big.Int).SetUint64(100000000)
	price.FillBytes(priceInput[36:68])

	_, err := twoWaySetStablecoinPrice(priceInput, oracleAddr, state)
	if err != nil {
		t.Fatalf("Set price failed: %v", err)
	}

	getPriceInput := make([]byte, 4+32)
	getPriceInput[0], getPriceInput[1], getPriceInput[2], getPriceInput[3] = 0x7A, 0x3B, 0x4F, 0x00
	copy(getPriceInput[4:36], stablecoinID)
	out, err := twoWayGetStablecoinPrice(getPriceInput, oracleAddr, state)
	if err != nil {
		t.Fatalf("Get price failed: %v", err)
	}
	gotPrice := readBigInt(readSlot(out, 0))
	if gotPrice.Cmp(price) != 0 {
		t.Fatalf("Expected price %s, got %s", price.String(), gotPrice.String())
	}
}

func TestTwoWayPriceDefault(t *testing.T) {
	state := NewStateDB()
	getPriceInput := make([]byte, 4+32)
	getPriceInput[0], getPriceInput[1], getPriceInput[2], getPriceInput[3] = 0x7A, 0x3B, 0x4F, 0x00
	stablecoinID := make([]byte, 32)
	copy(stablecoinID, []byte("NEWCOIN"))
	copy(getPriceInput[4:36], stablecoinID)
	out, err := twoWayGetStablecoinPrice(getPriceInput, "0xUser", state)
	if err != nil {
		t.Fatalf("Get price failed: %v", err)
	}
	gotPrice := readBigInt(readSlot(out, 0))
	defaultPrice := new(big.Int).SetUint64(100000000)
	if gotPrice.Cmp(defaultPrice) != 0 {
		t.Fatalf("Expected default price %s, got %s", defaultPrice.String(), gotPrice.String())
	}
}

func TestTwoWayPriceUnauthorizedOracle(t *testing.T) {
	state := NewStateDB()
	priceInput := make([]byte, 4+32+32)
	priceInput[0], priceInput[1], priceInput[2], priceInput[3] = 0x7A, 0x3B, 0x4F, 0x00
	stablecoinID := make([]byte, 32)
	copy(stablecoinID, []byte("USD"))
	copy(priceInput[4:36], stablecoinID)
	price := new(big.Int).SetUint64(100000000)
	price.FillBytes(priceInput[36:68])

	_, err := twoWaySetStablecoinPrice(priceInput, "0xUnverified", state)
	if err == nil {
		t.Fatal("Unverified caller should not be able to set prices")
	}
}

func TestTwoWayCollateralValueUSD(t *testing.T) {
	state := NewStateDB()
	oracleAddr := "oracle1"
	oracleAcc := state.GetOrCreateAccount(oracleAddr)
	oracleAcc.DoxDevLevel = 2

	priceInput := make([]byte, 4+32+32)
	priceInput[0], priceInput[1], priceInput[2], priceInput[3] = 0x7A, 0x3B, 0x4F, 0x00
	stablecoinID := make([]byte, 32)
	copy(stablecoinID, []byte("USD"))
	copy(priceInput[4:36], stablecoinID)
	price := new(big.Int).SetUint64(100000000)
	price.FillBytes(priceInput[36:68])
	twoWaySetStablecoinPrice(priceInput, oracleAddr, state)

	vaultID := bytes.Repeat([]byte{0x10}, 32)
	vaultAddr := PrecompileAddrHex(0x18)
	vaultAcc := state.GetOrCreateAccount(vaultAddr)
	vaultAcc.Storage[paramKey("USD:minCRatio")] = writeSlot(big.NewInt(13000))

	depAmt := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	depInput := make([]byte, 4+32+20+32)
	depInput[0], depInput[1], depInput[2], depInput[3] = 0xFB, 0xB3, 0x50, 0x30
	copy(depInput[4:36], vaultID)
	collAddr := make([]byte, 20)
	copy(collAddr, []byte("USD"))
	copy(depInput[36:56], collAddr)
	depAmt.FillBytes(depInput[56:88])
	twoWayVaultPrecompile(depInput, "0xUser", state, 1)

	valueUSD := getVaultCollateralValueUSD(vaultID, state)
	expected := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	if valueUSD.Cmp(expected) != 0 {
		t.Fatalf("Expected collateral value %s, got %s", expected.String(), valueUSD.String())
	}
}

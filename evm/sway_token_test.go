package evm

import (
	"bytes"
	"math/big"
	"testing"
)

// selSwayGetBalance = 0xC3D4E5A6, selSwayMint = 0xA1B2C3E4
func TestSwayGetBalanceNilAccount(t *testing.T) {
	state := NewStateDB()

	// Address that has never had an account — this is the exact path that
	// previously panicked (nil .Storage deref) and surfaced as HTTP 502.
	addr := bytes.Repeat([]byte{0xAB}, 20)
	input := make([]byte, 4+20)
	input[0], input[1], input[2], input[3] = 0xC3, 0xD4, 0xE5, 0xA6
	copy(input[4:24], addr)

	out, err := swayPrecompile(input, "0xAny", state, 1)
	if err != nil {
		t.Fatalf("getBalance on absent account failed: %v", err)
	}
	bal := readBigInt(readSlot(out, 0))
	if bal.Sign() != 0 {
		t.Fatalf("Expected 0 balance for absent account, got %s", bal.String())
	}
}

func TestSwayGetBalanceAfterMint(t *testing.T) {
	state := NewStateDB()

	addr := bytes.Repeat([]byte{0xCD}, 20)
	mintAmt := new(big.Int).Mul(big.NewInt(420), big.NewInt(1e18))

	// Mint requires caller == StabilityPool (0x19)
	mintInput := make([]byte, 4+20+32)
	mintInput[0], mintInput[1], mintInput[2], mintInput[3] = 0xA1, 0xB2, 0xC3, 0xE4
	copy(mintInput[4:24], addr)
	mintAmt.FillBytes(mintInput[24:56])

	if _, err := swayPrecompile(mintInput, PrecompileAddrHex(0x19), state, 1); err != nil {
		t.Fatalf("mint failed: %v", err)
	}

	getInput := make([]byte, 4+20)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0xC3, 0xD4, 0xE5, 0xA6
	copy(getInput[4:24], addr)

	out, err := swayPrecompile(getInput, "0xAny", state, 2)
	if err != nil {
		t.Fatalf("getBalance failed: %v", err)
	}
	bal := readBigInt(readSlot(out, 0))
	if bal.Cmp(mintAmt) != 0 {
		t.Fatalf("Expected balance %s, got %s", mintAmt.String(), bal.String())
	}
}

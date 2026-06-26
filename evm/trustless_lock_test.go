package evm

import (
	"bytes"
	"math/big"
	"testing"
)

func TestTrustlessLockTimeLock(t *testing.T) {
	state := NewStateDB()

	var poolAddr, token0, token1, recipient [20]byte
	copy(poolAddr[:], []byte("pool-address-12345678"))
	copy(token0[:], []byte("token0-address-1234567"))
	copy(token1[:], []byte("token1-address-1234567"))
	copy(recipient[:], []byte("recipient-addr-12345678"))

	amount := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	lockPeriod := new(big.Int).SetUint64(3000000) // ~34 days

	// Create time lock
	input := make([]byte, 4+20+20+20+32+32+20)
	input[0], input[1], input[2], input[3] = 0xA1, 0xB2, 0xC3, 0xD4
	copy(input[4:24], poolAddr[:])
	copy(input[24:44], token0[:])
	copy(input[44:64], token1[:])
	amount.FillBytes(input[64:96])
	lockPeriod.FillBytes(input[96:128])
	copy(input[128:148], recipient[:])

	out, err := trustlessLockPrecompile(input, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("CreateTimeLock failed: %v", err)
	}

	// Output should be 32 bytes (lockID)
	if len(out) != 32 {
		t.Fatalf("Expected 32 byte lockID, got %d bytes", len(out))
	}

	t.Logf("✅ Time lock created, lockID: %x", out[:8])

	// Test releasable amount before unlock (block 1000, unlock at 1000+3000000=3001000)
	releasableInput := append([]byte{0xE5, 0xF6, 0xA7, 0xB8}, out...)
	releasable, _ := trustlessLockPrecompile(releasableInput, "0xUser", state, 1000)
	releasableAmount := readBigInt(readSlot(releasable, 0))
	if releasableAmount.Sign() != 0 {
		t.Fatalf("Expected 0 releasable before unlock, got %s", releasableAmount.String())
	}

	// Test releasable amount after unlock (block 4000000 > 3001000)
	releasable2, _ := trustlessLockPrecompile(releasableInput, "0xUser", state, 4000000)
	releasableAmount2 := readBigInt(readSlot(releasable2, 0))
	if releasableAmount2.Sign() == 0 {
		t.Fatal("Expected >0 releasable after unlock")
	}

	t.Logf("✅ Time lock: 0 before unlock, >0 after unlock")

	// Test extend
	extendInput := append([]byte{0xA7, 0xB8, 0xC9, 0xD0}, out...)
	extendPeriod := new(big.Int).SetUint64(1000000)
	extendInput = append(extendInput, extendPeriod.FillBytes(make([]byte, 32))...)
	_, err = trustlessLockPrecompile(extendInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("Extend failed: %v", err)
	}

	t.Logf("✅ Time lock extended successfully")
}

func TestTrustlessLockVesting(t *testing.T) {
	state := NewStateDB()

	var poolAddr, token0, token1, recipient [20]byte
	copy(poolAddr[:], []byte("pool-vesting-123456789"))
	copy(token0[:], []byte("token0-vesting-123456"))
	copy(token1[:], []byte("token1-vesting-123456"))
	copy(recipient[:], []byte("recipient-vesting-12345"))

	amount := new(big.Int).Mul(big.NewInt(500), big.NewInt(1e18))

	// Create vesting lock
	input := make([]byte, 4+20+20+20+32+8+8+8+20)
	input[0], input[1], input[2], input[3] = 0xB2, 0xC3, 0xD4, 0xE5
	copy(input[4:24], poolAddr[:])
	copy(input[24:44], token0[:])
	copy(input[44:64], token1[:])
	amount.FillBytes(input[64:96])
	// vestingStart = 1000
	big.NewInt(1000).FillBytes(input[96:128])
	copy(input[96:104], []byte{0, 0, 0, 0, 0, 0, 0x03, 0xE8})
	// vestingEnd = 100000
	copy(input[104:112], []byte{0, 0, 0, 0, 0, 0x01, 0x86, 0xA0})
	// vestingCliff = 5000
	copy(input[112:120], []byte{0, 0, 0, 0, 0, 0, 0x13, 0x88})
	copy(input[120:140], recipient[:])

	out, err := trustlessLockPrecompile(input, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("CreateVestingLock failed: %v", err)
	}

	if len(out) != 32 {
		t.Fatalf("Expected 32 byte lockID, got %d", len(out))
	}

	// Test releasable at cliff
	releasableInput := append([]byte{0xE5, 0xF6, 0xA7, 0xB8}, out...)
	releasable, _ := trustlessLockPrecompile(releasableInput, "0xUser", state, 5000)
	releasableAmount := readBigInt(readSlot(releasable, 0))
	if releasableAmount.Sign() == 0 {
		t.Fatal("Expected >0 releasable at cliff")
	}

	// Test releasable after end
	releasable2, _ := trustlessLockPrecompile(releasableInput, "0xUser", state, 200000)
	releasableAmount2 := readBigInt(readSlot(releasable2, 0))
	if releasableAmount2.Sign() == 0 {
		t.Fatal("Expected >0 releasable after vesting end")
	}

	t.Logf("✅ Vesting lock: releasable at cliff and after end")
}

func TestTrustlessLockMinPeriod(t *testing.T) {
	state := NewStateDB()

	var poolAddr, token0, token1, recipient [20]byte
	copy(poolAddr[:], []byte("pool-short-12345678901"))
	copy(token0[:], []byte("token0-short-12345678"))
	copy(token1[:], []byte("token1-short-12345678"))
	copy(recipient[:], []byte("recipient-short-123456"))

	amount := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	shortPeriod := new(big.Int).SetUint64(100) // way below minimum

	input := make([]byte, 4+20+20+20+32+32+20)
	input[0], input[1], input[2], input[3] = 0xA1, 0xB2, 0xC3, 0xD4
	copy(input[4:24], poolAddr[:])
	copy(input[24:44], token0[:])
	copy(input[44:64], token1[:])
	amount.FillBytes(input[64:96])
	shortPeriod.FillBytes(input[96:128])
	copy(input[128:148], recipient[:])

	_, err := trustlessLockPrecompile(input, "0xUser", state, 1000)
	if err == nil {
		t.Fatal("Expected error for lock period below minimum")
	}

	t.Logf("✅ Minimum lock period enforced: %v", err)
}

func TestTrustlessLockRelease(t *testing.T) {
	state := NewStateDB()

	var poolAddr, token0, token1, recipient [20]byte
	copy(poolAddr[:], []byte("pool-release-123456789"))
	copy(token0[:], []byte("token0-release-123456"))
	copy(token1[:], []byte("token1-release-123456"))
	copy(recipient[:], []byte("recipient-release-12345"))

	amount := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	lockPeriod := new(big.Int).SetUint64(3000000) // valid period

	input := make([]byte, 4+20+20+20+32+32+20)
	input[0], input[1], input[2], input[3] = 0xA1, 0xB2, 0xC3, 0xD4
	offset := 4
	copy(input[offset:offset+20], poolAddr[:]); offset += 20
	copy(input[offset:offset+20], token0[:]); offset += 20
	copy(input[offset:offset+20], token1[:]); offset += 20
	amount.FillBytes(input[offset:offset+32]); offset += 32
	lockPeriod.FillBytes(input[offset:offset+32]); offset += 32
	copy(input[offset:offset+20], recipient[:])

	out, err := trustlessLockPrecompile(input, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Release after unlock period (block 4000000 > 1000+3000000)
	releaseInput := append([]byte{0xF6, 0xA7, 0xB8, 0xC9}, out...)
	_, err = trustlessLockPrecompile(releaseInput, "0xUser", state, 4000000)
	if err != nil {
		t.Fatalf("Release should work after unlock: %v", err)
	}

	t.Logf("✅ Lock created, released after unlock period")
}

func TestTrustlessLockIDUnique(t *testing.T) {
	state := NewStateDB()

	// Create two locks with same params at different blocks
	var poolAddr, token0, token1, recipient [20]byte
	copy(poolAddr[:], []byte("pool-unique-1234567890"))
	copy(token0[:], []byte("token0-unique-1234567"))
	copy(token1[:], []byte("token1-unique-1234567"))
	copy(recipient[:], []byte("recipient-unique-12345"))

	amount := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	lockPeriod := new(big.Int).SetUint64(3000000)

	makeInput := func(blockNum uint64) []byte {
		input := make([]byte, 4+20+20+20+32+32+20)
		input[0], input[1], input[2], input[3] = 0xA1, 0xB2, 0xC3, 0xD4
		offset := 4
		copy(input[offset:offset+20], poolAddr[:]); offset += 20
		copy(input[offset:offset+20], token0[:]); offset += 20
		copy(input[offset:offset+20], token1[:]); offset += 20
		amount.FillBytes(input[offset:offset+32]); offset += 32
		lockPeriod.FillBytes(input[offset:offset+32]); offset += 32
		copy(input[offset:offset+20], recipient[:])
		_ = blockNum // lockID includes blockNum
		return input
	}

	out1, _ := trustlessLockPrecompile(makeInput(1000), "0xUser", state, 1000)
	out2, _ := trustlessLockPrecompile(makeInput(2000), "0xUser", state, 2000)

	if bytes.Equal(out1, out2) {
		t.Fatal("Lock IDs should be unique for different blocks")
	}

	t.Logf("✅ Lock IDs are unique: lock1=%x... lock2=%x...", out1[:4], out2[:4])
}

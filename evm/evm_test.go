package evm

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func TestSimpleStorageContract(t *testing.T) {
	code, _ := hex.DecodeString("60003560005560005460005260206000F3")

	state := NewStateDB()
	evm := NewEVM(state, ConsensusLane, 1, 1000, 10008, 100000, "")
	deployer := state.GetOrCreateAccount("deployer")
	deployer.Balance.SetUint64(1_000_000)
	deployer.DoxDevLevel = 3

	addr, err := evm.DeployContractFromCode("deployer", code, ClassA)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}

	calldata := make([]byte, 32)
	calldata[31] = 42
	state.GetOrCreateAccount("user1").Balance.SetUint64(1_000_000)
	state.GetOrCreateAccount("user1").DoxDevLevel = 3
	ctx := &CallContext{Caller: "user1", Address: addr, Value: big.NewInt(0), GasLimit: 100000, Calldata: calldata}
	result := evm.Execute(ctx)
	if result.Error != nil {
		t.Fatalf("store failed: %v", result.Error)
	}

	var key [32]byte
	contractAcc := state.GetAccount(addr)
	valBytes := contractAcc.Storage[key]
	storedVal := new(big.Int).SetBytes(valBytes[:])
	if storedVal.Uint64() != 42 {
		t.Fatalf("expected 42 in storage, got %d", storedVal.Uint64())
	}
}

func TestCounter(t *testing.T) {
	code, _ := hex.DecodeString("60003560005560206000F3")

	state := NewStateDB()
	evm := NewEVM(state, ConsensusLane, 1, 1000, 10008, 100000, "")
	deployer := state.GetOrCreateAccount("deployer")
	deployer.Balance.SetUint64(1_000_000)
	deployer.DoxDevLevel = 3

	addr, err := evm.DeployContractFromCode("deployer", code, ClassA)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}

	calldata := make([]byte, 32)
	calldata[31] = 1
	state.GetOrCreateAccount("user1").Balance.SetUint64(1_000_000)
	state.GetOrCreateAccount("user1").DoxDevLevel = 3
	ctx := &CallContext{Caller: "user1", Address: addr, Value: big.NewInt(0), GasLimit: 100000, Calldata: calldata}
	evm.Execute(ctx)

	ctx2 := &CallContext{Caller: "user1", Address: addr, Value: big.NewInt(0), GasLimit: 100000, Calldata: []byte{}}
	result := evm.Execute(ctx2)
	val := big.NewInt(0).SetBytes(result.ReturnData)
	t.Logf("Counter after increment: %d", val.Uint64())
}

func TestWayChainOpcodes(t *testing.T) {
	if DOXDEVLEVEL != 0xC1 {
		t.Fatalf("expected DOXDEVLEVEL opcode 0xC1, got 0x%X", byte(DOXDEVLEVEL))
	}
	if LANETYPE != 0xC2 {
		t.Fatalf("expected LANETYPE opcode 0xC2, got 0x%X", byte(LANETYPE))
	}

	state := NewStateDB()
	state.GetOrCreateAccount("testuser").DoxDevLevel = 2
	state.GetOrCreateAccount("testuser").Balance.SetUint64(1_000_000)
	state.GetOrCreateAccount("testuser2").Balance.SetUint64(1_000_000)

	if err := CanDeployContract(2); err != nil {
		t.Fatalf("L2 should pass deploy gate: %v", err)
	}
	if err := CanDeployContract(0); err == nil {
		t.Fatal("L0 should fail deploy gate")
	}
	if state.GetAccount("testuser").DoxDevLevel != 2 {
		t.Fatal("DoxDev level should remain 2")
	}
	if state.GetAccount("testuser2").Balance.Uint64() != 1_000_000 {
		t.Fatal("lane account balance should remain funded")
	}
}

func TestArithmetic(t *testing.T) {
	code := []byte{byte(PUSH1), 3, byte(PUSH1), 4, byte(PUSH1), 2, byte(MUL), byte(ADD), byte(PUSH1), 0, byte(MSTORE), byte(PUSH1), 32, byte(PUSH1), 0, byte(RETURN)}

	state := NewStateDB()
	evm := NewEVM(state, ConsensusLane, 1, 1000, 10008, 100000, "")
	state.CreateAccount("math", code)
	state.GetAccount("math").Balance.SetUint64(1_000_000)
	state.GetOrCreateAccount("caller").Balance.SetUint64(1_000_000)
	ctx := &CallContext{Caller: "caller", Address: "math", Value: big.NewInt(0), GasLimit: 100000}
	result := evm.Execute(ctx)
	if result.Error != nil {
		t.Fatalf("math failed: %v", result.Error)
	}

	expected := big.NewInt(11)
	actual := big.NewInt(0).SetBytes(result.ReturnData)
	if actual.Cmp(expected) != 0 {
		t.Fatalf("expected 11, got %d", actual)
	}
}

func TestStateDBClone(t *testing.T) {
	state := NewStateDB()
	acc := state.GetOrCreateAccount("alice")
	acc.Balance.SetUint64(1000)
	acc.DoxDevLevel = 2

	clone := state.Clone()
	acc2 := clone.GetAccount("alice")
	if acc2 == nil {
		t.Fatal("clone should have alice")
	}
	if acc2.Balance.Uint64() != 1000 {
		t.Fatalf("expected 1000, got %d", acc2.Balance.Uint64())
	}
	if acc2.DoxDevLevel != 2 {
		t.Fatalf("expected level 2, got %d", acc2.DoxDevLevel)
	}

	acc.Balance.SetUint64(999)
	if clone.GetAccount("alice").Balance.Uint64() != 1000 {
		t.Fatal("clone should be isolated from mutation")
	}
}

func TestContractClassEnforcement(t *testing.T) {
	tests := []struct {
		level uint8
		class ContractClass
		valid bool
	}{
		{0, ClassA, true},
		{0, ClassB, false},
		{2, ClassB, true},
		{2, ClassC, false},
		{3, ClassC, true},
		{0, ClassD, false},
	}

	for _, tt := range tests {
		err := EnforceContractClass(tt.level, tt.class)
		valid := err == nil
		if valid != tt.valid {
			t.Errorf("level=%d, class=%s: expected valid=%v, got %v (%v)", tt.level, tt.class, tt.valid, valid, err)
		}
	}
}

func TestFullContractLifecycle(t *testing.T) {
	code, _ := hex.DecodeString("60003560005560005460005260206000F3")

	state := NewStateDB()
	evm := NewEVM(state, ConsensusLane, 1, 1000, 10008, 100000, "")
	state.GetOrCreateAccount("alice").Balance.SetUint64(1_000_000)
	state.GetOrCreateAccount("alice").DoxDevLevel = 3

	addr, err := evm.DeployContractFromCode("alice", code, ClassA)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	calldata := make([]byte, 32)
	calldata[29] = 3
	calldata[30] = 0x09
	calldata[31] = 0x09

	ctx := &CallContext{Caller: "alice", Address: addr, Value: big.NewInt(0), GasLimit: 100000, Calldata: calldata}
	result := evm.Execute(ctx)
	if result.Error != nil {
		t.Fatalf("store: %v", result.Error)
	}
	var key [32]byte
	contractAcc := state.GetAccount(addr)
	valBytes := contractAcc.Storage[key]
	storedVal := new(big.Int).SetBytes(valBytes[:])
	fmt.Printf("Stored value: %d\n", storedVal.Uint64())
}

func TestDeployGateEnforcement(t *testing.T) {
	tests := []struct {
		level uint8
		valid bool
	}{
		{0, false},
		{1, false},
		{2, true},
		{3, true},
	}

	for _, tt := range tests {
		err := CanDeployContract(tt.level)
		valid := err == nil
		if valid != tt.valid {
			t.Errorf("level=%d: expected valid=%v, got %v (%v)", tt.level, tt.valid, valid, err)
		}
	}
}

func TestCREATEEnforcesDeployGate(t *testing.T) {
	state := NewStateDB()
	evm := NewEVM(state, ConsensusLane, 1, 1000, 10008, 100000, "")

	caller := "attacker"
	acc := state.GetOrCreateAccount(caller)
	acc.DoxDevLevel = 0
	acc.Balance.SetUint64(1_000_000)

	code := []byte{0x60, 0x42, 0x60, 0x00, 0x55, 0x60, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3}
	_, err := evm.DeployContractFromCode(caller, code, ClassB)
	if err == nil {
		t.Error("L0 deployer should be rejected for ClassB deployment")
	}

	verifiedCaller := "dev"
	devAcc := state.GetOrCreateAccount(verifiedCaller)
	devAcc.DoxDevLevel = 2
	devAcc.Balance.SetUint64(1_000_000)

	if _, err := evm.DeployContractFromCode(verifiedCaller, code, ClassB); err != nil {
		t.Fatalf("L2 deployer should deploy ClassB: %v", err)
	}
	devAcc.DoxDevLevel = 3
	if _, err := evm.DeployContractFromCode(verifiedCaller, code, ClassA); err != nil {
		t.Fatalf("L3 should deploy ClassA: %v", err)
	}
}

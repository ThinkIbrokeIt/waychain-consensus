// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/sha3"
)

// EVM is the WayChain execution layer
type EVM struct {
	State     *StateDB
	Lane      LaneType
	BlockNum  uint64
	Timestamp uint64
	ChainID   uint64
	GasLimit  uint64

	doxDevOracle string
}

// ExecutionResult contains the result of EVM execution
type ExecutionResult struct {
	ReturnData []byte
	GasUsed    uint64
	Logs       []*LogEntry
	Error      error
}

// CallContext defines the context for a contract call
type CallContext struct {
	Caller   string
	Address  string
	Value    *big.Int
	GasLimit uint64
	Calldata []byte
	ReadOnly bool
}

// Stack is the EVM data stack
type Stack struct {
	data []*big.Int
}

func NewStack() *Stack { return &Stack{data: make([]*big.Int, 0, 1024)} }
func (s *Stack) Push(v *big.Int)  { s.data = append(s.data, v) }
func (s *Stack) Pop() *big.Int    { if len(s.data) == 0 { return big.NewInt(0) }; v := s.data[len(s.data)-1]; s.data = s.data[:len(s.data)-1]; return v }
func (s *Stack) Peek() *big.Int   { if len(s.data) == 0 { return big.NewInt(0) }; return s.data[len(s.data)-1] }
func (s *Stack) Swap(n int)       { if len(s.data) >= n+1 { s.data[len(s.data)-1], s.data[len(s.data)-1-n] = s.data[len(s.data)-1-n], s.data[len(s.data)-1] } }
func (s *Stack) Dup(n int)        { if len(s.data) >= n { s.Push(new(big.Int).Set(s.data[len(s.data)-n])) } }
func (s *Stack) Len() int         { return len(s.data) }

// Memory is the EVM memory space
type Memory struct{ data []byte }
func NewMemory() *Memory           { return &Memory{data: make([]byte, 0, 4096)} }
func (m *Memory) Resize(size uint64) {
	if uint64(len(m.data)) < size { newData := make([]byte, size); copy(newData, m.data); m.data = newData }
}
func (m *Memory) Set(offset uint64, value []byte) { m.Resize(offset+uint64(len(value))); copy(m.data[offset:], value) }
func (m *Memory) Get(offset, size uint64) []byte  { m.Resize(offset+size); r := make([]byte, size); copy(r, m.data[offset:offset+size]); return r }
func (m *Memory) Len() uint64                     { return uint64(len(m.data)) }

// NewEVM creates a new EVM instance
func NewEVM(state *StateDB, lane LaneType, blockNum, timestamp, chainID, gasLimit uint64, doxDevAddr string) *EVM {
	return &EVM{State: state, Lane: lane, BlockNum: blockNum, Timestamp: timestamp, ChainID: chainID, GasLimit: gasLimit, doxDevOracle: doxDevAddr}
}

// ── Execute dispatcher ───────────────────────────────────

// Execute runs a contract call through the production EVM (revm).
func (evm *EVM) Execute(ctx *CallContext) *ExecutionResult {
	// Precompile routing (0x0C-0x26)
	if ctx.Address != "" {
		addrStr := strings.TrimPrefix(strings.ToLower(ctx.Address), "0x")
		// Precompiles are stored at the canonical zero-padded form
		// "0000...0013" (PrecompileAddrHex -> 38 chars: 18 zero bytes + 1 byte).
		// Decode the full address; it is a precompile iff every byte except
		// the last is zero AND the last byte is a registered precompile.
		// This matches 42-char (40 zeros+byte), 40-char, 2-char, and bare
		// 1-byte forms without false-positives on normal accounts.
		if decoded, err := hex.DecodeString(addrStr); err == nil && len(decoded) >= 1 {
			last := decoded[len(decoded)-1]
			isPrecompileForm := true
			for _, x := range decoded[:len(decoded)-1] {
				if x != 0 {
					isPrecompileForm = false
					break
				}
			}
			if isPrecompileForm && IsPrecompile(last) {
				result, _, err := ExecutePrecompile(last, ctx.Calldata, ctx.Caller, evm.State, evm.BlockNum)
				if err != nil {
					return &ExecutionResult{Error: err}
				}
				return &ExecutionResult{ReturnData: result, GasUsed: PrecompileGas(last)}
			}
		}
	}

	// Contract creation (tx.To == "")
	if ctx.Address == "" {
		return evm.deployContractWithRevm(ctx)
	}

	// Get target code
	account := evm.State.GetOrCreateAccount(ctx.Address)
	code := account.Code

	// EOA transfer
	if len(code) == 0 && len(ctx.Calldata) == 0 {
		if ctx.Caller != ctx.Address && ctx.Value.Sign() > 0 {
			to := evm.State.GetOrCreateAccount(ctx.Address)
			to.Balance.Add(to.Balance, ctx.Value)
		}
		return &ExecutionResult{GasUsed: 21000}
	}

	// Contract call: route through revm
	if len(code) > 0 {
		return evm.executeWithRevm(ctx, code)
	}

	// Fallback: no code at target for a call with calldata
	if len(ctx.Calldata) > 0 {
		return evm.executeWithRevm(ctx, ctx.Calldata)
	}

	return &ExecutionResult{Error: fmt.Errorf("no code at address")}
}

// ── revm-backed contract creation ────────────────────────

// deployContractWithRevm executes contract init code through revm.
func (evm *EVM) deployContractWithRevm(ctx *CallContext) *ExecutionResult {
	// Use revm to execute init code; it handles address derivation and code storage.
	return evm.executeWithRevm(ctx, ctx.Calldata)
}

// ── DeployContractFromCode (template deploy) ─────────────

// DeployContractFromCode creates and deposits a contract from bytecode.
// Used for deploying contracts from the template registry.
func (evm *EVM) DeployContractFromCode(caller string, code []byte, class ContractClass) (string, error) {
	account := evm.State.GetOrCreateAccount(caller)
	if err := EnforceContractClass(account.DoxDevLevel, class); err != nil {
		return "", err
	}

	hash := sha256.Sum256([]byte(fmt.Sprintf("template:%s:%d", caller, account.Nonce)))
	addr := fmt.Sprintf("%x", hash[:20])
	account.Nonce++

	contract := evm.State.CreateAccount(addr, code)
	contract.DoxDevLevel = account.DoxDevLevel
	contract.ContractClass = class

	return addr, nil
}

// Keep these import-referenced symbols available (used in old interpreter — may be needed by precompiles)
var _ = hex.EncodeToString
var _ = sha3.NewLegacyKeccak256
var _ = NewStack
var _ = NewMemory
var _ Opcode = 0

// PrecompileGas returns the fixed gas cost for a precompile.
func PrecompileGas(addr byte) uint64 {
	if pc, ok := PrecompilesTable[addr]; ok {
		return pc.Gas
	}
	return 0
}
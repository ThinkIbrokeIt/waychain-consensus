package evm

// #cgo LDFLAGS: -L${SRCDIR}/../revm-ffi/target/release -lrevm_ffi -ldl -lm
// #include <stdlib.h>
//
// extern char* revm_execute(char* input);
// extern void revm_free_string(char* ptr);
import "C"

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"unsafe"
)

// revmExecuteRequest is the JSON payload sent to revm
type revmExecuteRequest struct {
	Caller    string                       `json:"caller"`
	Address   string                       `json:"address"`
	Value     string                       `json:"value,omitempty"`
	GasLimit  uint64                       `json:"gas_limit"`
	Calldata  string                       `json:"calldata"`
	Code      string                       `json:"code"`
	IsCreate  bool                         `json:"is_create"`
	State     map[string]revmAccountState  `json:"state,omitempty"`
}

type revmAccountState struct {
	Nonce   uint64            `json:"nonce"`
	Balance string            `json:"balance"`
	Code    string            `json:"code,omitempty"`
	Storage map[string]string `json:"storage,omitempty"`
}

// revmExecuteResponse is the JSON result from revm
type revmExecuteResponse struct {
	Success     bool                            `json:"success"`
	ReturnData  string                          `json:"return_data"`
	GasUsed     uint64                          `json:"gas_used"`
	Error       string                          `json:"error,omitempty"`
	State       map[string]revmAccountStateOut  `json:"state,omitempty"`
	NewContract string                          `json:"new_contract,omitempty"`
}

type revmAccountStateOut struct {
	Nonce   uint64            `json:"nonce"`
	Balance string            `json:"balance"`
	Code    string            `json:"code,omitempty"`
	Storage map[string]string `json:"storage,omitempty"`
}

// executeWithRevm runs EVM code through the revm shared library.
// Returns the execution result. On failure, returns the original result unmodified
// with an error flag.
func (evm *EVM) executeWithRevm(ctx *CallContext, code []byte) *ExecutionResult {
	// ── Build state snapshot ──
	state := make(map[string]revmAccountState)

	// Always include the caller
	caller := evm.State.GetOrCreateAccount(ctx.Caller)
	state[toEvmAddr(ctx.Caller)] = revmAccountState{
		Nonce:   caller.Nonce,
		Balance: fmt.Sprintf("0x%x", caller.Balance),
	}

	// If this is a call to an existing contract, include its state
	if ctx.Address != "" {
		target := evm.State.GetOrCreateAccount(ctx.Address)
		acctState := revmAccountState{
			Nonce:   target.Nonce,
			Balance: fmt.Sprintf("0x%x", target.Balance),
		}
		if len(target.Code) > 0 {
			acctState.Code = hex.EncodeToString(target.Code)
		}
		if len(target.Storage) > 0 {
			acctState.Storage = make(map[string]string)
			for k, v := range target.Storage {
				acctState.Storage[pad64hex(k[:])] = pad64hex(v[:])
			}
		}
		state[toEvmAddr(ctx.Address)] = acctState
	}

	// ── Build request ──
	req := revmExecuteRequest{
		Caller:   toEvmAddr(ctx.Caller),
		Address:  toEvmAddr(ctx.Address),
		GasLimit: ctx.GasLimit,
		Calldata: hex.EncodeToString(ctx.Calldata),
		Code:     hex.EncodeToString(code),
		IsCreate: ctx.Address == "",
		State:    state,
	}

	if ctx.Value != nil && ctx.Value.Sign() > 0 {
		req.Value = fmt.Sprintf("0x%x", ctx.Value)
	}

	reqJSON, err := json.Marshal(req)
	if err != nil {
		return &ExecutionResult{
			ReturnData: nil,
			GasUsed:    0,
			Error:      fmt.Errorf("revm: marshal request: %w", err),
		}
	}

	// ── Call revm FFI ──
	cInput := C.CString(string(reqJSON))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.revm_execute(cInput)
	if cResult == nil {
		return &ExecutionResult{
			ReturnData: nil,
			GasUsed:    0,
			Error:      fmt.Errorf("revm: null result"),
		}
	}
	defer C.revm_free_string(cResult)

	resultStr := C.GoString(cResult)
	var resp revmExecuteResponse
	if err := json.Unmarshal([]byte(resultStr), &resp); err != nil {
		return &ExecutionResult{
			ReturnData: nil,
			GasUsed:    0,
			Error:      fmt.Errorf("revm: unmarshal result: %w", err),
		}
	}

	// ── Handle error ──
	if !resp.Success {
		errMsg := resp.Error
		if errMsg == "" {
			errMsg = "unknown revm error"
		}
		return &ExecutionResult{
			ReturnData: decodeHexBytes(resp.ReturnData),
			GasUsed:    resp.GasUsed,
			Error:      fmt.Errorf("revm: %s", errMsg),
		}
	}

	// ── Apply state changes ──
	if resp.State != nil {
		for addrStr, outState := range resp.State {
			addr := unpadHex(addrStr)
			acct := evm.State.GetOrCreateAccount(addr)
			// Don't apply nonce for the caller — ProduceBlock handles it
			if addr != ctx.Caller {
				acct.Nonce = outState.Nonce
			}
			if outState.Balance != "" {
				acct.Balance = parseHexBig(outState.Balance)
			}
			if outState.Code != "" {
				newCode := decodeHexBytes(outState.Code)
				acct.Code = newCode
				acct.CodeHash = sha256.Sum256(newCode)
			}
			if outState.Storage != nil {
				for k, v := range outState.Storage {
					var key [32]byte
					var val [32]byte
					copy(key[:], decodeHexBytes(k))
					copy(val[:], decodeHexBytes(v))
					acct.Storage[key] = val
				}
			}
		}
	}

	// ── Build result ──
	result := &ExecutionResult{
		ReturnData: decodeHexBytes(resp.ReturnData),
		GasUsed:    resp.GasUsed,
		Error:      nil,
	}

	if resp.NewContract != "" {
		contractAddr := unpadHex(resp.NewContract)
		// Store runtime code (ReturnData is the runtime code after init)
		contract := evm.State.GetOrCreateAccount(contractAddr)
		if len(result.ReturnData) > 0 {
			contract.Code = result.ReturnData
			contract.CodeHash = sha256.Sum256(result.ReturnData)
		}
		// Tag the result so caller knows this was a deploy
		result.Logs = append(result.Logs, &LogEntry{
			Address: contractAddr,
			Topics:  nil,
			Data:    []byte(contractAddr),
		})
	}

	return result
}

// ── Helpers ───────────────────────────────────────────────

// toEvmAddr converts a WayChain address to a 20-byte EVM address.
// If already 20 bytes (40 hex), passes through. If 32 bytes (64 hex), hashes.
func toEvmAddr(addr string) string {
	addr = strings.TrimPrefix(addr, "0x")
	raw := decodeHexBytes(addr)
	if len(raw) == 20 {
		return "0x" + addr
	}
	hash := sha256.Sum256(raw)
	return "0x" + hex.EncodeToString(hash[:20])
}

func unpadHex(s string) string {
	s = strings.TrimPrefix(s, "0x")
	// Strip leading zeros to get canonical 40-char internal format
	for len(s) > 1 && s[0] == '0' {
		s = s[1:]
	}
	return s
}

func pad64hex(seed []byte) string {
	// Already 32 bytes from storage key — just hex encode
	return "0x" + hex.EncodeToString(seed)
}

func decodeHexBytes(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	b, _ := hex.DecodeString(s)
	return b
}

func parseHexBig(s string) *big.Int {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return new(big.Int)
	}
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return new(big.Int)
	}
	return n
}
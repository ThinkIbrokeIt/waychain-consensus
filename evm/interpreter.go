package evm

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// EVM is the WayChain execution layer
type EVM struct {
	State     *StateDB
	Lane      LaneType
	BlockNum  uint64
	Timestamp uint64
	ChainID   uint64
	GasLimit  uint64

	doxDevOracle string // Address of Dox_Dev badge contract (for LEVEL/VERIFY ops)
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
	Caller    string
	Address   string
	Value     *big.Int
	GasLimit  uint64
	Calldata  []byte
	ReadOnly  bool // staticcall
}

// Stack is the EVM data stack
type Stack struct {
	data []*big.Int
}

func NewStack() *Stack {
	return &Stack{data: make([]*big.Int, 0, 1024)}
}

func (s *Stack) Push(v *big.Int) {
	s.data = append(s.data, v)
}

func (s *Stack) Pop() *big.Int {
	if len(s.data) == 0 {
		return big.NewInt(0)
	}
	v := s.data[len(s.data)-1]
	s.data = s.data[:len(s.data)-1]
	return v
}

func (s *Stack) Peek() *big.Int {
	if len(s.data) == 0 {
		return big.NewInt(0)
	}
	return s.data[len(s.data)-1]
}

func (s *Stack) Swap(n int) {
	if len(s.data) < n+1 {
		return
	}
	s.data[len(s.data)-1], s.data[len(s.data)-1-n] = s.data[len(s.data)-1-n], s.data[len(s.data)-1]
}

func (s *Stack) Dup(n int) {
	if len(s.data) < n {
		return
	}
	s.Push(new(big.Int).Set(s.data[len(s.data)-n]))
}

func (s *Stack) Len() int {
	return len(s.data)
}

// Memory is the EVM memory space
type Memory struct {
	data []byte
}

func NewMemory() *Memory {
	return &Memory{data: make([]byte, 0, 4096)}
}

func (m *Memory) Resize(size uint64) {
	if uint64(len(m.data)) < size {
		newData := make([]byte, size)
		copy(newData, m.data)
		m.data = newData
	}
}

func (m *Memory) Set(offset uint64, value []byte) {
	m.Resize(offset + uint64(len(value)))
	copy(m.data[offset:], value)
}

func (m *Memory) Get(offset uint64, size uint64) []byte {
	m.Resize(offset + size)
	result := make([]byte, size)
	copy(result, m.data[offset:offset+size])
	return result
}

func (m *Memory) Len() uint64 {
	return uint64(len(m.data))
}

// NewEVM creates a new EVM instance
func NewEVM(state *StateDB, lane LaneType, blockNum uint64, timestamp uint64, chainID uint64, gasLimit uint64, doxDevAddr string) *EVM {
	return &EVM{
		State:        state,
		Lane:         lane,
		BlockNum:     blockNum,
		Timestamp:    timestamp,
		ChainID:      chainID,
		GasLimit:     gasLimit,
		doxDevOracle: doxDevAddr,
	}
}

// Execute runs a contract call
func (evm *EVM) Execute(ctx *CallContext) *ExecutionResult {
	stack := NewStack()
	mem := NewMemory()
	var gasUsed uint64
	var returnData []byte
	var pc uint64 // program counter

	// Get contract code
	account := evm.State.GetOrCreateAccount(ctx.Address)
	code := account.Code
	if len(code) == 0 && len(ctx.Calldata) == 0 {
		// EOA call — just transfer value, no code execution
		if ctx.Caller != ctx.Address && ctx.Value.Sign() > 0 {
			to := evm.State.GetOrCreateAccount(ctx.Address)
			to.Balance.Add(to.Balance, ctx.Value)
		}
		return &ExecutionResult{GasUsed: 21000}
	}

	if len(code) == 0 {
		return &ExecutionResult{GasUsed: 0, Error: fmt.Errorf("no code at address")}
	}

	// Execute bytecode
	for pc < uint64(len(code)) && gasUsed < ctx.GasLimit {
		op := Opcode(code[pc])
		pc++

		info, known := OpcodeTable[op]
		if !known || info.Name == "" {
			// Invalid opcode
			evm.State.Refunds++
			return &ExecutionResult{
				GasUsed: gasUsed,
				Error:   fmt.Errorf("invalid opcode 0x%02X at pc %d", byte(op), pc-1),
				Logs:    evm.State.Logs,
			}
		}

		gasUsed += info.Gas
		if gasUsed > ctx.GasLimit {
			return &ExecutionResult{
				GasUsed: gasUsed,
				Error:   fmt.Errorf("out of gas"),
			}
		}

		// Handle opcode
		var err error

		switch {
		case op == STOP:
			pc = uint64(len(code))
			returnData = nil

		case IsPushOp(op):
			n := PushSize(op)
			if int(pc)+n > len(code) {
				return &ExecutionResult{GasUsed: gasUsed, Error: fmt.Errorf("push beyond code")}
			}
			val := new(big.Int).SetBytes(code[pc : pc+uint64(n)])
			pc += uint64(n)
			stack.Push(val)

		case IsDupOp(op):
			stack.Dup(DupIndex(op))

		case IsSwapOp(op):
			stack.Swap(SwapIndex(op))

		case op == POP:
			stack.Pop()

		case op == ADD:
			a, b := stack.Pop(), stack.Pop()
			stack.Push(new(big.Int).Add(a, b))

		case op == SUB:
			a, b := stack.Pop(), stack.Pop()
			stack.Push(new(big.Int).Sub(a, b))

		case op == MUL:
			a, b := stack.Pop(), stack.Pop()
			stack.Push(new(big.Int).Mul(a, b))

		case op == DIV:
			a, b := stack.Pop(), stack.Pop()
			if b.Sign() == 0 {
				stack.Push(big.NewInt(0))
			} else {
				stack.Push(new(big.Int).Div(a, b))
			}

		case op == MOD:
			a, b := stack.Pop(), stack.Pop()
			if b.Sign() == 0 {
				stack.Push(big.NewInt(0))
			} else {
				stack.Push(new(big.Int).Mod(a, b))
			}

		case op == EXP:
			a, b := stack.Pop(), stack.Pop()
			stack.Push(new(big.Int).Exp(a, b, nil))

		case op == LT:
			a, b := stack.Pop(), stack.Pop()
			if a.Cmp(b) < 0 { stack.Push(big.NewInt(1)) } else { stack.Push(big.NewInt(0)) }

		case op == GT:
			a, b := stack.Pop(), stack.Pop()
			if a.Cmp(b) > 0 { stack.Push(big.NewInt(1)) } else { stack.Push(big.NewInt(0)) }

		case op == EQ:
			a, b := stack.Pop(), stack.Pop()
			if a.Cmp(b) == 0 { stack.Push(big.NewInt(1)) } else { stack.Push(big.NewInt(0)) }

		case op == ISZERO:
			a := stack.Pop()
			if a.Sign() == 0 { stack.Push(big.NewInt(1)) } else { stack.Push(big.NewInt(0)) }

		case op == AND:
			a, b := stack.Pop(), stack.Pop()
			stack.Push(new(big.Int).And(a, b))

		case op == OR:
			a, b := stack.Pop(), stack.Pop()
			stack.Push(new(big.Int).Or(a, b))

		case op == XOR:
			a, b := stack.Pop(), stack.Pop()
			stack.Push(new(big.Int).Xor(a, b))

		case op == NOT:
			a := stack.Pop()
			stack.Push(new(big.Int).Not(a))

		case op == ADDRESS:
			buf := make([]byte, 32)
			copy(buf[12:], []byte(ctx.Address))
			stack.Push(new(big.Int).SetBytes(buf))

		case op == CALLER:
			buf := make([]byte, 32)
			copy(buf[12:], []byte(ctx.Caller))
			stack.Push(new(big.Int).SetBytes(buf))

		case op == CALLVALUE:
			stack.Push(new(big.Int).Set(ctx.Value))

		case op == CALLDATALOAD:
			offset := stack.Pop().Uint64()
			data := make([]byte, 32)
			if offset < uint64(len(ctx.Calldata)) {
				end := offset + 32
				if end > uint64(len(ctx.Calldata)) {
					end = uint64(len(ctx.Calldata))
				}
				copy(data, ctx.Calldata[offset:end])
			}
			stack.Push(new(big.Int).SetBytes(data))

		case op == CALLDATASIZE:
			stack.Push(big.NewInt(int64(len(ctx.Calldata))))

		case op == CALLDATACOPY:
			destOff := stack.Pop().Uint64()
			srcOff := stack.Pop().Uint64()
			size := stack.Pop().Uint64()
			data := make([]byte, size)
			if srcOff < uint64(len(ctx.Calldata)) {
				copy(data, ctx.Calldata[srcOff:])
			}
			mem.Set(destOff, data)

		case op == CODESIZE:
			stack.Push(big.NewInt(int64(len(code))))

		case op == GASPRICE:
			stack.Push(big.NewInt(1)) // WayChain base fee equivalent

		case op == TIMESTAMP:
			stack.Push(big.NewInt(int64(evm.Timestamp)))

		case op == NUMBER:
			stack.Push(big.NewInt(int64(evm.BlockNum)))

		case op == CHAINID:
			stack.Push(big.NewInt(int64(evm.ChainID)))

		case op == SELFBALANCE:
			stack.Push(account.Balance)

		case op == MLOAD:
			offset := stack.Pop()
			val := mem.Get(offset.Uint64(), 32)
			stack.Push(new(big.Int).SetBytes(val))

		case op == MSTORE:
			offset := stack.Pop()
			val := stack.Pop()
			b := val.Bytes()
			padded := make([]byte, 32)
			copy(padded[32-len(b):], b)
			mem.Set(offset.Uint64(), padded)

		case op == MSTORE8:
			offset := stack.Pop()
			val := stack.Pop()
			mem.Set(offset.Uint64(), []byte{byte(val.Uint64() & 0xFF)})

		case op == SLOAD:
			key := stack.Pop()
			var k [32]byte
			copy(k[:], key.Bytes())
			val := account.Storage[k]
			stack.Push(new(big.Int).SetBytes(val[:]))

		case op == SSTORE:
			key := stack.Pop()
			val := stack.Pop()
			var k [32]byte
			copy(k[:], key.Bytes())
			var v [32]byte
			b := val.Bytes()
			copy(v[32-len(b):], b)
			account.Storage[k] = v
			gasUsed += 4800 // warm storage cost — simplified

		case op == JUMP:
			target := stack.Pop().Uint64()
			if target >= uint64(len(code)) || code[target] != byte(JUMPDEST) {
				return &ExecutionResult{GasUsed: gasUsed, Error: fmt.Errorf("invalid jump destination")}
			}
			pc = target

		case op == JUMPI:
			target := stack.Pop().Uint64()
			cond := stack.Pop()
			if cond.Sign() != 0 {
				if target >= uint64(len(code)) || code[target] != byte(JUMPDEST) {
					return &ExecutionResult{GasUsed: gasUsed, Error: fmt.Errorf("invalid jump destination")}
				}
				pc = target
			}

		case op == JUMPDEST:
			// No-op marker

		case op == PC:
			stack.Push(big.NewInt(int64(pc - 1)))

		case op == GAS:
			remaining := ctx.GasLimit - gasUsed
			stack.Push(big.NewInt(int64(remaining)))

		case op == MSIZE:
			stack.Push(big.NewInt(int64(mem.Len())))

		case op == RETURN || op == REVERT:
			offset := stack.Pop().Uint64()
			size := stack.Pop().Uint64()
			returnData = mem.Get(offset, size)
			pc = uint64(len(code))
			if op == REVERT {
				err = fmt.Errorf("execution reverted")
			}

		case op == SHA3:
			offset := stack.Pop().Uint64()
			size := stack.Pop().Uint64()
			data := mem.Get(offset, size)
			hash := sha256.Sum256(data)
			stack.Push(new(big.Int).SetBytes(hash[:]))

		case IsLogOp(op):
			nTopics := LogTopicCount(op)
			offset := stack.Pop().Uint64()
			size := stack.Pop().Uint64()
			topics := make([][32]byte, nTopics)
			for i := 0; i < nTopics; i++ {
				topic := stack.Pop()
				var t [32]byte
				copy(t[:], topic.Bytes())
				topics[i] = t
			}
			data := mem.Get(offset, size)
			evm.State.AddLog(ctx.Address, topics, data, evm.BlockNum)

		case op == BALANCE:
			addrBytes := stack.Pop().Bytes()
			addr := fmt.Sprintf("%x", addrBytes)
			acc := evm.State.GetAccount(addr)
			if acc != nil {
				stack.Push(acc.Balance)
			} else {
				stack.Push(big.NewInt(0))
			}

		case op == EXTCODESIZE:
			addrBytes := stack.Pop().Bytes()
			addr := fmt.Sprintf("%x", addrBytes)
			acc := evm.State.GetAccount(addr)
			if acc != nil {
				stack.Push(big.NewInt(int64(len(acc.Code))))
			} else {
				stack.Push(big.NewInt(0))
			}

		case op == CALL:
			_gas := stack.Pop()
			addrVal := stack.Pop()
			value := stack.Pop()
			argsOff := stack.Pop().Uint64()
			argsSize := stack.Pop().Uint64()
			retOff := stack.Pop().Uint64()
			_ = stack.Pop().Uint64() // retSize (unused in simplified CALL)

			// Check if target is a precompile (0x0C-0x1F)
			addrBytes := addrVal.Bytes()
			if len(addrBytes) <= 1 && len(addrBytes) > 0 {
				addr := addrBytes[0]
				if IsPrecompile(addr) {
					calldata := mem.Get(argsOff, argsSize)
					result, _, err := ExecutePrecompile(addr, calldata, ctx.Caller, evm.State, evm.BlockNum)
					_ = err
					mem.Set(retOff, result)
					stack.Push(big.NewInt(1)) // success
					break
				}
			}

			targetAddr := fmt.Sprintf("%x", addrBytes)
			calldata := mem.Get(argsOff, argsSize)
			subCtx := &CallContext{
				Caller:   ctx.Address,
				Address:  targetAddr,
				Value:    value,
				GasLimit: _gas.Uint64(),
				Calldata: calldata,
			}
			result := evm.Execute(subCtx)
			mem.Set(retOff, result.ReturnData)
			if result.Error != nil {
				stack.Push(big.NewInt(0)) // failure
			} else {
				stack.Push(big.NewInt(1)) // success
			}

		case op == STATICCALL:
			// Same as CALL but value is always 0 (no state changes)
			_gas := stack.Pop()
			addrVal := stack.Pop()
			argsOff := stack.Pop().Uint64()
			argsSize := stack.Pop().Uint64()
			retOff := stack.Pop().Uint64()
			_ = stack.Pop().Uint64() // retSize (unused)

			// Check if target is a precompile (0x0C-0x1F)
			addrBytes := addrVal.Bytes()
			if len(addrBytes) <= 1 && len(addrBytes) > 0 {
				addr := addrBytes[0]
				if IsPrecompile(addr) {
					calldata := mem.Get(argsOff, argsSize)
					result, _, err := ExecutePrecompile(addr, calldata, ctx.Caller, evm.State, evm.BlockNum)
					_ = err
					mem.Set(retOff, result)
					stack.Push(big.NewInt(1)) // success
					break
				}
			}

			targetAddr := fmt.Sprintf("%x", addrBytes)
			calldata := mem.Get(argsOff, argsSize)
			subCtx := &CallContext{
				Caller:    ctx.Address,
				Address:   targetAddr,
				Value:     big.NewInt(0),
				GasLimit:  _gas.Uint64(),
				Calldata:  calldata,
				ReadOnly:  true,
			}
			result := evm.Execute(subCtx)
			mem.Set(retOff, result.ReturnData)
			if result.Error != nil {
				stack.Push(big.NewInt(0))
			} else {
				stack.Push(big.NewInt(1))
			}

		case op == CREATE:
			_ = stack.Pop() // value (unused — balance transfer not fully implemented)
			offset := stack.Pop().Uint64()
			size := stack.Pop().Uint64()
			initCode := mem.Get(offset, size)

			// Derive new address (simplified)
			hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", ctx.Address, account.Nonce)))
			newAddr := fmt.Sprintf("%x", hash[:20])
			account.Nonce++

			// Deploy gate: CREATE requires Dox_Dev Level 2+
			// L0/L1 deployers cannot deploy unknown contracts via CREATE
			// Use DeployContractFromCode for ClassA template deployment
			class := ClassB
			if err := EnforceContractClass(account.DoxDevLevel, class); err != nil {
				stack.Push(big.NewInt(0))
				break
			}

			// Deploy contract
			newAcc := evm.State.CreateAccount(newAddr, initCode)
			newAcc.DoxDevLevel = account.DoxDevLevel
			newAcc.ContractClass = class

			buf := make([]byte, 32)
			copy(buf[12:], []byte(newAddr))
			stack.Push(new(big.Int).SetBytes(buf))

		case op == CREATE2:
			_ = stack.Pop() // value
			offset := stack.Pop().Uint64()
			size := stack.Pop().Uint64()
			salt := stack.Pop()
			initCode := mem.Get(offset, size)
			_ = salt // salt used in address derivation for CREATE2

			// Same deploy gate as CREATE
			class := ClassB
			if err := EnforceContractClass(account.DoxDevLevel, class); err != nil {
				stack.Push(big.NewInt(0))
				break
			}

			// Derive CREATE2 address (simplified — uses salt)
			hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", ctx.Address, account.Nonce, salt.String())))
			newAddr := fmt.Sprintf("%x", hash[:20])
			account.Nonce++

			newAcc := evm.State.CreateAccount(newAddr, initCode)
			newAcc.DoxDevLevel = account.DoxDevLevel
			newAcc.ContractClass = class

			buf := make([]byte, 32)
			copy(buf[12:], []byte(newAddr))
			stack.Push(new(big.Int).SetBytes(buf))

		// ══════════════════════════════════
		// WayChain Native Opcodes
		// ══════════════════════════════════

		case op == CONTRACTCLASS:
			// Push contract classification level
			class := uint64(account.ContractClass)
			stack.Push(big.NewInt(int64(class)))

		case op == DOXDEVLEVEL:
			// Push the current caller's Dox_Dev badge level
			stack.Push(big.NewInt(int64(account.DoxDevLevel)))

		case op == LANETYPE:
			// Push current lane type
			stack.Push(big.NewInt(int64(evm.Lane)))

		case op == ATTEST:
			// Anchor a SHA-256 hash on WayChain
			hashData := stack.Pop().Bytes()
			var hash [32]byte
			copy(hash[:], hashData)
			// Emit as log so the oracle can witness it
			evm.State.AddLog(ctx.Address, [][32]byte{hash}, nil, evm.BlockNum)

		case op == RANDOM:
			// Push a verifiable random value from block hash + entropy
			seed := sha256.Sum256([]byte(fmt.Sprintf("waychain:vrf:%d:%s", evm.BlockNum, ctx.Address)))
			stack.Push(new(big.Int).SetBytes(seed[:]))

		case op == RENTBALANCE:
			// Push remaining state rent balance for an address
			addrBytes := stack.Pop().Bytes()
			addr := fmt.Sprintf("%x", addrBytes)
			acc := evm.State.GetAccount(addr)
			if acc != nil {
				stack.Push(new(big.Int).Set(acc.StateRentPaid))
			} else {
				stack.Push(big.NewInt(0))
			}

		case op == DEADMANSWITCH:
			// Check Dead Man's Switch status — returns 0 (active) always in EVM
			// (Actual status comes from the DMS contract — this opcode
			//  is for direct integration from any contract)
			_ = stack.Pop().Uint64() // switchID (simplified — real check calls DMS contract)
			stack.Push(big.NewInt(0)) // active

		case op == VERIFYBADGE:
			// Verify Dox_Dev badge level for any address
			addrBytes := stack.Pop().Bytes()
			minLevel := stack.Pop().Uint64()
			addr := fmt.Sprintf("%x", addrBytes)
			acc := evm.State.GetAccount(addr)
			if acc != nil && uint64(acc.DoxDevLevel) >= minLevel {
				stack.Push(big.NewInt(1))
			} else {
				stack.Push(big.NewInt(0))
			}

		case op == SELFDESTRUCT:
			// Transfer remaining balance to beneficiary
			beneficiary := stack.Pop().Bytes()
			benefAddr := fmt.Sprintf("%x", beneficiary)
			benefAcc := evm.State.GetOrCreateAccount(benefAddr)
			benefAcc.Balance.Add(benefAcc.Balance, account.Balance)
			account.Balance.SetUint64(0)
			// Mark account for deletion (simplified — clear code)
			account.Code = nil
			evm.State.Refunds += 24000
			pc = uint64(len(code))

		case op == INVALID:
			return &ExecutionResult{
				GasUsed: gasUsed,
				Error:   fmt.Errorf("invalid opcode encountered"),
			}

		default:
			return &ExecutionResult{
				GasUsed: gasUsed,
				Error:   fmt.Errorf("unimplemented opcode 0x%02X at pc %d", byte(op), pc-1),
			}
		}

		if err != nil {
			return &ExecutionResult{GasUsed: gasUsed, Error: err, Logs: evm.State.Logs}
		}
	}

	// Apply gas refund (max half of gas used)
	refund := evm.State.Refunds
	maxRefund := gasUsed / 2
	if refund > maxRefund {
		refund = maxRefund
	}
	gasUsed -= refund

	return &ExecutionResult{
		ReturnData: returnData,
		GasUsed:    gasUsed,
		Logs:       evm.State.Logs,
	}
}

// DeployContractFromCode creates and deposits a contract from bytecode
// Used for deploying contracts from the template registry
func (evm *EVM) DeployContractFromCode(caller string, code []byte, class ContractClass) (string, error) {
	// Check deployer's Dox_Dev level
	account := evm.State.GetOrCreateAccount(caller)
	if err := EnforceContractClass(account.DoxDevLevel, class); err != nil {
		return "", err
	}

	// Derive contract address
	hash := sha256.Sum256([]byte(fmt.Sprintf("template:%s:%d", caller, account.Nonce)))
	addr := fmt.Sprintf("%x", hash[:20])
	account.Nonce++

	// Create contract
	contract := evm.State.CreateAccount(addr, code)
	contract.DoxDevLevel = account.DoxDevLevel
	contract.ContractClass = class

	return addr, nil
}
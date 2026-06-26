package evm

import "fmt"

// Opcode represents a single EVM opcode
type Opcode byte

// ── Standard EVM Opcodes (subset — commonly used) ──
const (
	// Stop & Arithmetic
	STOP       Opcode = 0x00
	ADD        Opcode = 0x01
	MUL        Opcode = 0x02
	SUB        Opcode = 0x03
	DIV        Opcode = 0x04
	SDIV       Opcode = 0x05
	MOD        Opcode = 0x06
	SMOD       Opcode = 0x07
	ADDMOD     Opcode = 0x08
	MULMOD     Opcode = 0x09
	EXP        Opcode = 0x0A
	SIGNEXTEND Opcode = 0x0B

	// Comparison & Bitwise
	LT     Opcode = 0x10
	GT     Opcode = 0x11
	SLT    Opcode = 0x12
	SGT    Opcode = 0x13
	EQ     Opcode = 0x14
	ISZERO Opcode = 0x15
	AND    Opcode = 0x16
	OR     Opcode = 0x17
	XOR    Opcode = 0x18
	NOT    Opcode = 0x19
	BYTE   Opcode = 0x1A
	SHL    Opcode = 0x1B
	SHR    Opcode = 0x1C
	SAR    Opcode = 0x1D

	// SHA3
	SHA3 Opcode = 0x20

	// Environment Information
	ADDRESS        Opcode = 0x30
	BALANCE        Opcode = 0x31
	ORIGIN         Opcode = 0x32
	CALLER         Opcode = 0x33
	CALLVALUE      Opcode = 0x34
	CALLDATALOAD   Opcode = 0x35
	CALLDATASIZE   Opcode = 0x36
	CALLDATACOPY   Opcode = 0x37
	CODESIZE       Opcode = 0x38
	CODECOPY       Opcode = 0x39
	GASPRICE       Opcode = 0x3A
	EXTCODESIZE    Opcode = 0x3B
	EXTCODECOPY    Opcode = 0x3C
	RETURNDATASIZE Opcode = 0x3D
	RETURNDATACOPY Opcode = 0x3E
	EXTCODEHASH    Opcode = 0x3F

	// Block Information
	BLOCKHASH  Opcode = 0x40
	COINBASE   Opcode = 0x41
	TIMESTAMP  Opcode = 0x42
	NUMBER     Opcode = 0x43
	DIFFICULTY Opcode = 0x44
	GASLIMIT   Opcode = 0x45
	CHAINID    Opcode = 0x46
	SELFBALANCE Opcode = 0x47
	BASEFEE    Opcode = 0x48

	// Stack, Memory, Storage
	POP      Opcode = 0x50
	MLOAD    Opcode = 0x51
	MSTORE   Opcode = 0x52
	MSTORE8  Opcode = 0x53
	SLOAD    Opcode = 0x54
	SSTORE   Opcode = 0x55
	JUMP     Opcode = 0x56
	JUMPI    Opcode = 0x57
	PC       Opcode = 0x58
	MSIZE    Opcode = 0x59
	GAS      Opcode = 0x5A
	JUMPDEST Opcode = 0x5B

	// Push Operations (0x60-0x7F)
	PUSH1  Opcode = 0x60
	PUSH32 Opcode = 0x7F

	// Duplication Operations (0x80-0x8F)
	DUP1 Opcode = 0x80
	DUP16 Opcode = 0x8F

	// Exchange Operations (0x90-0x9F)
	SWAP1 Opcode = 0x90
	SWAP16 Opcode = 0x9F

	// Logging Operations (0xA0-0xA4)
	LOG0 Opcode = 0xA0
	LOG4 Opcode = 0xA4

	// System Operations
	CREATE  Opcode = 0xF0
	CALL    Opcode = 0xF1
	CALLCODE Opcode = 0xF2
	RETURN  Opcode = 0xF3
	DELEGATECALL Opcode = 0xF4
	CREATE2 Opcode = 0xF5
	STATICCALL  Opcode = 0xFA
	REVERT  Opcode = 0xFD
	INVALID Opcode = 0xFE
	SELFDESTRUCT Opcode = 0xFF
)

// ═══════════════════════════════════════════════
// WayChain New Opcodes (0xC0-0xC7)
// Using the unused 0xC0-0xCF range so standard EVM
// opcodes (CREATE, CALL, RETURN, etc.) remain untouched.
// ═══════════════════════════════════════════════

const (
	// CONTRACTCLASS — Push the contract's classification (A/B/C/D) onto the stack
	CONTRACTCLASS Opcode = 0xC0

	// DOXDEVLEVEL — Push the caller's Dox_Dev badge level onto the stack
	DOXDEVLEVEL Opcode = 0xC1

	// LANETYPE — Push the current execution lane type onto the stack
	LANETYPE Opcode = 0xC2

	// ATTEST — Emit a WayChain attestation event (anchors a hash)
	ATTEST Opcode = 0xC3

	// RANDOM — Push a verifiable random value (from VRF)
	RANDOM Opcode = 0xC4

	// RENTBALANCE — Push the remaining state rent balance for an address
	RENTBALANCE Opcode = 0xC5

	// DEADMANSWITCH — Check if a dead man's switch has fired
	DEADMANSWITCH Opcode = 0xC6

	// VERIFYBADGE — Verify a Dox_Dev badge level for any address
	VERIFYBADGE Opcode = 0xC7
)

// OpcodeInfo stores metadata about each opcode
type OpcodeInfo struct {
	Name     string
	Gas      uint64
	MinStack int // Minimum stack items required
	Result   int // Stack items pushed as result
}

// OpcodeTable maps opcodes to their metadata
var OpcodeTable = map[Opcode]OpcodeInfo{
	// Arithmetic
	STOP:       {"STOP", 0, 0, 0},
	ADD:        {"ADD", 3, 2, 1},
	MUL:        {"MUL", 5, 2, 1},
	SUB:        {"SUB", 3, 2, 1},
	DIV:        {"DIV", 5, 2, 1},
	SDIV:       {"SDIV", 5, 2, 1},
	MOD:        {"MOD", 5, 2, 1},
	SMOD:       {"SMOD", 5, 2, 1},
	ADDMOD:     {"ADDMOD", 8, 3, 1},
	MULMOD:     {"MULMOD", 8, 3, 1},
	EXP:        {"EXP", 10, 2, 1},
	SIGNEXTEND: {"SIGNEXTEND", 5, 2, 1},

	// Comparison & Bitwise
	LT:     {"LT", 3, 2, 1},
	GT:     {"GT", 3, 2, 1},
	SLT:    {"SLT", 3, 2, 1},
	SGT:    {"SGT", 3, 2, 1},
	EQ:     {"EQ", 3, 2, 1},
	ISZERO: {"ISZERO", 3, 1, 1},
	AND:    {"AND", 3, 2, 1},
	OR:     {"OR", 3, 2, 1},
	XOR:    {"XOR", 3, 2, 1},
	NOT:    {"NOT", 3, 1, 1},
	BYTE:   {"BYTE", 3, 2, 1},
	SHL:    {"SHL", 3, 2, 1},
	SHR:    {"SHR", 3, 2, 1},
	SAR:    {"SAR", 3, 2, 1},

	// SHA3
	SHA3: {"SHA3", 30, 2, 1},

	// Environment
	ADDRESS:        {"ADDRESS", 2, 0, 1},
	BALANCE:        {"BALANCE", 700, 1, 1},
	ORIGIN:         {"ORIGIN", 2, 0, 1},
	CALLER:         {"CALLER", 2, 0, 1},
	CALLVALUE:      {"CALLVALUE", 2, 0, 1},
	CALLDATALOAD:   {"CALLDATALOAD", 3, 1, 1},
	CALLDATASIZE:   {"CALLDATASIZE", 2, 0, 1},
	CALLDATACOPY:   {"CALLDATACOPY", 3, 3, 0},
	CODESIZE:       {"CODESIZE", 2, 0, 1},
	CODECOPY:       {"CODECOPY", 3, 3, 0},
	GASPRICE:       {"GASPRICE", 2, 0, 1},
	EXTCODESIZE:    {"EXTCODESIZE", 700, 1, 1},
	RETURNDATASIZE: {"RETURNDATASIZE", 2, 0, 1},
	RETURNDATACOPY: {"RETURNDATACOPY", 3, 3, 0},

	// Block
	TIMESTAMP:  {"TIMESTAMP", 2, 0, 1},
	NUMBER:     {"NUMBER", 2, 0, 1},
	CHAINID:    {"CHAINID", 2, 0, 1},
	BASEFEE:    {"BASEFEE", 2, 0, 1},
	SELFBALANCE: {"SELFBALANCE", 5, 0, 1},

	// Stack/Memory/Storage
	POP:      {"POP", 2, 1, 0},
	MLOAD:    {"MLOAD", 3, 1, 1},
	MSTORE:   {"MSTORE", 3, 2, 0},
	MSTORE8:  {"MSTORE8", 3, 2, 0},
	SLOAD:    {"SLOAD", 2100, 1, 1},
	SSTORE:   {"SSTORE", 5000, 2, 0},
	JUMP:     {"JUMP", 8, 1, 0},
	JUMPI:    {"JUMPI", 10, 2, 0},
	PC:       {"PC", 2, 0, 1},
	MSIZE:    {"MSIZE", 2, 0, 1},
	GAS:      {"GAS", 2, 0, 1},
	JUMPDEST: {"JUMPDEST", 1, 0, 0},

	// Push (PUSH1 shown — others are N+2 gas)
	PUSH1:  {"PUSH1", 3, 0, 1},
	PUSH32: {"PUSH32", 3, 0, 1},

	// DUP
	DUP1: {"DUP1", 3, 1, 1},

	// SWAP
	SWAP1: {"SWAP1", 3, 2, 0},

	// LOG
	LOG0: {"LOG0", 375, 2, 0},
	LOG4: {"LOG4", 625, 6, 0},

	// System
	CREATE:  {"CREATE", 32000, 3, 1},
	CALL:    {"CALL", 700, 7, 1},
	RETURN:  {"RETURN", 0, 2, 0},
	REVERT:  {"REVERT", 0, 2, 0},
	INVALID: {"INVALID", 0, 0, 0},
	SELFDESTRUCT: {"SELFDESTRUCT", 5000, 1, 0},

	// WayChain native opcodes
	CONTRACTCLASS: {"CONTRACTCLASS", 2, 0, 1},
	DOXDEVLEVEL:   {"DOXDEVLEVEL", 20, 0, 1},
	LANETYPE:      {"LANETYPE", 2, 0, 1},
	ATTEST:        {"ATTEST", 20000, 1, 0},
	RANDOM:        {"RANDOM", 20, 0, 1},
	RENTBALANCE:   {"RENTBALANCE", 700, 1, 1},
	DEADMANSWITCH: {"DEADMANSWITCH", 2000, 1, 1},
	VERIFYBADGE:   {"VERIFYBADGE", 700, 2, 1},
}

// OpcodeName returns the name of an opcode
func OpcodeName(op Opcode) string {
	if info, ok := OpcodeTable[op]; ok {
		return info.Name
	}
	return fmt.Sprintf("UNKNOWN(0x%02X)", byte(op))
}

// IsPushOp returns true if the opcode is a PUSH instruction
func IsPushOp(op Opcode) bool {
	return op >= PUSH1 && op <= PUSH32
}

// PushSize returns how many bytes a PUSH instruction reads
func PushSize(op Opcode) int {
	if IsPushOp(op) {
		return int(op - PUSH1 + 1)
	}
	return 0
}

// IsDupOp returns true if the opcode is a DUP instruction
func IsDupOp(op Opcode) bool {
	return op >= DUP1 && op <= DUP16
}

// DupIndex returns which stack item a DUP duplicates (1-indexed)
func DupIndex(op Opcode) int {
	if IsDupOp(op) {
		return int(op - DUP1 + 1)
	}
	return 0
}

// IsSwapOp returns true if the opcode is a SWAP instruction
func IsSwapOp(op Opcode) bool {
	return op >= SWAP1 && op <= SWAP16
}

// SwapIndex returns which stack item a SWAP exchanges with
func SwapIndex(op Opcode) int {
	if IsSwapOp(op) {
		return int(op - SWAP1 + 1)
	}
	return 0
}

// IsLogOp returns true if the opcode is a LOG instruction
func IsLogOp(op Opcode) bool {
	return op >= LOG0 && op <= LOG4
}

// LogTopicCount returns the number of topics for a LOG instruction
func LogTopicCount(op Opcode) int {
	if IsLogOp(op) {
		return int(op - LOG0)
	}
	return 0
}

// GasCost returns the gas cost for a LOG opcode based on topic count
func LogGasCost(topics int) uint64 {
	return 375 + uint64(topics)*125
}
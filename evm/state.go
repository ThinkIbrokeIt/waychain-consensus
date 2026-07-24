// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// LaneType defines which execution lane a transaction runs in
type LaneType byte

const (
	ConsensusLane LaneType = iota // 0 — standard transactions
	OracleLane                    // 1 — oracle attestations
	PrivateLane                   // 2 — private transactions (encrypted mempool)
)

// ContractClass defines the risk classification of a contract
type ContractClass byte

const (
	ClassNone ContractClass = iota // 0 — not classified (unverified)
	ClassA                         // 1 — safe (permissionless)
	ClassB                         // 2 — managed (Dox_Dev Level 2+)
	ClassC                         // 3 — governed (Dox_Dev Level 3+)
	ClassD                         // 4 — restricted (governance vote required)
)

// ContractClassNames maps class to string
var ContractClassNames = map[ContractClass]string{
	ClassNone: "None",
	ClassA:    "A — Safe",
	ClassB:    "B — Managed",
	ClassC:    "C — Governed",
	ClassD:    "D — Restricted",
}

func (c ContractClass) String() string {
	if name, ok := ContractClassNames[c]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", c)
}

// Account represents a WayChain account on the execution layer
type Account struct {
	Nonce    uint64
	Balance  *big.Int
	CodeHash [32]byte
	Code     []byte
	Storage  map[[32]byte][32]byte // key → value

	// WayChain extensions
	ContractClass   ContractClass
	DoxDevLevel     uint8    // 0 (unverified) to 3
	StateRentPaid   *big.Int
	LastRentPayment uint64   // Block number of last rent payment
}

// NewAccount creates a new account
func NewAccount() *Account {
	return &Account{
		Balance:       new(big.Int),
		Storage:       make(map[[32]byte][32]byte),
		StateRentPaid: new(big.Int),
	}
}

// StateDB manages all accounts on the execution layer
type StateDB struct {
	Accounts map[string]*Account // address → account
	Logs     []*LogEntry
	Refunds  uint64
}

// LogEntry represents an EVM log
type LogEntry struct {
	Address string
	Topics  [][32]byte
	Data    []byte
	Block   uint64
}

// NewStateDB creates a new state database
func NewStateDB() *StateDB {
	return &StateDB{
		Accounts: make(map[string]*Account),
	}
}

// GetOrCreateAccount retrieves or creates an account
func (s *StateDB) GetOrCreateAccount(addr string) *Account {
	if acc, ok := s.Accounts[addr]; ok {
		return acc
	}
	acc := NewAccount()
	s.Accounts[addr] = acc
	return acc
}

// GetAccount retrieves an account, returns nil if not found
func (s *StateDB) GetAccount(addr string) *Account {
	acc, ok := s.Accounts[addr]
	if !ok {
		return nil
	}
	return acc
}

// Exist checks if an account exists
func (s *StateDB) Exist(addr string) bool {
	_, ok := s.Accounts[addr]
	return ok
}

// CreateAccount explicitly creates a new account (with code)
func (s *StateDB) CreateAccount(addr string, code []byte) *Account {
	codeHash := sha256.Sum256(code)
	acc := &Account{
		Nonce:           0,
		Balance:         new(big.Int),
		CodeHash:        codeHash,
		Code:            code,
		Storage:         make(map[[32]byte][32]byte),
		StateRentPaid:   new(big.Int),
		ContractClass:   ClassNone,
	}
	s.Accounts[addr] = acc
	return acc
}

// Clone creates a copy of the state for speculative execution
func (s *StateDB) Clone() *StateDB {
	clone := NewStateDB()
	for addr, acc := range s.Accounts {
		accClone := NewAccount()
		accClone.Nonce = acc.Nonce
		accClone.Balance = new(big.Int).Set(acc.Balance)
		accClone.CodeHash = acc.CodeHash
		accClone.Code = make([]byte, len(acc.Code))
		copy(accClone.Code, acc.Code)
		accClone.ContractClass = acc.ContractClass
		accClone.DoxDevLevel = acc.DoxDevLevel
		accClone.StateRentPaid = new(big.Int).Set(acc.StateRentPaid)
		accClone.LastRentPayment = acc.LastRentPayment
		for k, v := range acc.Storage {
			accClone.Storage[k] = v
		}
		clone.Accounts[addr] = accClone
	}
	clone.Logs = append(clone.Logs, s.Logs...)
	clone.Refunds = s.Refunds
	return clone
}

// AddLog adds a log entry
func (s *StateDB) AddLog(addr string, topics [][32]byte, data []byte, block uint64) {
	s.Logs = append(s.Logs, &LogEntry{
		Address: addr,
		Topics:  topics,
		Data:    data,
		Block:   block,
	})
}

// EnforceContractClass checks if a deployer can deploy a contract of a given class
// Returns error if not permitted
func EnforceContractClass(deployerLvl uint8, class ContractClass) error {
	switch class {
	case ClassA:
		return nil // Anyone can deploy Class A
	case ClassB:
		if deployerLvl < 2 {
			return fmt.Errorf("Class B requires Dox_Dev Level 2+ (deployer has level %d)", deployerLvl)
		}
	case ClassC:
		if deployerLvl < 3 {
			return fmt.Errorf("Class C requires Dox_Dev Level 3+ (deployer has level %d)", deployerLvl)
		}
	case ClassD:
		return fmt.Errorf("Class D requires governance approval")
	}
	return nil
}

// CanDeployContract returns nil if the deployer is allowed to deploy any contract
// on WayChain. This is the chain-level deploy gate — unverified (L0) or low-level (L1)
// addresses cannot deploy contracts via CREATE/CREATE2.
// They can only use pre-deployed ClassA templates via DeployContractFromCode.
func CanDeployContract(deployerLvl uint8) error {
	if deployerLvl < 2 {
		return fmt.Errorf("contract deployment requires Dox_Dev Level 2+ (deployer has level %d)", deployerLvl)
	}
	return nil
}
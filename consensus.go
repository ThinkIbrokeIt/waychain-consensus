package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"
)

// ══════════════════════════════════════════════════════════════════════
// BFT Consensus Engine — CometBFT-derived
// Propose → Prevote → Precommit → Commit
// Instant finality with 2/3+ voting power
// ══════════════════════════════════════════════════════════════════════

// Consensus phase types
type ConsensusPhase byte

const (
	PhasePropose    ConsensusPhase = iota
	PhasePrevote
	PhasePrecommit
	PhaseCommit
	PhaseTimeout
)

func (p ConsensusPhase) String() string {
	switch p {
	case PhasePropose:
		return "PROPOSE"
	case PhasePrevote:
		return "PREVOTE"
	case PhasePrecommit:
		return "PRECOMMIT"
	case PhaseCommit:
		return "COMMIT"
	case PhaseTimeout:
		return "TIMEOUT"
	default:
		return "UNKNOWN"
	}
}

// Consensus-specific constants (beyond MaxValidators in types.go)
const (
	ConsensusTimeout         = 3 * time.Second  // Time to wait for 2/3+ commits
	MinValidatorStake        = 10000            // Minimum self-bond
	EpochLength              = 10000            // Blocks per epoch
	InstantFinalityThreshold = 2.0 / 3.0        // 2/3+ for finality
)

// ConsensusRound tracks the state of a single height's consensus
type ConsensusRound struct {
	Height       uint64
	Round        byte
	Phase        ConsensusPhase
	Proposer     *ValidatorID
	Block        *BlockWithTx
	Votes        map[string]Vote // validatorID → Vote
	PrevoteSet   map[[32]byte]int // blockHash → vote count
	PrecommitSet map[[32]byte]int // blockHash → vote count
	StartedAt    time.Time
	mu           sync.RWMutex
}

// ConsensusEngine manages the BFT consensus process
type ConsensusEngine struct {
	CurrentHeight uint64
	CurrentRound  byte
	Validators     *ValidatorSet
	ActiveSet     []*ValidatorID // Current epoch's active validators
	VotingPower   map[string]uint64 // validatorID → voting power (equal for active)
	TotalPower    uint64
	Blocks        map[uint64]BlockWithTx // height → finalized block
	RandomSeed    [32]byte
	mu            sync.RWMutex
}

// NewConsensusEngine creates a new consensus engine
func NewConsensusEngine(validators *ValidatorSet) *ConsensusEngine {
	engine := &ConsensusEngine{
		CurrentHeight: 0,
		CurrentRound:  0,
		Validators:     validators,
		Blocks:        make(map[uint64]BlockWithTx),
		VotingPower:   make(map[string]uint64),
	}
	engine.selectNewEpoch()
	return engine
}

// selectNewEpoch selects the active validator set via sqrt-weighted lottery
func (ce *ConsensusEngine) selectNewEpoch() {
	registered := ce.Validators.IDs
	if len(registered) == 0 {
		ce.ActiveSet = nil
		ce.TotalPower = 0
		return
	}

	// Sqrt-weighted lottery selection
	type weightedVal struct {
		id     ValidatorID
		weight float64
	}

	var weighted []weightedVal
	for _, v := range registered {
		weight := sqrtWeighted(float64(ce.Validators.Stakes[v]))
		weighted = append(weighted, weightedVal{id: v, weight: weight})
	}

	// Sort by weight (descending) for deterministic selection
	sort.Slice(weighted, func(i, j int) bool {
		return weighted[i].weight > weighted[j].weight
	})

	// Select top N
	n := MaxValidators
	if len(weighted) < n {
		n = len(weighted)
	}

	ce.ActiveSet = make([]*ValidatorID, n)
	ce.VotingPower = make(map[string]uint64)
	ce.TotalPower = 0

	// All active validators get EQUAL voting power (1 each)
	for i := 0; i < n; i++ {
		ce.ActiveSet[i] = &weighted[i].id
		ce.VotingPower[weighted[i].id.String()] = 1
		ce.TotalPower++
	}

	// Generate new random seed for this epoch
	ce.RandomSeed = sha256.Sum256([]byte(fmt.Sprintf("epoch:%d", ce.CurrentHeight)))
}

// SelectProposer deterministically selects the next block proposer
func (ce *ConsensusEngine) SelectProposer(height uint64) *ValidatorID {
	if len(ce.ActiveSet) == 0 {
		return nil
	}

	// Deterministic: seed = hash(randomSeed, height)
	seedInput := append(ce.RandomSeed[:], []byte(fmt.Sprintf(":%d", height))...)
	hash := sha256.Sum256(seedInput)

	// Use hash to select proposer index
	index := new(big.Int).SetBytes(hash[:]).Uint64() % uint64(len(ce.ActiveSet))
	return ce.ActiveSet[index]
}

// GetQuorumHeight returns the block height that 2/3+ voting power last committed
func (ce *ConsensusEngine) GetQuorumHeight() uint64 {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	var max uint64
	for h := range ce.Blocks {
		if h > max {
			max = h
		}
	}
	return max
}

// IsValidatorActive checks if a validator is in the current active set
func (ce *ConsensusEngine) IsValidatorActive(id ValidatorID) bool {
	for _, v := range ce.ActiveSet {
		if *v == id {
			return true
		}
	}
	return false
}

// FinalizeBlock records a finalized block (2/3+ commits achieved)
func (ce *ConsensusEngine) FinalizeBlock(block *BlockWithTx) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.Blocks[block.Height] = *block
	if block.Height > ce.CurrentHeight {
		ce.CurrentHeight = block.Height
	}
}

// NewConsensusState creates a new consensus engine (alias for backward compat)
func NewConsensusState(vs *ValidatorSet) *ConsensusEngine {
	return NewConsensusEngine(vs)
}

// sqrtWeighted returns the square root of x
func sqrtWeighted(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 10; i++ {
		z = (z + x/z) / 2
	}
	return z
}

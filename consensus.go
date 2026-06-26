package main

import (
	"fmt"
	"time"
)

// ConsensusState tracks a round of BFT consensus
type ConsensusState struct {
	Height      uint64
	Round       uint32
	Validators  *ValidatorSet
	Proposer    ValidatorID
	Proposal    *BlockHeader

	Prevotes    map[ValidatorID][32]byte  // validator → block hash
	Precommits  map[ValidatorID][32]byte  // validator → block hash
	NilVotes    map[ValidatorID]bool      // validators who sent nil prevote

	StartedAt   time.Time
	Committed   uint64  // blocks committed
}

// NewConsensusState creates a new consensus instance
func NewConsensusState(valSet *ValidatorSet) *ConsensusState {
	return &ConsensusState{
		Height:     1,
		Round:      0,
		Validators: valSet,
		Prevotes:   make(map[ValidatorID][32]byte),
		Precommits: make(map[ValidatorID][32]byte),
		NilVotes:   make(map[ValidatorID]bool),
	}
}

// StartRound begins a new consensus round
func (cs *ConsensusState) StartRound() {
	cs.Proposer = cs.Validators.SelectProposer(cs.Height)
	cs.Round = 0
	cs.Prevotes = make(map[ValidatorID][32]byte)
	cs.Precommits = make(map[ValidatorID][32]byte)
	cs.NilVotes = make(map[ValidatorID]bool)
	cs.Proposal = nil
	cs.StartedAt = time.Now()
}

// Propose creates a block proposal from the proposer
func (cs *ConsensusState) Propose(proposer ValidatorID) *BlockHeader {
	if proposer != cs.Proposer {
		return nil
	}

	var prevHash [32]byte
	if cs.Committed > 0 {
		prevHash = [32]byte{byte(cs.Height - 1)}
	}

	block := &BlockHeader{
		Height:    cs.Height,
		Round:     cs.Round,
		Proposer:  proposer,
		Timestamp: time.Now().Unix(),
		PrevHash:  prevHash,
	}

	cs.Proposal = block
	return block
}

// Prevote submits a prevote for a block
func (cs *ConsensusState) Prevote(validator ValidatorID, blockHash [32]byte) {
	cs.Prevotes[validator] = blockHash
}

// Precommit submits a precommit for a block
func (cs *ConsensusState) Precommit(validator ValidatorID, blockHash [32]byte) {
	cs.Precommits[validator] = blockHash
}

// HasTwoThirdsPrevotes checks if a block has 2/3+ prevotes
func (cs *ConsensusState) HasTwoThirdsPrevotes(blockHash [32]byte) bool {
	totalActive := cs.Validators.Count()
	if totalActive == 0 {
		return false
	}
	count := 0
	for _, hash := range cs.Prevotes {
		if hash == blockHash {
			count++
		}
	}
	return float64(count)/float64(totalActive) >= 2.0/3.0
}

// HasTwoThirdsPrecommits checks if a block has 2/3+ precommits
func (cs *ConsensusState) HasTwoThirdsPrecommits(blockHash [32]byte) bool {
	totalActive := cs.Validators.Count()
	if totalActive == 0 {
		return false
	}
	count := 0
	for _, hash := range cs.Precommits {
		if hash == blockHash {
			count++
		}
	}
	return float64(count)/float64(totalActive) >= 2.0/3.0
}

// Commit finalizes a block and advances to the next height
func (cs *ConsensusState) Commit() *BlockHeader {
	if cs.Proposal == nil {
		return nil
	}
	cs.Committed++
	block := cs.Proposal
	cs.Height++
	cs.Round = 0
	cs.Prevotes = make(map[ValidatorID][32]byte)
	cs.Precommits = make(map[ValidatorID][32]byte)
	cs.NilVotes = make(map[ValidatorID]bool)
	cs.Proposal = nil
	return block
}

// AdvanceToNextRound increments the round and resets votes
func (cs *ConsensusState) AdvanceToNextRound() {
	cs.Round++
	cs.Prevotes = make(map[ValidatorID][32]byte)
	cs.Precommits = make(map[ValidatorID][32]byte)
	cs.NilVotes = make(map[ValidatorID]bool)
}

// RunConsensusRound runs one complete consensus round
// Returns true if a block was committed
func (cs *ConsensusState) RunConsensusRound() bool {
	validators := cs.Validators.IDs
	activeCount := len(validators)
	if activeCount == 0 {
		return false
	}

	// Step 1: Proposer proposes
	proposer := cs.Proposer
	block := cs.Propose(proposer)
	if block == nil {
		fmt.Printf("  ⚠️  Proposer %s failed to propose\n", proposer.String())
		cs.AdvanceToNextRound()
		return false
	}

	blockHash := block.Hash()
	fmt.Printf("  📝 Proposer %s proposes block #%d (hash: %x...)\n",
		proposer.String(), cs.Height, blockHash[:4])

	// Step 2: Validators prevote
	for _, vid := range validators {
		if vid == proposer {
			// Proposer votes for their own block
			cs.Prevote(vid, blockHash)
		} else {
			// Others vote for the proposed block (simplified — no malicious actors)
			cs.Prevote(vid, blockHash)
		}
	}
	fmt.Printf("  ✅ %d validators prevoted\n", len(cs.Prevotes))

	// Step 3: Check if we have 2/3+ prevotes
	if !cs.HasTwoThirdsPrevotes(blockHash) {
		fmt.Printf("  ⚠️  Not enough prevotes (have %d, need 2/3)\n", len(cs.Prevotes))
		cs.AdvanceToNextRound()
		return false
	}
	fmt.Printf("  🔒 2/3+ prevotes achieved\n")

	// Step 4: Validators precommit
	for _, vid := range validators {
		cs.Precommit(vid, blockHash)
	}
	fmt.Printf("  ✅ %d validators precommitted\n", len(cs.Precommits))

	// Step 5: Check if we have 2/3+ precommits
	if !cs.HasTwoThirdsPrecommits(blockHash) {
		fmt.Printf("  ⚠️  Not enough precommits\n")
		cs.AdvanceToNextRound()
		return false
	}
	fmt.Printf("  🔒 2/3+ precommits achieved\n")

	// Step 6: Commit!
	committed := cs.Commit()
	if committed != nil {
		fmt.Printf("  🎉 Block #%d COMMITTED (proposer: %s | timestamp: %d | hash: %x...)\n",
			committed.Height, committed.Proposer.String(), committed.Timestamp, blockHash[:4])
		return true
	}

	return false
}
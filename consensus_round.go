// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"fmt"
	"sync"
	"time"
)

// ══════════════════════════════════════════════════════════════════════
// Consensus Round Manager — BFT Propose→Prevote→Precommit→Commit
// Runs on each validator node, coordinates via P2P
// ══════════════════════════════════════════════════════════════════════

// RoundState tracks the current consensus round for a given height
type RoundState struct {
	Height       uint64
	Round        byte
	Phase        ConsensusPhase
	Proposer     *ValidatorID
	Proposal     *BlockWithTx
	Prevotes     map[string]Vote // validatorID → prevote
	Precommits   map[string]Vote // validatorID → precommit
	PrevotePower  uint64          // total voting power that prevoted
	PrecommitPower uint64         // total voting power that precommitted
	StartedAt    time.Time
	Timeout      *time.Timer
}

// ConsensusManager orchestrates consensus rounds across the network
type ConsensusManager struct {
	Engine     *ConsensusEngine
	P2PNode    *P2PNode
	Chain      *Chain
	CurrentRound *RoundState
	consensusMu sync.Mutex
	done        chan struct{}
}

// NewConsensusManager creates a new consensus manager
func NewConsensusManager(engine *ConsensusEngine, p2pNode *P2PNode, chain *Chain) *ConsensusManager {
	cm := &ConsensusManager{
		Engine:  engine,
		P2PNode: p2pNode,
		Chain:   chain,
		done:    make(chan struct{}),
	}

	// Wire P2P message handlers
	if p2pNode != nil {
		p2pNode.OnVote = cm.handleVote
	}

	return cm
}

// Start begins the consensus loop
func (cm *ConsensusManager) Start() {
	go cm.consensusLoop()
}

// Stop halts the consensus loop
func (cm *ConsensusManager) Stop() {
	close(cm.done)
}

// consensusLoop is the main consensus loop — produces blocks at 1s intervals
func (cm *ConsensusManager) consensusLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-cm.done:
			return
		case <-ticker.C:
			cm.runBlockRound()
		}
	}
}

// runBlockRound executes one consensus round for the next block
func (cm *ConsensusManager) runBlockRound() {
	height := cm.Engine.CurrentHeight + 1

	// Select proposer
	proposer := cm.Engine.SelectProposer(height)
	if proposer == nil {
		return
	}

	// Check if we are the proposer
	if cm.isLocalValidator(*proposer) {
		cm.proposeBlock(height, *proposer)
	}

	// Wait for block proposal from network (or timeout)
	// In a full implementation, this would listen for P2P messages
	// For now, the block production is handled by the daemon loop
}

// proposeBlock creates and broadcasts a new block proposal
func (cm *ConsensusManager) proposeBlock(height uint64, proposer ValidatorID) {
	// Build block from chain
	block := cm.Chain.ProduceBlock(proposer)
	if block == nil {
		return
	}

	// Create round state
	round := &RoundState{
		Height:    height,
		Round:     0,
		Phase:     PhasePropose,
		Proposer:  &proposer,
		Proposal:  block,
		Prevotes:  make(map[string]Vote),
		Precommits: make(map[string]Vote),
		StartedAt: time.Now(),
	}

	cm.consensusMu.Lock()
	cm.CurrentRound = round
	cm.consensusMu.Unlock()

	// Broadcast proposal via P2P
	if cm.P2PNode != nil {
		cm.broadcastProposal(round)
	}

	// Start timeout
	round.Timeout = time.AfterFunc(ConsensusTimeout, func() {
		cm.handleTimeout(height, 0)
	})

	// If we're also a validator, prevote on our own proposal
	if cm.isLocalValidator(proposer) {
		cm.prevote(height, 0, block.Hash, proposer)
	}
}

// broadcastProposal sends the block proposal to all peers
func (cm *ConsensusManager) broadcastProposal(round *RoundState) {
	if cm.P2PNode == nil || round.Proposal == nil {
		return
	}

	msg := P2PMessage{
		Type:    MsgBlock,
		From:    cm.P2PNode.ID,
		Seq:     cm.P2PNode.nextSeq(),
		Payload: serializeBlock(round.Proposal),
	}
	cm.P2PNode.Broadcast(msg)
}

// prevote sends a prevote for a block hash
func (cm *ConsensusManager) prevote(height uint64, round byte, blockHash [32]byte, voter ValidatorID) {
	vote := Vote{
		Height:    height,
		Round:     uint32(round),
		BlockHash: blockHash,
		Validator: voter,
		VoteType:  1, // prevote
	}

	// Add to current round
	cm.consensusMu.Lock()
	if cm.CurrentRound != nil && cm.CurrentRound.Height == height && cm.CurrentRound.Round == round {
		cm.CurrentRound.Prevotes[voter.String()] = vote
		cm.CurrentRound.PrevotePower++
	}
	cm.consensusMu.Unlock()

	// Broadcast vote
	if cm.P2PNode != nil {
		cm.broadcastVote(vote)
	}
}

// precommit sends a precommit for a block hash
func (cm *ConsensusManager) precommit(height uint64, round byte, blockHash [32]byte, voter ValidatorID) {
	vote := Vote{
		Height:    height,
		Round:     uint32(round),
		BlockHash: blockHash,
		Validator: voter,
		VoteType:  2, // precommit
	}

	// Add to current round
	cm.consensusMu.Lock()
	if cm.CurrentRound != nil && cm.CurrentRound.Height == height && cm.CurrentRound.Round == round {
		cm.CurrentRound.Precommits[vote.Validator.String()] = vote
		cm.CurrentRound.PrecommitPower++
	}
	cm.consensusMu.Unlock()

	// Broadcast vote
	if cm.P2PNode != nil {
		cm.broadcastVote(vote)
	}

	// Check if we have 2/3+ precommits
	cm.checkCommit(height, round)
}

// handleVote processes an incoming vote from P2P
func (cm *ConsensusManager) handleVote(vote interface{}, from string) {
	v, ok := vote.(Vote)
	if !ok {
		return
	}

	cm.consensusMu.Lock()
	defer cm.consensusMu.Unlock()

	if cm.CurrentRound == nil || cm.CurrentRound.Height != v.Height {
		return
	}

	if v.VoteType == 1 {
		// Prevote
		cm.CurrentRound.Prevotes[from] = v
		cm.CurrentRound.PrevotePower++
	} else if v.VoteType == 2 {
		// Precommit
		cm.CurrentRound.Precommits[v.Validator.String()] = v
		cm.CurrentRound.PrecommitPower++
		cm.checkCommitLocked(v.Height, cm.CurrentRound.Round)
	}
}

// checkCommit checks if 2/3+ precommits are reached (must hold lock)
func (cm *ConsensusManager) checkCommitLocked(height uint64, round byte) {
	if cm.CurrentRound == nil {
		return
	}

	threshold := uint64(float64(cm.Engine.TotalPower) * InstantFinalityThreshold)
	if cm.CurrentRound.PrecommitPower >= threshold {
		// Commit block!
		cm.CurrentRound.Phase = PhaseCommit
		if cm.CurrentRound.Timeout != nil {
			cm.CurrentRound.Timeout.Stop()
		}

		if cm.CurrentRound.Proposal != nil {
			cm.Engine.FinalizeBlock(cm.CurrentRound.Proposal)
		}
	}
}

// checkCommit checks if 2/3+ precommits are reached (public, acquires lock)
func (cm *ConsensusManager) checkCommit(height uint64, round byte) {
	cm.consensusMu.Lock()
	defer cm.consensusMu.Unlock()
	cm.checkCommitLocked(height, round)
}

// handleTimeout handles a consensus round timeout
func (cm *ConsensusManager) handleTimeout(height uint64, round byte) {
	cm.consensusMu.Lock()
	defer cm.consensusMu.Unlock()

	if cm.CurrentRound == nil || cm.CurrentRound.Height != height {
		return
	}

	cm.CurrentRound.Phase = PhaseTimeout
	fmt.Printf("  ⏱️  Consensus timeout at height %d round %d\n", height, round)
}

// broadcastVote sends a vote to all peers
func (cm *ConsensusManager) broadcastVote(vote Vote) {
	if cm.P2PNode == nil {
		return
	}

	msg := P2PMessage{
		Type:    MsgVote,
		From:    cm.P2PNode.ID,
		Seq:     cm.P2PNode.nextSeq(),
		Payload: serializeVote(vote),
	}
	cm.P2PNode.Broadcast(msg)
}

// isLocalValidator checks if the given validator ID is this node
func (cm *ConsensusManager) isLocalValidator(id ValidatorID) bool {
	// In production, this would check against the node's configured validator ID
	// For now, assume we are validator 0x01
	localID := NewValidatorID(0x01)
	return id == localID
}

// serializeBlock serializes a block for P2P transmission
func serializeBlock(block *BlockWithTx) []byte {
	if block == nil {
		return []byte("nil")
	}
	return []byte(fmt.Sprintf("block:%d:%x:%d", block.Height, block.Hash[:4], len(block.Transactions)))
}

// serializeVote serializes a vote for P2P transmission
func serializeVote(vote Vote) []byte {
	return []byte(fmt.Sprintf("vote:%d:%d:%x:%x", vote.Height, vote.Round, vote.BlockHash[:4], vote.Validator[:4]))
}

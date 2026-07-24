// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"testing"
	"time"
)

func TestConsensusRoundManager(t *testing.T) {
	vs := NewValidatorSet()
	vs.Add(NewValidatorID(0x01), 10000)
	vs.Add(NewValidatorID(0x02), 50000)
	vs.Add(NewValidatorID(0x03), 100000)

	engine := NewConsensusEngine(vs)
	chain := NewChain()

	// Create consensus manager (no P2P for unit test)
	cm := NewConsensusManager(engine, nil, chain)

	// Test 1: Manager created
	if cm == nil {
		t.Fatal("Expected consensus manager to be created")
	}
	if cm.Engine != engine {
		t.Fatal("Engine not wired correctly")
	}

	// Test 2: Proposer selection works
	proposer := cm.Engine.SelectProposer(1)
	if proposer == nil {
		t.Fatal("Expected proposer to be selected")
	}
	t.Logf("Proposer for height 1: %s", proposer.String())

	// Test 3: isLocalValidator
	if !cm.isLocalValidator(NewValidatorID(0x01)) {
		t.Fatal("Validator 0x01 should be local")
	}
	if cm.isLocalValidator(NewValidatorID(0x02)) {
		t.Fatal("Validator 0x02 should not be local")
	}

	// Test 4: Propose block (use the actual proposer for height 1)
	proposerID := *proposer
	cm.proposeBlock(1, proposerID)
	if cm.CurrentRound == nil {
		t.Fatal("Expected current round to be set")
	}
	if cm.CurrentRound.Height != 1 {
		t.Fatalf("Expected height 1, got %d", cm.CurrentRound.Height)
	}
	if cm.CurrentRound.Phase != PhasePropose {
		t.Fatalf("Expected phase PROPOSE, got %s", cm.CurrentRound.Phase)
	}

	// Test 5: All 3 validators prevote
	cm.prevote(1, 0, [32]byte{0x01, 0x02}, NewValidatorID(0x01))
	cm.prevote(1, 0, [32]byte{0x01, 0x02}, NewValidatorID(0x02))
	cm.prevote(1, 0, [32]byte{0x01, 0x02}, NewValidatorID(0x03))
	cm.consensusMu.Lock()
	if cm.CurrentRound.PrevotePower != 3 {
		t.Fatalf("Expected prevote power 3, got %d", cm.CurrentRound.PrevotePower)
	}
	cm.consensusMu.Unlock()

	// Test 6: Precommit with 2/3+ threshold (2 of 3 is enough)
	cm.precommit(1, 0, [32]byte{0x01, 0x02}, NewValidatorID(0x01))
	cm.precommit(1, 0, [32]byte{0x01, 0x02}, NewValidatorID(0x02))

	// Check if block was finalized
	if cm.Engine.CurrentHeight < 1 {
		t.Fatal("Expected block to be finalized after 2/3 precommits")
	}
	if cm.CurrentRound.Phase != PhaseCommit {
		t.Fatalf("Expected phase COMMIT, got %s", cm.CurrentRound.Phase)
	}

	t.Logf("✅ Consensus round: propose→prevote→precommit→commit with 2/3 threshold")
}

func TestConsensusTimeout(t *testing.T) {
	vs := NewValidatorSet()
	vs.Add(NewValidatorID(0x01), 10000)
	vs.Add(NewValidatorID(0x02), 50000)

	engine := NewConsensusEngine(vs)
	chain := NewChain()
	cm := NewConsensusManager(engine, nil, chain)

	// Propose block
	cm.proposeBlock(1, NewValidatorID(0x01))

	// Simulate timeout
	cm.handleTimeout(1, 0)

	if cm.CurrentRound.Phase != PhaseTimeout {
		t.Fatalf("Expected phase TIMEOUT, got %s", cm.CurrentRound.Phase)
	}

	t.Logf("✅ Consensus timeout handled correctly")
}

func TestConsensusMultipleRounds(t *testing.T) {
	vs := NewValidatorSet()
	for i := byte(1); i <= 5; i++ {
		vs.Add(NewValidatorID(i), uint64(i)*10000)
	}

	engine := NewConsensusEngine(vs)
	chain := NewChain()
	cm := NewConsensusManager(engine, nil, chain)

	// Run 3 rounds
	for h := uint64(1); h <= 3; h++ {
		proposer := engine.SelectProposer(h)
		if proposer == nil {
			t.Fatalf("No proposer for height %d", h)
		}
		cm.proposeBlock(h, *proposer)

		// Simulate 2/3 precommits (3 out of 5)
		for i := byte(1); i <= 3; i++ {
			cm.precommit(h, 0, [32]byte{byte(h)}, NewValidatorID(i))
		}

		if cm.Engine.CurrentHeight != h {
			t.Fatalf("Expected height %d, got %d", h, cm.Engine.CurrentHeight)
		}
	}

	t.Logf("✅ Multiple consensus rounds: 3 blocks finalized")
}

func TestP2PNodeCreation(t *testing.T) {
	// Test that P2P node can be created and started
	node := NewP2PNode("test-node", "127.0.0.1:0")
	if node == nil {
		t.Fatal("Expected P2P node to be created")
	}

	err := node.Start()
	if err != nil {
		t.Fatalf("P2P node start failed: %v", err)
	}

	// Give it a moment
	time.Sleep(100 * time.Millisecond)

	// Stop
	node.Stop()

	t.Logf("✅ P2P node created, started, and stopped cleanly")
}

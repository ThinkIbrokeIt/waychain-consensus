// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"math/big"
	"testing"
)

func TestGovernanceProposal(t *testing.T) {
	state := NewStateDB()

	// Create proposal
	createInput := make([]byte, 4+1+32+32+20+32+4)
	createInput[0], createInput[1], createInput[2], createInput[3] = 0xD1, 0xE2, 0xF3, 0xA4
	offset := 4
	createInput[offset] = VoteTypeDirect; offset++ // voteType
	titleHash := make([]byte, 32)
	copy(titleHash, []byte("Proposal: Increase block size"))
	copy(createInput[offset:offset+32], titleHash); offset += 32
	descHash := make([]byte, 32)
	copy(descHash, []byte("Description hash"))
	copy(createInput[offset:offset+32], descHash); offset += 32
	target := make([]byte, 20)
	copy(target, []byte("target-contract-addr"))
	copy(createInput[offset:offset+20], target); offset += 20
	// calldataLen = 4
	big.NewInt(4).FillBytes(createInput[offset:offset+32]); offset += 32
	// calldata
	copy(createInput[offset:offset+4], []byte{0x01, 0x02, 0x03, 0x04})

	out, err := governancePrecompile(createInput, "0xProposer", state, 1000)
	if err != nil {
		t.Fatalf("CreateProposal failed: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("Expected 32 byte proposal ID, got %d", len(out))
	}
	t.Logf("✅ Proposal created: %x...", out[:8])

	// Get proposal
	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0xF3, 0xA4, 0xB5, 0xC6
	copy(getInput[4:36], out)

	getOut, err := governancePrecompile(getInput, "0xProposer", state, 1000)
	if err != nil {
		t.Fatalf("GetProposal failed: %v", err)
	}
	if getOut[0] != VoteTypeDirect {
		t.Fatalf("Expected vote type %d, got %d", VoteTypeDirect, getOut[0])
	}
	if getOut[1] != ProposalStatusActive {
		t.Fatalf("Expected status %d, got %d", ProposalStatusActive, getOut[1])
	}
	t.Logf("✅ Proposal retrieved: type=%d, status=%d", getOut[0], getOut[1])
}

func TestGovernanceVote(t *testing.T) {
	state := NewStateDB()

	// Create proposal
	createInput := make([]byte, 4+1+32+32+20+32+4)
	createInput[0], createInput[1], createInput[2], createInput[3] = 0xD1, 0xE2, 0xF3, 0xA4
	offset := 4
	createInput[offset] = VoteTypeDirect; offset++
	titleHash := make([]byte, 32)
	copy(titleHash, []byte("Test proposal for voting"))
	copy(createInput[offset:offset+32], titleHash); offset += 32
	descHash := make([]byte, 32)
	copy(descHash, []byte("Description"))
	copy(createInput[offset:offset+32], descHash); offset += 32
	target := make([]byte, 20)
	copy(target, []byte("target-addr-1234567890"))
	copy(createInput[offset:offset+20], target); offset += 20
	big.NewInt(4).FillBytes(createInput[offset:offset+32]); offset += 32
	copy(createInput[offset:offset+4], []byte{0x01, 0x02, 0x03, 0x04})

	out, _ := governancePrecompile(createInput, "0xProposer", state, 1000)

	// Vote YES
	voteInput := make([]byte, 4+32+1+32)
	voteInput[0], voteInput[1], voteInput[2], voteInput[3] = 0xE2, 0xF3, 0xA4, 0xB5
	offset = 4
	copy(voteInput[offset:offset+32], out); offset += 32
	voteInput[offset] = 1; offset++ // YES
	big.NewInt(1).FillBytes(voteInput[offset:offset+32])

	voteOut, err := governancePrecompile(voteInput, "0xVoter1", state, 1000)
	if err != nil {
		t.Fatalf("Vote failed: %v", err)
	}
	if voteOut[31] != 1 {
		t.Fatal("Vote should return true")
	}
	t.Logf("✅ Vote cast: YES")

	// Double vote should fail
	_, err = governancePrecompile(voteInput, "0xVoter1", state, 1000)
	if err == nil {
		t.Fatal("Double vote should fail")
	}
	t.Logf("✅ Double vote correctly rejected")

	// Get vote
	getVoteInput := make([]byte, 4+32)
	getVoteInput[0], getVoteInput[1], getVoteInput[2], getVoteInput[3] = 0xA4, 0xB5, 0xC6, 0xD7
	copy(getVoteInput[4:36], out)

	getVoteOut, err := governancePrecompile(getVoteInput, "0xVoter1", state, 1000)
	if err != nil {
		t.Fatalf("GetVote failed: %v", err)
	}
	if getVoteOut[0] != 1 {
		t.Fatal("Vote direction should be YES (1)")
	}
	t.Logf("✅ Vote retrieved: direction=%d", getVoteOut[0])
}

func TestGovernanceFinalize(t *testing.T) {
	state := NewStateDB()

	// Create proposal
	createInput := make([]byte, 4+1+32+32+20+32+4)
	createInput[0], createInput[1], createInput[2], createInput[3] = 0xD1, 0xE2, 0xF3, 0xA4
	offset := 4
	createInput[offset] = VoteTypeDirect; offset++
	titleHash := make([]byte, 32)
	copy(titleHash, []byte("Finalize test proposal"))
	copy(createInput[offset:offset+32], titleHash); offset += 32
	descHash := make([]byte, 32)
	copy(descHash, []byte("Description"))
	copy(createInput[offset:offset+32], descHash); offset += 32
	target := make([]byte, 20)
	copy(target, []byte("target-addr-1234567890"))
	copy(createInput[offset:offset+20], target); offset += 20
	big.NewInt(4).FillBytes(createInput[offset:offset+32]); offset += 32
	copy(createInput[offset:offset+4], []byte{0x01, 0x02, 0x03, 0x04})

	out, _ := governancePrecompile(createInput, "0xProposer", state, 1000)

	// Vote YES
	voteInput := make([]byte, 4+32+1+32)
	voteInput[0], voteInput[1], voteInput[2], voteInput[3] = 0xE2, 0xF3, 0xA4, 0xB5
	offset = 4
	copy(voteInput[offset:offset+32], out); offset += 32
	voteInput[offset] = 1; offset++
	big.NewInt(1).FillBytes(voteInput[offset:offset+32])
	governancePrecompile(voteInput, "0xVoter1", state, 1000)

	// Finalize
	finalizeInput := make([]byte, 4+32)
	finalizeInput[0], finalizeInput[1], finalizeInput[2], finalizeInput[3] = 0xC6, 0xD7, 0xE8, 0xF9
	copy(finalizeInput[4:36], out)

	finalizeOut, err := governancePrecompile(finalizeInput, "0xProposer", state, 1000)
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}
	if finalizeOut[31] != 1 {
		t.Fatal("Proposal should pass with 1 YES vote")
	}
	t.Logf("✅ Proposal finalized: passed=%v", finalizeOut[31] == 1)
}

func TestGovernanceQuadraticCredits(t *testing.T) {
	state := NewStateDB()

	// Initialize voter credits
	creditsKey := govCreditsKey([]byte("0xVoter1"))
	addr := PrecompileAddrHex(0x1D)
	acc := state.GetOrCreateAccount(addr)
	var creditsSlot [32]byte
	big.NewInt(CreditsPerPeriod).FillBytes(creditsSlot[0:32])
	acc.Storage[creditsKey] = creditsSlot

	// Create quadratic proposal
	createInput := make([]byte, 4+1+32+32+20+32+4)
	createInput[0], createInput[1], createInput[2], createInput[3] = 0xD1, 0xE2, 0xF3, 0xA4
	offset := 4
	createInput[offset] = VoteTypeQuadratic; offset++
	titleHash := make([]byte, 32)
	copy(titleHash, []byte("Quadratic test proposal"))
	copy(createInput[offset:offset+32], titleHash); offset += 32
	descHash := make([]byte, 32)
	copy(descHash, []byte("Description"))
	copy(createInput[offset:offset+32], descHash); offset += 32
	target := make([]byte, 20)
	copy(target, []byte("target-addr-1234567890"))
	copy(createInput[offset:offset+20], target); offset += 20
	big.NewInt(4).FillBytes(createInput[offset:offset+32]); offset += 32
	copy(createInput[offset:offset+4], []byte{0x01, 0x02, 0x03, 0x04})

	out, _ := governancePrecompile(createInput, "0xProposer", state, 1000)

	// Vote with credits
	voteInput := make([]byte, 4+32+1+32)
	voteInput[0], voteInput[1], voteInput[2], voteInput[3] = 0xE2, 0xF3, 0xA4, 0xB5
	offset = 4
	copy(voteInput[offset:offset+32], out); offset += 32
	voteInput[offset] = 1; offset++
	big.NewInt(4).FillBytes(voteInput[offset:offset+32]) // spend 4 credits

	voteOut, err := governancePrecompile(voteInput, "0xVoter1", state, 1000)
	if err != nil {
		t.Fatalf("Vote failed: %v", err)
	}
	if voteOut[31] != 1 {
		t.Fatal("Vote should return true")
	}
	t.Logf("✅ Quadratic vote cast with 4 credits")
}

func TestGovernanceFutarchyMarket(t *testing.T) {
	state := NewStateDB()

	// Create proposal
	createInput := make([]byte, 4+1+32+32+20+32+4)
	createInput[0], createInput[1], createInput[2], createInput[3] = 0xD1, 0xE2, 0xF3, 0xA4
	offset := 4
	createInput[offset] = VoteTypeFutarchy; offset++
	titleHash := make([]byte, 32)
	copy(titleHash, []byte("Futarchy test proposal"))
	copy(createInput[offset:offset+32], titleHash); offset += 32
	descHash := make([]byte, 32)
	copy(descHash, []byte("Description"))
	copy(createInput[offset:offset+32], descHash); offset += 32
	target := make([]byte, 20)
	copy(target, []byte("target-addr-1234567890"))
	copy(createInput[offset:offset+20], target); offset += 20
	big.NewInt(4).FillBytes(createInput[offset:offset+32]); offset += 32
	copy(createInput[offset:offset+4], []byte{0x01, 0x02, 0x03, 0x04})

	propOut, _ := governancePrecompile(createInput, "0xProposer", state, 1000)

	// Create prediction market
	marketInput := make([]byte, 4+32+32)
	marketInput[0], marketInput[1], marketInput[2], marketInput[3] = 0xD7, 0xE8, 0xF9, 0xA0
	offset = 4
	copy(marketInput[offset:offset+32], propOut); offset += 32
	questionHash := make([]byte, 32)
	copy(questionHash, []byte("Will price be higher in 90 days?"))
	copy(marketInput[offset:offset+32], questionHash)

	marketOut, err := governancePrecompile(marketInput, "0xProposer", state, 1000)
	if err != nil {
		t.Fatalf("CreateMarket failed: %v", err)
	}
	if len(marketOut) != 32 {
		t.Fatalf("Expected 32 byte market ID, got %d", len(marketOut))
	}
	t.Logf("✅ Prediction market created: %x...", marketOut[:8])

	// Trade YES
	tradeInput := make([]byte, 4+32+1+32)
	tradeInput[0], tradeInput[1], tradeInput[2], tradeInput[3] = 0xE8, 0xF9, 0xA0, 0xB1
	offset = 4
	copy(tradeInput[offset:offset+32], marketOut); offset += 32
	tradeInput[offset] = 1; offset++ // YES
	big.NewInt(100).FillBytes(tradeInput[offset:offset+32])

	tradeOut, err := governancePrecompile(tradeInput, "0xTrader", state, 1000)
	if err != nil {
		t.Fatalf("Trade failed: %v", err)
	}
	if tradeOut[31] != 1 {
		t.Fatal("Trade should return true")
	}
	t.Logf("✅ Market trade: YES, 100 WAY")
}

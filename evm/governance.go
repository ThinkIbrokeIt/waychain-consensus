package evm

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// ══════════════════════════════════════════════════════════════════════
// Governance Precompile (0x1D)
// Dox_Dev-weighted voting: Direct, Quadratic, Futarchy
// ══════════════════════════════════════════════════════════════════════

const (
	GovernanceSlotProposals byte = 0x01
	GovernanceSlotVotes     byte = 0x02
	GovernanceSlotCredits   byte = 0x03
	GovernanceSlotMarkets   byte = 0x04
)

const (
	VoteTypeDirect    uint8 = 0
	VoteTypeQuadratic uint8 = 1
	VoteTypeFutarchy  uint8 = 2
)

const (
	ProposalStatusPending  uint8 = 0
	ProposalStatusActive   uint8 = 1
	ProposalStatusPassed   uint8 = 2
	ProposalStatusFailed   uint8 = 3
	ProposalStatusExecuted uint8 = 4
)

const (
	DirectBond         = 100
	QuadraticBond      = 500
	FutarchyBond       = 1000
	DirectThreshold    = 50
	QuadraticThreshold = 60
	FutarchyThreshold  = 66
	CreditsPerPeriod   = 9
	PeriodLength       = 2592000
)

const (
	govCreateProposalSelector uint32 = 0xD1E2F3A4
	govVoteSelector           uint32 = 0xE2F3A4B5
	govGetProposalSelector    uint32 = 0xF3A4B5C6
	govGetVoteSelector        uint32 = 0xA4B5C6D7
	govGetCreditsSelector     uint32 = 0xB5C6D7E8
	govFinalizeSelector       uint32 = 0xC6D7E8F9
	govCreateMarketSelector   uint32 = 0xD7E8F9A0
	govTradeMarketSelector    uint32 = 0xE8F9A0B1
)

func governancePrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("Governance: input too short")
	}

	sel := selectorBytes(input)

	switch sel {
	case govCreateProposalSelector:
		return govCreateProposal(input, caller, state, blockNum)
	case govVoteSelector:
		return govVote(input, caller, state, blockNum)
	case govGetProposalSelector:
		return govGetProposal(input, caller, state)
	case govGetVoteSelector:
		return govGetVote(input, caller, state)
	case govGetCreditsSelector:
		return govGetCredits(input, caller, state, blockNum)
	case govFinalizeSelector:
		return govFinalize(input, caller, state, blockNum)
	case govCreateMarketSelector:
		return govCreateMarket(input, caller, state, blockNum)
	case govTradeMarketSelector:
		return govTradeMarket(input, caller, state, blockNum)
	default:
		return nil, fmt.Errorf("Governance: unknown selector 0x%08X", sel)
	}
}

func govCreateProposal(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+1+32+32+20+32 {
		return nil, fmt.Errorf("Governance: createProposal input too short")
	}

	offset := 4
	voteType := input[offset]; offset++
	titleHash := input[offset : offset+32]; offset += 32
	descriptionHash := input[offset : offset+32]; offset += 32
	target := input[offset : offset+20]; offset += 20
	calldataLen := readBigInt(readSlot(input, offset)).Uint64(); offset += 32

	if offset+int(calldataLen) > len(input) {
		return nil, fmt.Errorf("Governance: calldata exceeds input length")
	}
	calldata := input[offset : offset+int(calldataLen)]

	proposalID := generateProposalID(titleHash, caller, blockNum)

	addr := PrecompileAddrHex(0x1D)
	acc := state.GetOrCreateAccount(addr)
	propKey := govProposalKey(proposalID[:])

	var slot [32]byte
	slot[0] = voteType
	slot[1] = ProposalStatusActive
	copy(slot[2:32], titleHash[0:30])
	acc.Storage[propKey] = slot

	descKey := govDescriptionKey(proposalID[:])
	var descSlot [32]byte
	copy(descSlot[:], descriptionHash)
	acc.Storage[descKey] = descSlot

	targetKey := govTargetKey(proposalID[:])
	var targetSlot [32]byte
	copy(targetSlot[0:20], target)
	acc.Storage[targetKey] = targetSlot

	calldataKey := govCalldataKey(proposalID[:])
	var calldataSlot [32]byte
	copy(calldataSlot[0:min(32, len(calldata))], calldata)
	acc.Storage[calldataKey] = calldataSlot

	votesKey := govVotesKey(proposalID[:])
	var votesSlot [32]byte
	acc.Storage[votesKey] = votesSlot

	state.AddLog(addr, [][32]byte{
		storageKey([]byte("ProposalCreated")),
		proposalID,
	}, []byte{voteType}, blockNum)

	return proposalID[:], nil
}

func govVote(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+1+32 {
		return nil, fmt.Errorf("Governance: vote input too short")
	}

	offset := 4
	proposalID := input[offset : offset+32]; offset += 32
	voteDirection := input[offset]; offset++
	credits := readBigInt(readSlot(input, offset))

	addr := PrecompileAddrHex(0x1D)
	acc := state.GetOrCreateAccount(addr)

	propKey := govProposalKey(proposalID)
	propSlot := acc.Storage[propKey]
	if propSlot == [32]byte{} {
		return nil, fmt.Errorf("Governance: proposal not found")
	}
	if propSlot[1] != ProposalStatusActive {
		return nil, fmt.Errorf("Governance: proposal not active")
	}

	voteKey := govVoteRecordKey(proposalID, []byte(caller))
	if acc.Storage[voteKey] != [32]byte{} {
		return nil, fmt.Errorf("Governance: already voted")
	}

	var voteSlot [32]byte
	voteSlot[0] = voteDirection
	credits.FillBytes(voteSlot[1:32])
	acc.Storage[voteKey] = voteSlot

	votesKey := govVotesKey(proposalID)
	votesSlot := acc.Storage[votesKey]

	if voteDirection == 1 {
		yesCount := readBigInt(readSlot(votesSlot[:], 0))
		yesCount = new(big.Int).Add(yesCount, big.NewInt(1))
		yesCount.FillBytes(votesSlot[0:32])
	} else {
		noKey := govNoVotesKey(proposalID)
		noSlot := acc.Storage[noKey]
		noCount := readBigInt(readSlot(noSlot[:], 0))
		noCount = new(big.Int).Add(noCount, big.NewInt(1))
		noCount.FillBytes(noSlot[0:32])
		acc.Storage[noKey] = noSlot
	}

	acc.Storage[votesKey] = votesSlot

	voteType := propSlot[0]
	if voteType == VoteTypeQuadratic {
		creditsKey := govCreditsKey([]byte(caller))
		creditsSlot := acc.Storage[creditsKey]
		currentCredits := readBigInt(readSlot(creditsSlot[:], 0))
		newCredits := new(big.Int).Sub(currentCredits, credits)
		if newCredits.Sign() < 0 {
			return nil, fmt.Errorf("Governance: insufficient credits")
		}
		newCredits.FillBytes(creditsSlot[0:32])
		acc.Storage[creditsKey] = creditsSlot
	}

	_ = blockNum

	state.AddLog(addr, [][32]byte{
		storageKey([]byte("VoteCast")),
		*(*[32]byte)(proposalID),
	}, []byte{voteDirection}, 0)

	return boolResult(true), nil
}

func govGetProposal(input []byte, caller string, state *StateDB) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("Governance: getProposal input too short")
	}

	proposalID := input[4:36]
	addr := PrecompileAddrHex(0x1D)
	acc := state.GetOrCreateAccount(addr)
	propKey := govProposalKey(proposalID)
	propSlot := acc.Storage[propKey]

	if propSlot == [32]byte{} {
		return nil, fmt.Errorf("Governance: proposal not found")
	}

	out := make([]byte, 34)
	out[0] = propSlot[0]
	out[1] = propSlot[1]
	copy(out[2:34], propSlot[2:32])

	_ = caller
	return out, nil
}

func govGetVote(input []byte, caller string, state *StateDB) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("Governance: getVote input too short")
	}

	proposalID := input[4:36]
	addr := PrecompileAddrHex(0x1D)
	acc := state.GetOrCreateAccount(addr)
	voteKey := govVoteRecordKey(proposalID, []byte(caller))
	voteSlot := acc.Storage[voteKey]

	if voteSlot == [32]byte{} {
		return nil, fmt.Errorf("Governance: vote not found")
	}

	out := make([]byte, 33)
	out[0] = voteSlot[0]
	copy(out[1:33], voteSlot[1:32])

	return out, nil
}

func govGetCredits(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	addr := PrecompileAddrHex(0x1D)
	acc := state.GetOrCreateAccount(addr)
	creditsKey := govCreditsKey([]byte(caller))
	creditsSlot := acc.Storage[creditsKey]

	credits := readBigInt(readSlot(creditsSlot[:], 0))
	_ = blockNum

	out := make([]byte, 32)
	credits.FillBytes(out)
	return out, nil
}

func govFinalize(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("Governance: finalize input too short")
	}

	proposalID := input[4:36]
	addr := PrecompileAddrHex(0x1D)
	acc := state.GetOrCreateAccount(addr)

	propKey := govProposalKey(proposalID)
	propSlot := acc.Storage[propKey]
	if propSlot == [32]byte{} {
		return nil, fmt.Errorf("Governance: proposal not found")
	}
	if propSlot[1] != ProposalStatusActive {
		return nil, fmt.Errorf("Governance: proposal not active")
	}

	voteType := propSlot[0]

	votesKey := govVotesKey(proposalID)
	votesSlot := acc.Storage[votesKey]
	yesVotes := readBigInt(readSlot(votesSlot[:], 0))

	noKey := govNoVotesKey(proposalID)
	noSlot := acc.Storage[noKey]
	noVotes := readBigInt(readSlot(noSlot[:], 0))

	totalVotes := new(big.Int).Add(yesVotes, noVotes)

	var threshold uint64
	switch voteType {
	case VoteTypeDirect:
		threshold = DirectThreshold
	case VoteTypeQuadratic:
		threshold = QuadraticThreshold
	case VoteTypeFutarchy:
		threshold = FutarchyThreshold
	}

	passed := false
	if totalVotes.Sign() > 0 {
		yesPct := new(big.Int).Mul(yesVotes, big.NewInt(100))
		yesPct = yesPct.Div(yesPct, totalVotes)
		if yesPct.Uint64() > threshold {
			passed = true
		}
	}

	if passed {
		propSlot[1] = ProposalStatusPassed
	} else {
		propSlot[1] = ProposalStatusFailed
	}
	acc.Storage[propKey] = propSlot

	_ = caller

	state.AddLog(addr, [][32]byte{
		storageKey([]byte("ProposalFinalized")),
		*(*[32]byte)(proposalID),
	}, boolToBytes(passed), blockNum)

	return boolResult(passed), nil
}

func govCreateMarket(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+32 {
		return nil, fmt.Errorf("Governance: createMarket input too short")
	}

	offset := 4
	proposalID := input[offset : offset+32]; offset += 32
	questionHash := input[offset : offset+32]; offset += 32

	marketID := generateMarketID(proposalID, blockNum)

	addr := PrecompileAddrHex(0x1D)
	acc := state.GetOrCreateAccount(addr)
	marketKey := govMarketKey(marketID[:])

	var slot [32]byte
	copy(slot[0:32], questionHash)
	acc.Storage[marketKey] = slot

	_ = caller

	state.AddLog(addr, [][32]byte{
		storageKey([]byte("MarketCreated")),
		marketID,
	}, []byte{1}, blockNum)

	return marketID[:], nil
}

func govTradeMarket(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+1+32 {
		return nil, fmt.Errorf("Governance: tradeMarket input too short")
	}

	offset := 4
	marketID := input[offset : offset+32]; offset += 32
	side := input[offset]; offset++
	amount := readBigInt(readSlot(input, offset))

	addr := PrecompileAddrHex(0x1D)
	acc := state.GetOrCreateAccount(addr)

	tradeKey := govTradeKey(marketID, []byte(caller))
	var tradeSlot [32]byte
	tradeSlot[0] = side
	amount.FillBytes(tradeSlot[1:32])
	acc.Storage[tradeKey] = tradeSlot

	_ = blockNum

	state.AddLog(addr, [][32]byte{
		storageKey([]byte("MarketTrade")),
		*(*[32]byte)(marketID),
	}, []byte{side}, 0)

	return boolResult(true), nil
}

func govProposalKey(id []byte) [32]byte {
	return storageKey(append([]byte{GovernanceSlotProposals}, id...))
}

func govDescriptionKey(id []byte) [32]byte {
	return storageKey(append([]byte{0x10}, id...))
}

func govTargetKey(id []byte) [32]byte {
	return storageKey(append([]byte{0x11}, id...))
}

func govCalldataKey(id []byte) [32]byte {
	return storageKey(append([]byte{0x12}, id...))
}

func govVotesKey(id []byte) [32]byte {
	return storageKey(append([]byte{0x13}, id...))
}

func govVoteRecordKey(proposalID, voter []byte) [32]byte {
	return storageKey(append(append([]byte{GovernanceSlotVotes}, proposalID...), voter...))
}

func govCreditsKey(voter []byte) [32]byte {
	return storageKey(append([]byte{GovernanceSlotCredits}, voter...))
}

func govMarketKey(id []byte) [32]byte {
	return storageKey(append([]byte{GovernanceSlotMarkets}, id...))
}

func govNoVotesKey(proposalID []byte) [32]byte {
	return storageKey(append([]byte{0x15}, proposalID...))
}

func govTradeKey(marketID, trader []byte) [32]byte {
	return storageKey(append(append([]byte{0x14}, marketID...), trader...))
}

func generateProposalID(titleHash []byte, proposer string, blockNum uint64) [32]byte {
	data := append(titleHash, []byte(proposer)...)
	data = append(data, []byte(fmt.Sprintf("%d", blockNum))...)
	return sha256.Sum256(data)
}

func generateMarketID(proposalID []byte, blockNum uint64) [32]byte {
	data := append(proposalID, []byte(fmt.Sprintf("%d", blockNum))...)
	return sha256.Sum256(data)
}

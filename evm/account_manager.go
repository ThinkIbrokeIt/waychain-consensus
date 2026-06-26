package evm

import (
	"fmt"
)

// ══════════════════════════════════════════════════════════════════════
// Account Manager Precompile (0x1B)
// 3-stage account model: Stage 0 (onboarding), 1 (standard), 2 (self-custody)
// ══════════════════════════════════════════════════════════════════════

const (
	AccountSlotStage       byte = 0x01
	AccountSlotSessionKeys byte = 0x02
	AccountSlotGuardians   byte = 0x03
)

const (
	StageOnboarding  uint8 = 0
	StageStandard    uint8 = 1
	StageSelfCustody uint8 = 2
)

const Stage1WaitingPeriod = 2592000 // 30 days at 1s blocks

const (
	accountGetStageSelector      uint32 = 0xB1C2D3E4
	accountGraduateSelector      uint32 = 0xC2D3E4F5
	accountAdvanceSelector       uint32 = 0xD3E4F5A6
	accountRotateKeySelector     uint32 = 0xE4F5A6B7
	accountCreateSessionSelector uint32 = 0xF5A6B7C8
	accountRevokeSessionSelector uint32 = 0xA6B7C8D9
	accountGetSessionSelector    uint32 = 0xB7C8D9E0
	accountSetGuardianSelector   uint32 = 0xC8D9E0F1
	accountGetGuardianSelector   uint32 = 0xD9E0F1A2
	accountFreezeSelector        uint32 = 0xE0F1A2B3
	accountUnfreezeSelector      uint32 = 0xF1A2B3C4
)

func accountManagerPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("AccountManager: input too short")
	}

	sel := selectorBytes(input)

	switch sel {
	case accountGetStageSelector:
		return accountGetStage(input, caller, state)
	case accountGraduateSelector:
		return accountGraduate(input, caller, state, blockNum)
	case accountAdvanceSelector:
		return accountAdvance(input, caller, state, blockNum)
	case accountRotateKeySelector:
		return accountRotateKey(input, caller, state, blockNum)
	case accountCreateSessionSelector:
		return accountCreateSession(input, caller, state, blockNum)
	case accountRevokeSessionSelector:
		return accountRevokeSession(input, caller, state)
	case accountGetSessionSelector:
		return accountGetSession(input, caller, state)
	case accountSetGuardianSelector:
		return accountSetGuardian(input, caller, state)
	case accountGetGuardianSelector:
		return accountGetGuardianCount(input, caller, state)
	case accountFreezeSelector:
		return accountFreeze(input, caller, state, blockNum)
	case accountUnfreezeSelector:
		return accountUnfreeze(input, caller, state)
	default:
		return nil, fmt.Errorf("AccountManager: unknown selector 0x%08X", sel)
	}
}

func accountGetStage(input []byte, caller string, state *StateDB) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("AccountManager: getStage input too short")
	}
	accountAddr := input[4:36]
	addr := PrecompileAddrHex(0x1B)
	acc := state.GetOrCreateAccount(addr)
	stageKey := accountStageKey(accountAddr)
	stageSlot := acc.Storage[stageKey]
	stage := uint8(0)
	if stageSlot != [32]byte{} {
		stage = stageSlot[0]
	}
	return []byte{stage}, nil
}

func accountGraduate(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	addr := PrecompileAddrHex(0x1B)
	acc := state.GetOrCreateAccount(addr)
	stageKey := accountStageKey([]byte(caller))
	stageSlot := acc.Storage[stageKey]
	currentStage := uint8(0)
	if stageSlot != [32]byte{} {
		currentStage = stageSlot[0]
	}
	if currentStage != StageOnboarding {
		return nil, fmt.Errorf("AccountManager: can only graduate from Stage 0")
	}
	stageSlot[0] = StageStandard
	encodeBlockNumber(stageSlot, 1, blockNum)
	acc.Storage[stageKey] = stageSlot
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("StageGraduated")),
		stringToHash([]byte(caller)),
	}, []byte{StageStandard}, blockNum)
	return boolResult(true), nil
}

func accountAdvance(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	addr := PrecompileAddrHex(0x1B)
	acc := state.GetOrCreateAccount(addr)
	stageKey := accountStageKey([]byte(caller))
	stageSlot := acc.Storage[stageKey]
	currentStage := uint8(0)
	if stageSlot != [32]byte{} {
		currentStage = stageSlot[0]
	}
	if currentStage != StageStandard {
		return nil, fmt.Errorf("AccountManager: can only advance from Stage 1")
	}
	stageSince := decodeBlockNumber(stageSlot, 1)
	if blockNum < stageSince+Stage1WaitingPeriod {
		return nil, fmt.Errorf("AccountManager: must wait 30 days in Stage 1")
	}
	stageSlot[0] = StageSelfCustody
	acc.Storage[stageKey] = stageSlot
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("StageAdvanced")),
		stringToHash([]byte(caller)),
	}, []byte{StageSelfCustody}, blockNum)
	return boolResult(true), nil
}

func accountRotateKey(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("AccountManager: rotateKey input too short")
	}
	newKey := input[4:36]
	addr := PrecompileAddrHex(0x1B)
	acc := state.GetOrCreateAccount(addr)
	keyKey := accountKeyKey([]byte(caller))
	var slot [32]byte
	copy(slot[0:32], newKey)
	acc.Storage[keyKey] = slot
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("KeyRotated")),
		stringToHash([]byte(caller)),
	}, newKey, blockNum)
	return boolResult(true), nil
}

func accountCreateSession(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4+32+32+4 {
		return nil, fmt.Errorf("AccountManager: createSession input too short")
	}
	offset := 4
	keyID := input[offset : offset+32]; offset += 32
	sessionPubKey := input[offset : offset+32]; offset += 32
	offset += 32 // skip permissions
	offset += 32 // skip maxSpend
	expiryBlock := uint32(input[offset])<<24 | uint32(input[offset+1])<<16 | uint32(input[offset+2])<<8 | uint32(input[offset+3])

	addr := PrecompileAddrHex(0x1B)
	acc := state.GetOrCreateAccount(addr)
	sessionKey := accountSessionKey([]byte(caller), keyID)
	var slot [32]byte
	slot[0] = 0x00
	copy(slot[1:32], sessionPubKey)
	slot[30] = byte(expiryBlock >> 8)
	slot[31] = byte(expiryBlock)
	acc.Storage[sessionKey] = slot
	_ = blockNum
	return boolResult(true), nil
}

func accountRevokeSession(input []byte, caller string, state *StateDB) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("AccountManager: revokeSession input too short")
	}
	keyID := input[4:36]
	addr := PrecompileAddrHex(0x1B)
	acc := state.GetOrCreateAccount(addr)
	sessionKey := accountSessionKey([]byte(caller), keyID)
	sessionSlot := acc.Storage[sessionKey]
	if sessionSlot == [32]byte{} {
		return nil, fmt.Errorf("AccountManager: session key not found")
	}
	sessionSlot[0] = 0xFF
	acc.Storage[sessionKey] = sessionSlot
	return boolResult(true), nil
}

func accountGetSession(input []byte, caller string, state *StateDB) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("AccountManager: getSession input too short")
	}
	keyID := input[4:36]
	addr := PrecompileAddrHex(0x1B)
	acc := state.GetOrCreateAccount(addr)
	sessionKey := accountSessionKey([]byte(caller), keyID)
	sessionSlot := acc.Storage[sessionKey]
	if sessionSlot == [32]byte{} {
		return nil, fmt.Errorf("AccountManager: session key not found")
	}
	out := make([]byte, 33)
	copy(out[0:32], sessionSlot[1:32])
	out[32] = sessionSlot[0]
	return out, nil
}

func accountSetGuardian(input []byte, caller string, state *StateDB) ([]byte, error) {
	if len(input) < 4+20+1 {
		return nil, fmt.Errorf("AccountManager: setGuardian input too short")
	}
	offset := 4
	var guardianAddr [20]byte
	copy(guardianAddr[:], input[offset:offset+20]); offset += 20
	weight := input[offset]

	addr := PrecompileAddrHex(0x1B)
	acc := state.GetOrCreateAccount(addr)
	countKey := accountGuardianCountKey([]byte(caller))
	countSlot := acc.Storage[countKey]
	guardianCount := uint8(0)
	if countSlot != [32]byte{} {
		guardianCount = countSlot[0]
	}
	if guardianCount >= 10 {
		return nil, fmt.Errorf("AccountManager: max 10 guardians")
	}
	guardianKey := accountGuardianKey([]byte(caller), guardianCount)
	var slot [32]byte
	copy(slot[0:20], guardianAddr[:])
	slot[20] = weight
	acc.Storage[guardianKey] = slot
	countSlot[0] = guardianCount + 1
	acc.Storage[countKey] = countSlot
	return boolResult(true), nil
}

func accountGetGuardianCount(input []byte, caller string, state *StateDB) ([]byte, error) {
	if len(input) < 4+32 {
		return nil, fmt.Errorf("AccountManager: getGuardianCount input too short")
	}
	accountAddr := input[4:36]
	addr := PrecompileAddrHex(0x1B)
	acc := state.GetOrCreateAccount(addr)
	countKey := accountGuardianCountKey(accountAddr)
	countSlot := acc.Storage[countKey]
	count := uint8(0)
	if countSlot != [32]byte{} {
		count = countSlot[0]
	}
	return []byte{count}, nil
}

func accountFreeze(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	addr := PrecompileAddrHex(0x1B)
	acc := state.GetOrCreateAccount(addr)
	stageKey := accountStageKey([]byte(caller))
	stageSlot := acc.Storage[stageKey]
	stageSlot[31] = 0x01
	acc.Storage[stageKey] = stageSlot
	state.AddLog(addr, [][32]byte{
		storageKey([]byte("AccountFrozen")),
		stringToHash([]byte(caller)),
	}, []byte{0x01}, blockNum)
	return boolResult(true), nil
}

func accountUnfreeze(input []byte, caller string, state *StateDB) ([]byte, error) {
	addr := PrecompileAddrHex(0x1B)
	acc := state.GetOrCreateAccount(addr)
	stageKey := accountStageKey([]byte(caller))
	stageSlot := acc.Storage[stageKey]
	if stageSlot[31] != 0x01 {
		return nil, fmt.Errorf("AccountManager: account not frozen")
	}
	stageSlot[31] = 0x00
	acc.Storage[stageKey] = stageSlot
	return boolResult(true), nil
}

func accountStageKey(accountAddr []byte) [32]byte {
	return storageKey(append([]byte{AccountSlotStage}, accountAddr...))
}

func accountKeyKey(accountAddr []byte) [32]byte {
	return storageKey(append([]byte{0x05}, accountAddr...))
}

func accountSessionKey(accountAddr, keyID []byte) [32]byte {
	return storageKey(append(append([]byte{AccountSlotSessionKeys}, accountAddr...), keyID...))
}

func accountGuardianKey(accountAddr []byte, idx uint8) [32]byte {
	return storageKey(append(append([]byte{AccountSlotGuardians}, accountAddr...), idx))
}

func accountGuardianCountKey(accountAddr []byte) [32]byte {
	return storageKey(append([]byte{0x06}, accountAddr...))
}

func encodeBlockNumber(slot [32]byte, startByte int, val uint64) {
	slot[startByte+0] = byte(val >> 56)
	slot[startByte+1] = byte(val >> 48)
	slot[startByte+2] = byte(val >> 40)
	slot[startByte+3] = byte(val >> 32)
	slot[startByte+4] = byte(val >> 24)
	slot[startByte+5] = byte(val >> 16)
	slot[startByte+6] = byte(val >> 8)
	slot[startByte+7] = byte(val)
}

func decodeBlockNumber(slot [32]byte, startByte int) uint64 {
	return uint64(slot[startByte+0])<<56 | uint64(slot[startByte+1])<<48 |
		uint64(slot[startByte+2])<<40 | uint64(slot[startByte+3])<<32 |
		uint64(slot[startByte+4])<<24 | uint64(slot[startByte+5])<<16 |
		uint64(slot[startByte+6])<<8 | uint64(slot[startByte+7])
}

func boolResult(val bool) []byte {
	out := make([]byte, 32)
	if val {
		out[31] = 1
	}
	return out
}

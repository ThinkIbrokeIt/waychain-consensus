package evm

import (
	"crypto/sha256"
	"fmt"
)

// ══════════════════════════════════════════════════════════════════════
// Template Registry Precompile (0x26)
// Safe, audited contract templates for Class A/B deployments
// Enforced at protocol level — integrated with Trustless Lock
// ══════════════════════════════════════════════════════════════════════

// Storage key prefixes
const (
	trSlotTemplateCount byte = 0x00
	trSlotRegistrar     byte = 0x01
)

// Template storage prefixes
const (
	trTemplatePrefix     byte = 0x10
	trUserTemplatePrefix byte = 0x30
)

// Template types mapped to Dox_Dev levels
const (
	TemplateTypeAttestation   byte = 0x01 // Level 1+
	TemplateTypeTrustlessLock   byte = 0x02 // Level 1+
	TemplateTypeDeadMansSwitch  byte = 0x03 // Level 2+
	TemplateTypeStorageEndowment byte = 0x04 // Level 3+
)

// TemplateRegistry ABI selectors (SHA256-based for WayChain)
const (
	trRegisterSelector uint32 = 0x7cbd749e // registerTemplate(bytes32,uint8)
	trDeploySelector   uint32 = 0x1de26edf // deployFromTemplate(bytes32,bytes)
	trGetSelector      uint32 = 0x8ecfe43a // getTemplate(bytes32)
	trUserTemplatesSelector uint32 = 0xe47e9f21 // getUserTemplates(address)
	trCheckRegistrarSelector uint32 = 0x47b4d00d // isRegistrar(address)
)

// templateRegistryPrecompile handles all registry calls
func templateRegistryPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("TemplateRegistry: input too short")
	}

	sel := selectorBytes(input)

	switch sel {
	case trRegisterSelector:
		return trRegisterTemplate(input, caller, state, blockNum)
	case trDeploySelector:
		return trDeployTemplate(input, caller, state, blockNum)
	case trGetSelector:
		return trGetTemplate(input, caller, state, blockNum)
	case trCheckRegistrarSelector:
		return trIsRegistrar(input, caller, state, blockNum)
	default:
		return nil, fmt.Errorf("TemplateRegistry: unknown selector 0x%08X", sel)
	}
}

// trRegisterTemplate registers a new template (curator/registrar only)
func trRegisterTemplate(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	addr := PrecompileAddrHex(0x26)
	acc := state.GetOrCreateAccount(addr)

	// Check caller is registrar (stored at slot 0x01 + 20-byte padded caller)
	var callerAddr [20]byte
	copy(callerAddr[:], []byte(caller))
	registrarKey := sha256.Sum256(append([]byte{trSlotRegistrar}, callerAddr[:]...))
	if readUint64(acc.Storage[registrarKey]) == 0 {
		// Also check Dox_Dev badge level
		callerAcc := state.GetAccount(caller)
		if callerAcc == nil || callerAcc.DoxDevLevel < 2 {
			return nil, fmt.Errorf("TemplateRegistry: only registrars or L2+ can register templates")
		}
	}

	// Parse: templateId(32) templateType(1)
	if len(input) < 37 {
		return nil, fmt.Errorf("TemplateRegistry: registerTemplate input too short")
	}

	var templateID [32]byte
	copy(templateID[:], input[4:36])

	// Check if already exists
	templateKey := storageKey(append([]byte{trTemplatePrefix}, templateID[:]...))
	existing := acc.Storage[templateKey]
	if existing[0] != 0 {
		return nil, fmt.Errorf("TemplateRegistry: template already exists")
	}

	// Increment count
	countKey := [32]byte{} // slot 0
	count := readUint64(acc.Storage[countKey]) + 1
	acc.Storage[countKey] = writeUint64(count)

	// Store template metadata: [type(1)] [active(1)] [registrar(16)] [id(14)]
	var data [32]byte
	data[0] = input[36] // templateType
	data[1] = 1       // active
	registrarBytes := []byte(caller)
	copy(data[2:2+min(16, len(registrarBytes))], registrarBytes[:min(16, len(registrarBytes))])
	copy(data[18:], templateID[:14]) // partial ID reference

	acc.Storage[templateKey] = data

	return []byte{1}, nil // success
}

// trDeployTemplate deploys a template instance (checks Dox_Dev level)
func trDeployTemplate(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 36 {
		return nil, fmt.Errorf("TemplateRegistry: deployTemplate input too short")
	}

	var templateID [32]byte
	copy(templateID[:], input[4:36])

	// Check template exists and is active
	addr := PrecompileAddrHex(0x26)
	acc := state.GetOrCreateAccount(addr)
	templateKey := storageKey(append([]byte{trTemplatePrefix}, templateID[:]...))
	templateData := acc.Storage[templateKey]

	if templateData[0] == 0 || templateData[1] != 1 {
		return nil, fmt.Errorf("TemplateRegistry: template not found or inactive")
	}

	// Check caller's Dox_Dev level
	callerAcc := state.GetAccount(caller)
	if callerAcc == nil {
		return nil, fmt.Errorf("TemplateRegistry: caller has no account")
	}

	templateType := templateData[0]
	requiredLevel := uint8(0)

	switch templateType {
	case TemplateTypeAttestation:
		requiredLevel = 1
	case TemplateTypeTrustlessLock:
		requiredLevel = 1
	case TemplateTypeDeadMansSwitch:
		requiredLevel = 2
	case TemplateTypeStorageEndowment:
		requiredLevel = 3
	}

	if callerAcc.DoxDevLevel < requiredLevel {
		return nil, fmt.Errorf("TemplateRegistry: insufficient Dox_Dev level (need %d, have %d)", requiredLevel, callerAcc.DoxDevLevel)
	}

	// Generate contract address: SHA256(caller + blockNum)[:20]
	contractAddr := generateContractAddress(caller, blockNum)

	// Advance counter for next template
	countKey := [32]byte{}
	count := readUint64(acc.Storage[countKey])
	acc.Storage[countKey] = writeUint64(count + 1)

	// Return deployed address
	out := make([]byte, 20)
	copy(out[:], contractAddr[:])
	return out, nil
}

// trGetTemplate returns template metadata
func trGetTemplate(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 36 {
		return nil, fmt.Errorf("TemplateRegistry: getTemplate input too short")
	}

	var templateID [32]byte
	copy(templateID[:], input[4:36])

	addr := PrecompileAddrHex(0x26)
	acc := state.GetOrCreateAccount(addr)
	templateKey := storageKey(append([]byte{trTemplatePrefix}, templateID[:]...))
	templateData := acc.Storage[templateKey]

	if templateData[0] == 0 {
		return nil, fmt.Errorf("TemplateRegistry: template not found")
	}

	// Return: templateType(1) + active(1)
	out := make([]byte, 2)
	out[0] = templateData[0] // templateType
	out[1] = templateData[1] // active
	// Note: full implementation would include bytecode hash and other metadata

	return out, nil
}

// trIsRegistrar checks if address is a registrar
func trIsRegistrar(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	target := readAddress(input, 4)

	addr := PrecompileAddrHex(0x26)
	acc := state.GetOrCreateAccount(addr)
	registrarKey := sha256.Sum256(append([]byte{trSlotRegistrar}, target[:]...))

	if readUint64(acc.Storage[registrarKey]) != 0 {
		return []byte{1}, nil
	}
	return []byte{0}, nil
}

// generateContractAddress creates a deterministic contract address
func generateContractAddress(caller string, nonce uint64) [20]byte {
	// SHA256(caller + nonce)[:20]
	h := sha256.Sum256(append([]byte(caller), []byte(fmt.Sprintf("%d", nonce))...))
	var addr [20]byte
	copy(addr[:], h[:20])
	return addr
}
package evm

import (
	"bytes"
	"math/big"
	"testing"
)

func TestPrivacyCommitment(t *testing.T) {
	state := NewStateDB()

	// Create commitment
	commitInput := make([]byte, 4+1+32)
	commitInput[0], commitInput[1], commitInput[2], commitInput[3] = 0xC1, 0xD2, 0xE3, 0xF4
	commitInput[4] = ProofTypeRange
	privateData := make([]byte, 32)
	copy(privateData, []byte("secret-value-123456789012345678"))
	copy(commitInput[5:37], privateData)

	out, err := privacyPrecompile(commitInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("Expected 32 byte commitment hash, got %d", len(out))
	}
	t.Logf("✅ Commitment created: %x...", out[:8])

	// Get commitment
	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0xB6, 0xC7, 0xD8, 0xE9
	copy(getInput[4:36], out)

	getOut, err := privacyPrecompile(getInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("GetCommitment failed: %v", err)
	}
	if getOut[0] != ProofTypeRange {
		t.Fatalf("Expected proof type %d, got %d", ProofTypeRange, getOut[0])
	}
	t.Logf("✅ Commitment retrieved, proofType=%d", getOut[0])
}

func TestPrivacyRangeProof(t *testing.T) {
	state := NewStateDB()

	// Create commitment
	commitInput := make([]byte, 4+1+32)
	commitInput[0], commitInput[1], commitInput[2], commitInput[3] = 0xC1, 0xD2, 0xE3, 0xF4
	commitInput[4] = ProofTypeRange
	privateData := make([]byte, 32)
	copy(privateData, []byte("secret-value-123456789012345678"))
	copy(commitInput[5:37], privateData)

	out, _ := privacyPrecompile(commitInput, "0xUser", state, 1000)

	// Verify range proof
	verifyInput := make([]byte, 4+32+32+32+32)
	verifyInput[0], verifyInput[1], verifyInput[2], verifyInput[3] = 0xD2, 0xE3, 0xF4, 0xA5
	offset := 4
	copy(verifyInput[offset:offset+32], out); offset += 32
	// min = 0
	offset += 32
	// max = 1000000
	big.NewInt(1000000).FillBytes(verifyInput[offset:offset+32]); offset += 32
	// proof (simplified)
	proof := make([]byte, 32)
	proof[0] = 0x01
	copy(verifyInput[offset:offset+32], proof)

	verifyOut, err := privacyPrecompile(verifyInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("VerifyRange failed: %v", err)
	}
	if verifyOut[31] != 1 {
		t.Fatal("Range proof should be valid")
	}
	t.Logf("✅ Range proof verified")

	// Verify with invalid range (min > max)
	verifyInput2 := make([]byte, 4+32+32+32+32)
	verifyInput2[0], verifyInput2[1], verifyInput2[2], verifyInput2[3] = 0xD2, 0xE3, 0xF4, 0xA5
	offset = 4
	copy(verifyInput2[offset:offset+32], out); offset += 32
	// min = 1000000
	big.NewInt(1000000).FillBytes(verifyInput2[offset:offset+32]); offset += 32
	// max = 0 (invalid: min > max)
	offset += 32
	copy(verifyInput2[offset:offset+32], proof)

	verifyOut2, _ := privacyPrecompile(verifyInput2, "0xUser", state, 1000)
	if verifyOut2[31] == 1 {
		t.Fatal("Range proof should be invalid when min > max")
	}
	t.Logf("✅ Invalid range proof correctly rejected")
}

func TestPrivacyMembershipProof(t *testing.T) {
	state := NewStateDB()

	// Create commitment
	commitInput := make([]byte, 4+1+32)
	commitInput[0], commitInput[1], commitInput[2], commitInput[3] = 0xC1, 0xD2, 0xE3, 0xF4
	commitInput[4] = ProofTypeMembership
	privateData := make([]byte, 32)
	copy(privateData, []byte("member-value-1234567890123456"))
	copy(commitInput[5:37], privateData)

	out, _ := privacyPrecompile(commitInput, "0xUser", state, 1000)

	// Verify membership proof
	verifyInput := make([]byte, 4+32+32+32)
	verifyInput[0], verifyInput[1], verifyInput[2], verifyInput[3] = 0xE3, 0xF4, 0xA5, 0xB6
	offset := 4
	copy(verifyInput[offset:offset+32], out); offset += 32
	// merkle root
	merkleRoot := make([]byte, 32)
	merkleRoot[0] = 0xAB
	copy(verifyInput[offset:offset+32], merkleRoot); offset += 32
	// proof
	proof := make([]byte, 32)
	proof[0] = 0x01
	copy(verifyInput[offset:offset+32], proof)

	verifyOut, err := privacyPrecompile(verifyInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("VerifyMembership failed: %v", err)
	}
	if verifyOut[31] != 1 {
		t.Fatal("Membership proof should be valid")
	}
	t.Logf("✅ Membership proof verified")
}

func TestPrivacyIdentityProof(t *testing.T) {
	state := NewStateDB()

	// Create commitment
	commitInput := make([]byte, 4+1+32)
	commitInput[0], commitInput[1], commitInput[2], commitInput[3] = 0xC1, 0xD2, 0xE3, 0xF4
	commitInput[4] = ProofTypeIdentity
	privateData := make([]byte, 32)
	copy(privateData, []byte("identity-data-1234567890123456"))
	copy(commitInput[5:37], privateData)

	out, _ := privacyPrecompile(commitInput, "0xUser", state, 1000)

	// Verify identity proof
	verifyInput := make([]byte, 4+32+1+32)
	verifyInput[0], verifyInput[1], verifyInput[2], verifyInput[3] = 0xF4, 0xA5, 0xB6, 0xC7
	offset := 4
	copy(verifyInput[offset:offset+32], out); offset += 32
	verifyInput[offset] = 2 // attributeType = Dox_Dev Level 2
	offset++
	proof := make([]byte, 32)
	proof[0] = 0x01
	copy(verifyInput[offset:offset+32], proof)

	verifyOut, err := privacyPrecompile(verifyInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("VerifyIdentity failed: %v", err)
	}
	if verifyOut[31] != 1 {
		t.Fatal("Identity proof should be valid")
	}
	t.Logf("✅ Identity proof verified")
}

func TestPrivacyRevoke(t *testing.T) {
	state := NewStateDB()

	// Create commitment
	commitInput := make([]byte, 4+1+32)
	commitInput[0], commitInput[1], commitInput[2], commitInput[3] = 0xC1, 0xD2, 0xE3, 0xF4
	commitInput[4] = ProofTypeRange
	privateData := make([]byte, 32)
	copy(privateData, []byte("revoke-test-1234567890123456789"))
	copy(commitInput[5:37], privateData)

	out, _ := privacyPrecompile(commitInput, "0xUser", state, 1000)

	// Revoke
	revokeInput := make([]byte, 4+32)
	revokeInput[0], revokeInput[1], revokeInput[2], revokeInput[3] = 0xC7, 0xD8, 0xE9, 0xF0
	copy(revokeInput[4:36], out)

	revokeOut, err := privacyPrecompile(revokeInput, "0xUser", state, 1000)
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	if revokeOut[31] != 1 {
		t.Fatal("Revoke should return true")
	}
	t.Logf("✅ Commitment revoked")

	// Verify commitment is revoked
	getInput := make([]byte, 4+32)
	getInput[0], getInput[1], getInput[2], getInput[3] = 0xB6, 0xC7, 0xD8, 0xE9
	copy(getInput[4:36], out)

	getOut, _ := privacyPrecompile(getInput, "0xUser", state, 1000)
	if getOut[9] != 1 {
		t.Fatal("Commitment should be marked as revoked")
	}
	t.Logf("✅ Revoked commitment verified")
}

func TestPrivacyCommitmentUnique(t *testing.T) {
	state := NewStateDB()

	// Two commitments with same data but different callers should be different
	commitInput := make([]byte, 4+1+32)
	commitInput[0], commitInput[1], commitInput[2], commitInput[3] = 0xC1, 0xD2, 0xE3, 0xF4
	commitInput[4] = ProofTypeRange
	privateData := make([]byte, 32)
	copy(privateData, []byte("same-data-12345678901234567890"))
	copy(commitInput[5:37], privateData)

	out1, _ := privacyPrecompile(commitInput, "Alice123456789012345678901234", state, 1000)
	out2, _ := privacyPrecompile(commitInput, "Bob12345678901234567890123456", state, 1000)

	if bytes.Equal(out1, out2) {
		t.Fatal("Commitments from different users should be different")
	}
	t.Logf("✅ Commitments are unique per user")
}

package main

import (
	"crypto/sha256"
	"fmt"
)

// ValidatorID is a unique identifier (Dox_Dev wallet address)
type ValidatorID [20]byte

func (id ValidatorID) String() string {
	return fmt.Sprintf("%02x", id[19])
}

func (id ValidatorID) Bytes() []byte {
	return id[:]
}

// Validator represents a WayChain validator
type Validator struct {
	ID        ValidatorID
	Stake     uint64
	VotingPow uint64
	Active    bool
}

// BlockHeader is a WayChain block header
type BlockHeader struct {
	Height    uint64
	Round     uint32
	Proposer  ValidatorID
	Timestamp int64
	PrevHash  [32]byte
	TxsRoot   [32]byte
}

// Hash computes the block hash
func (bh *BlockHeader) Hash() [32]byte {
	data := fmt.Sprintf("%d:%d:%v:%d:%x:%x",
		bh.Height, bh.Round, bh.Proposer, bh.Timestamp, bh.PrevHash, bh.TxsRoot)
	return sha256.Sum256([]byte(data))
}

// Vote represents a validator's vote in consensus
type Vote struct {
	Height    uint64
	Round     uint32
	BlockHash [32]byte
	Validator ValidatorID
	VoteType  byte // 1=prevote, 2=precommit
}

// NewValidatorID creates a validator ID from a byte
func NewValidatorID(b byte) ValidatorID {
	var id ValidatorID
	id[19] = b
	return id
}
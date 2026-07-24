// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"fmt"
	"time"
)

// RunP2PNode starts a long-running P2P node within the daemon.
// It connects to seed peers and continuously gossips blocks and transactions.
func RunP2PNode(nodeID, listenAddr string, seedPeers []string, chain *Chain) *P2PNode {
	node := NewP2PNode(nodeID, listenAddr)

	// Set up callbacks
	node.OnTx = func(tx Transaction) {
		// Add received transaction to pool (avoid duplicates)
		chain.Pool.Add(tx)
	}

	node.OnBlock = func(block BlockWithTx) {
		// In a real implementation: validate block, apply to local state
		// For now, just log receipt
		_ = block
	}

	node.OnVote = func(vote interface{}, from string) {
		// Consensus vote handling — future
		_ = vote
		_ = from
	}

	// Start listening
	if err := node.Start(); err != nil {
		fmt.Printf("  ❌ P2P start failed: %v\n", err)
		return nil
	}

	// Connect to seed peers
	for _, addr := range seedPeers {
		if addr == listenAddr {
			continue // Don't connect to self
		}
		go func(peerAddr string) {
			time.Sleep(500 * time.Millisecond) // stagger connections
			if err := node.Connect(peerAddr); err != nil {
				fmt.Printf("  ⚠️  P2P connect to %s: %v\n", peerAddr, err)
			}
		}(addr)
	}

	return node
}

// BroadcastBlock sends a new block to all P2P peers
func BroadcastBlock(node *P2PNode, block *BlockWithTx) {
	if node == nil {
		return
	}
	msg := P2PMessage{
		Type:    MsgBlock,
		From:    node.ID,
		Seq:     node.nextSeq(),
		Payload: []byte(fmt.Sprintf("block:#%d:hash:%x:txs:%d", block.Height, block.Hash[:4], len(block.Transactions))),
	}
	node.Broadcast(msg)
}

// BroadcastTransaction sends a new transaction to all P2P peers
func BroadcastTransaction(node *P2PNode, tx *Transaction) {
	if node == nil {
		return
	}
	msg := P2PMessage{
		Type:    MsgTx,
		From:    node.ID,
		Seq:     node.nextSeq(),
		Payload: []byte(fmt.Sprintf("tx:%x", tx.Hash[:4])),
	}
	node.Broadcast(msg)
}

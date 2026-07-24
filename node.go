// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// runAsNode starts a persistent validator node (used by devnet)
func runAsNode() {
	nodeID := getEnv("WAYCHAIN_NODE_ID", "devnet-val-1")
	listenAddr := getEnv("WAYCHAIN_LISTEN", ":9100")
	peers := getEnv("WAYCHAIN_PEERS", "")

	fmt.Printf("═══ WayChain Node: %s ═══\n", nodeID)
	fmt.Printf("  Listen: %s\n", listenAddr)
	fmt.Printf("  Peers: %s\n", peers)
	fmt.Println()

	// Start P2P
	node := NewP2PNode(nodeID, listenAddr)
	err := node.Start()
	if err != nil {
		fmt.Printf("❌ Failed to start: %v\n", err)
		os.Exit(1)
	}

	// Connect to peers
	if peers != "" {
		for len(peers) > 0 {
			end := 0
			for i, c := range peers {
				if c == ',' {
					end = i
					break
				}
				end = i + 1
			}
			addr := peers[:end]
			if addr != "" {
				err := node.Connect(addr)
				if err != nil {
					fmt.Printf("  ⚠️  Failed to connect to %s: %v\n", addr, err)
				}
			}
			if end >= len(peers) {
				break
			}
			peers = peers[end+1:]
		}
	}

	// Start the chain
	chain := NewChain()

	// Listen for incoming messages
	go func() {
		for msg := range node.Incoming {
			switch msg.Type {
			case MsgTx:
				fmt.Printf("  📥 [%s] Received tx\n", nodeID)
			case MsgBlock:
				fmt.Printf("  📦 [%s] Received block\n", nodeID)
			case MsgVote:
				fmt.Printf("  🗳️  [%s] Received vote\n", nodeID)
			}
		}
	}()

	// Produce blocks periodically
	go func() {
		for {
			time.Sleep(1 * time.Second)
			// Simplified block production
			_ = chain
			fmt.Printf("  💚 [%s] heartbeat | %d peers\n", nodeID, len(node.Peers))
		}
	}()

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\nShutting down...")
	node.Stop()
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
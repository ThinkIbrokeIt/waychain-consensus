// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	st "github.com/ThinkIbrokeIt/waychain-consensus/store"
)

// RunCLI handles command-line arguments for the waychain binary
func RunCLI() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	cmd := os.Args[1]
	switch cmd {
	case "demo":
		runAllDemos()

	case "init":
		genesisPath := "genesis.json"
		if len(os.Args) > 2 {
			genesisPath = os.Args[2]
		}

		// Use DefaultGenesis() which now has FIXED addresses (real precompile keys)
		config := DefaultGenesis()
		if _, err := os.Stat(genesisPath); err == nil {
			loaded, err := LoadGenesis(genesisPath)
			if err == nil {
				config = *loaded
			}
		}

		gs := InitGenesis(config)
		gs.ProduceGenesisBlock()

		// Save the genesis that was ACTUALLY used (with corrected addresses)
		// Note: This writes the config back with the fixed state
		_ = gs // gs.Chain.State now has correct state; config already has fixed addresses
		fmt.Println("  ✅ Chain initialized to genesis state")

	case "start":
		runNode()

	case "devnet":
		fmt.Println("Running devnet bootstrap...")
		fmt.Println("  Use: bash devnet.sh [num_nodes]")

	case "version":
		fmt.Println("WayChain v0.1.0")
		fmt.Println("\"Actually Decentralized\"")

	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printUsage()
	}
}

func printUsage() {
	fmt.Println("WayChain — Actually Decentralized")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  waychain demo           Run all demos (consensus, EVM, P2P, oracle)")
	fmt.Println("  waychain init [file]    Initialize chain from genesis.json")
	fmt.Println("  waychain start [file]   Start a validator node")
	fmt.Println("  waychain devnet         Launch a multi-node devnet")
	fmt.Println("  waychain version        Show version info")
	fmt.Println()
}

// ── Daemon Mode ──

func runNode() {
	// Default paths
	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".waychain")
	dbPath := filepath.Join(dataDir, "chain.db")
	genesisPath := "genesis.json"
	if len(os.Args) > 2 {
		genesisPath = os.Args[2]
	}

	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" WayChain Node — Starting")
	fmt.Println("═══════════════════════════════════════════")

	// Set up structured logging
	SetupLogger()

	fmt.Printf("  Data dir: %s\n", dataDir)
	fmt.Printf("  Database: %s\n", dbPath)
	fmt.Println()

	// ── Setup chain ──
	chain := NewChain()

	// Open persistent store — loads existing state or creates fresh
	store, err := chain.OpenStore(dbPath)
	if err != nil {
		slog.Error("failed to open store", "error", err)
		os.Exit(1)
	}
	defer chain.CloseStore()

	// Log startup info
	height := chain.Height
	slog.Info("restored from disk", "height", height, "accounts", len(chain.State.Accounts))

	// If fresh database, run genesis initialization
	if chain.Height == 0 {
		var config GenesisConfig
		if data, err := os.ReadFile(genesisPath); err == nil {
			json.Unmarshal(data, &config)
		} else {
			fmt.Println("  ⚠️  No genesis.json found, using defaults")
			config = DefaultGenesis()
		}

		gs := InitGenesis(config)
		gs.ProduceGenesisBlock()
		chain = gs.Chain
		chain.Store = store

		// Seed live WAY supply (backs the 5%-of-supply quest cap) on the
		// canonical genesis chain so it persists via Sync below.
		chain.SeedQuestSupply()

		// Persist genesis state
		if err := chain.Sync("genesis", 0, [32]byte{}, [32]byte{}); err != nil {
			fmt.Printf("  ❌ Failed to persist genesis: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  ✅ Genesis committed at height %d\n", chain.Height)
	}

	// ── Fund test validator account ──
	valAddr := "validator-1"
	val := chain.State.GetOrCreateAccount(valAddr)
	if val.Balance.Sign() == 0 {
		val.Balance.SetUint64(1_000_000)
		val.DoxDevLevel = 3
		fmt.Println("  ✅ Funded validator-1 with 1,000,000 WAY")
	}

	// ── Generate a funded Ed25519 keypair for RPC users ──
	// This gives the daemon a real Ed25519 account that can sign transactions.
	// The private key is stored in BoltDB and printed on first start.
	var devPrivKey ed25519.PrivateKey
	devPubKeyHex := ""
	
	// Try loading existing key from store
	nodeInfo, _ := store.LoadNodeInfo()
	if nodeInfo != nil && len(nodeInfo.NodeKey) == ed25519.PrivateKeySize {
		devPrivKey = ed25519.PrivateKey(nodeInfo.NodeKey)
		devPubKeyHex = hex.EncodeToString([]byte(devPrivKey.Public().(ed25519.PublicKey)))
		fmt.Printf("  🔑 Loaded dev key: 0x%s\n", devPubKeyHex)
	} else {
		// Generate new key
		_, devPrivKey, _ = ed25519.GenerateKey(rand.Reader)
		devPubKeyHex = hex.EncodeToString([]byte(devPrivKey.Public().(ed25519.PublicKey)))
		
		// Save to store
		if store != nil {
			nodeInfo := &st.NodeInfo{
				ID:      valAddr,
				NodeKey: []byte(devPrivKey),
			}
			store.SaveNodeInfo(nodeInfo)
		}
		
		fmt.Printf("  🔑 NEW dev key generated\n")
	}
	
	// Fund the dev account
	devAcc := chain.State.GetOrCreateAccount(devPubKeyHex)
	if devAcc.Balance.Sign() == 0 {
		devAcc.Balance.SetUint64(10_000_000)
		devAcc.DoxDevLevel = 3
		fmt.Printf("  ✅ Funded dev account 0x%s... with 10,000,000 WAY\n", devPubKeyHex[:16])
	}
	
	// Print private key for signing transactions
	fmt.Printf("  🔐 Dev private key: %s\n", hex.EncodeToString([]byte(devPrivKey)))
	fmt.Println()

	// ── Build validator set with multiple validators ──
	vs := NewValidatorSet()
	vs.Add(NewValidatorID(0x01), 10000)
	vs.Add(NewValidatorID(0x02), 10000)
	vs.Add(NewValidatorID(0x03), 10000)
	fmt.Printf("  🗳️  Validator set: %d validators\n", vs.Count())

	// ── Start P2P node ──
	listenAddr := getEnv("WAYCHAIN_P2P_LISTEN", ":9100")
	seedPeers := getEnvAsList("WAYCHAIN_SEED_PEERS")
	p2pNode := RunP2PNode(valAddr, listenAddr, seedPeers, chain)
	if p2pNode != nil {
		defer p2pNode.Stop()
	}

	// ── Start JSON-RPC server (with WebSocket support) ──
	rpcAddr := getEnv("WAYCHAIN_RPC_LISTEN", ":9545")
	rpc := RunRPCServer(rpcAddr, chain)
	// Expose the validator set so way_validatorCount reports the live count.
	rpc.SetValidators(vs)
	// Wire P2P node to RPC server for tx/block broadcasting
	rpc.SetP2PNode(p2pNode)
	fmt.Printf("  🌐 RPC server (HTTP+WS) on %s\n", rpcAddr)

	// ── Signal handling ──
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println()
	fmt.Println("  🌐 Node running. Press Ctrl+C to stop.")
	fmt.Println()

	// ── Block production loop ──
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	blockCount := 0
	startTime := time.Now()

	for {
		select {
		case <-ticker.C:
			blockCount++

			// Produce a block
			proposer := vs.SelectProposer(uint64(blockCount))
			block := chain.ProduceBlock(proposer)

			// Compute prev hash
			var prevHash [32]byte
			if len(chain.Blocks) > 1 {
				prevHash = chain.Blocks[len(chain.Blocks)-2].Hash
			}

			// Persist state
			if err := chain.Sync(proposer.String(), len(block.Transactions), block.Hash, prevHash); err != nil {
				slog.Error("sync error", "height", block.Height, "error", err)
			}
			// Persist transactions
			if err := chain.SyncTxs(block); err != nil {
				slog.Error("tx sync error", "height", block.Height, "error", err)
			}

			// Broadcast block to P2P peers
			BroadcastBlock(p2pNode, block)

				// Show status every 10 blocks
			if blockCount%10 == 0 {
				elapsed := time.Since(startTime)
				bps := float64(blockCount) / elapsed.Seconds()
				LogBlock(chain.Height, proposer.String(), len(block.Transactions), len(chain.State.Accounts), bps)
			}

		case sig := <-sigCh:
			fmt.Printf("\n  🛑 Received signal %v\n", sig)
			fmt.Println("  💾 Syncing state to disk...")
			if err := chain.Sync("shutdown", 0, [32]byte{}, [32]byte{}); err != nil {
				fmt.Printf("  ⚠️  Final sync error: %v\n", err)
			}
			fmt.Println("  ✅ State saved. Goodbye.")
			return
		}
	}
}

// ── Demo Runner ──

func runAllDemos() {
	runConsensusDemo()
	fmt.Println()
	runFullStackDemo()
	fmt.Println()
	RunPrecompileDemo()
	fmt.Println()
	RunP2PDemo()
	fmt.Println()
	RunOracleDemo()
	fmt.Println()
	RunRPCDemo()
	fmt.Println()
	RunGenesisDemo()
}

// ── Helpers for daemon config ──

func getEnvAsList(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	return []string{v} // Simple: single address for now
}

// RunRPCServer starts the JSON-RPC server with a chain reference
// and returns the RPCServer for callback wiring
func RunRPCServer(addr string, chain *Chain) *RPCServer {
	rpc := NewRPCServer(chain, 9545)
	
	// Wire OnNewBlock callback to subscription manager
	chain.OnNewBlock = func(block *BlockWithTx) {
		rpc.subs.BroadcastNewHead(block)
	}
	
	go func() {
		if err := rpc.Start(); err != nil {
			fmt.Printf("  ❌ RPC server error: %v\n", err)
		}
	}()
	return rpc
}
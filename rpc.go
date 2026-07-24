// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ThinkIbrokeIt/waychain-consensus/evm"
	"nhooyr.io/websocket"
)

// JSON-RPC types
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// RPCServer handles JSON-RPC requests for WayChain
type RPCServer struct {
	chain       *Chain
	validators  *ValidatorSet // optional; enables way_validatorCount
	mu          sync.RWMutex
	port        int
	server      *http.Server
	subs        *SubscriptionManager
	rateLimiter *RateLimiter
	p2pNode     *P2PNode
}

// SetValidators wires the active validator set so the RPC can report
// way_validatorCount. Called from the node entrypoint after the consensus
// engine is constructed.
func (rpc *RPCServer) SetValidators(vs *ValidatorSet) {
	rpc.validators = vs
}

// NewRPCServer creates a new RPC server connected to the chain
func NewRPCServer(chain *Chain, port int) *RPCServer {
	sm := NewSubscriptionManager()
	rl := NewRateLimiter(100, time.Second) // 100 requests/second/IP
	return &RPCServer{
		chain:       chain,
		port:        port,
		subs:        sm,
		rateLimiter: rl,
	}
}

// SetP2PNode sets the P2P node reference for broadcasting
func (rpc *RPCServer) SetP2PNode(node *P2PNode) {
	rpc.p2pNode = node
}

// Start begins listening for RPC requests
func (rpc *RPCServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", rpc.handleRequest)
	mux.HandleFunc("/health", rpc.handleHealth)

	rpc.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", rpc.port),
		Handler: rpc.rateLimiter.Middleware(mux),
	}

	slog.Info("rpc server started", "port", rpc.port, "rate_limit", "100/sec")
	return rpc.server.ListenAndServe()
}

// Stop shuts down the RPC server
func (rpc *RPCServer) Stop() {
	if rpc.server != nil {
		rpc.server.Close()
	}
}

func (rpc *RPCServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"blocks": len(rpc.chain.Blocks),
	})
}

func (rpc *RPCServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Check for WebSocket upgrade
	if wsUpgrade := r.Header.Get("Upgrade"); wsUpgrade == "websocket" || wsUpgrade == "WebSocket" {
		rpc.handleWS(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// NOTE: CORS is owned exclusively by nginx (sites-available/waychain), which
	// adds Access-Control-Allow-Origin "*" with `always`. The Go API MUST NOT set
	// ACAO — a duplicate ACAO header (different values) is invalid per spec and
	// makes browsers reject the response ("Failed to fetch"), while curl ignores
	// it. That duplication is what broke Mission Control / all browser RPC calls.
	// OPTIONS preflight is still short-circuited here; nginx passes it through.

	if r.Method == "OPTIONS" {
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		rpc.writeError(w, nil, -32700, "Parse error")
		return
	}

	result, err := rpc.handleMethod(req.Method, req.Params)
	if err != nil {
		rpc.writeError(w, req.ID, -32000, err.Error())
		return
	}

	rpc.writeResult(w, req.ID, result)
}

func (rpc *RPCServer) handleMethod(method string, params json.RawMessage) (interface{}, error) {
	switch method {
	// ── Chain methods ──
	case "eth_chainId":
		return fmt.Sprintf("0x%x", 10008), nil
	case "net_version":
		return "10008", nil

	// ── Block methods ──
	case "eth_blockNumber":
		rpc.mu.RLock()
		height := len(rpc.chain.Blocks)
		rpc.mu.RUnlock()
		return fmt.Sprintf("0x%x", height), nil

	case "eth_getBlockByNumber":
		var p []interface{}
		if err := json.Unmarshal(params, &p); err != nil || len(p) < 1 {
			return nil, fmt.Errorf("invalid params")
		}
		blockNumStr := fmt.Sprintf("%v", p[0])
		var blockNum int
		fullTx := false
		if len(p) > 1 {
			if b, ok := p[1].(bool); ok { fullTx = b }
		}
		if strings.HasPrefix(blockNumStr, "0x") {
			fmt.Sscanf(blockNumStr, "0x%x", &blockNum)
		} else if blockNumStr == "latest" || blockNumStr == "pending" {
			blockNum = len(rpc.chain.Blocks) - 1
		} else {
			fmt.Sscanf(blockNumStr, "%d", &blockNum)
		}
		if blockNum < 0 || blockNum >= len(rpc.chain.Blocks) {
			return nil, nil
		}
		block := rpc.chain.Blocks[blockNum]

		// Build transactions array
		var txResult interface{}
		if fullTx {
			txList := make([]map[string]interface{}, len(block.Transactions))
			for i, tx := range block.Transactions {
				j, _ := json.Marshal(tx.ToJSON())
				var m map[string]interface{}
				json.Unmarshal(j, &m)
				txList[i] = m
			}
			txResult = txList
		} else {
			txList := make([]string, len(block.Transactions))
			for i, tx := range block.Transactions {
				txList[i] = "0x" + hex.EncodeToString(tx.Hash[:])
			}
			txResult = txList
		}

		return map[string]interface{}{
			"number":       fmt.Sprintf("0x%x", block.Height),
			"hash":         fmt.Sprintf("0x%x", block.Hash),
			"parentHash":   fmt.Sprintf("0x%x", block.PrevHash),
			"timestamp":    fmt.Sprintf("0x%x", block.Timestamp),
			"transactions": txResult,
			"proposer":     block.Proposer.String(),
		}, nil

	case "eth_getBlockByHash":
			var p []interface{}
			if err := json.Unmarshal(params, &p); err != nil || len(p) < 1 {
				return nil, fmt.Errorf("invalid params")
			}
			hashStr := strings.TrimPrefix(fmt.Sprintf("%v", p[0]), "0x")

			for _, blk := range rpc.chain.Blocks {
				blockHash := fmt.Sprintf("%x", blk.Hash)
				if strings.EqualFold(blockHash, hashStr[:min(len(hashStr), len(blockHash))]) {
					// Build transactions array (same as eth_getBlockByNumber)
					txList := make([]map[string]interface{}, len(blk.Transactions))
					for i, tx := range blk.Transactions {
						j, _ := json.Marshal(tx.ToJSON())
						var m map[string]interface{}
						json.Unmarshal(j, &m)
						txList[i] = m
					}
					return map[string]interface{}{
						"number":       fmt.Sprintf("0x%x", blk.Height),
						"hash":         fmt.Sprintf("0x%x", blk.Hash),
						"parentHash":   fmt.Sprintf("0x%x", blk.PrevHash),
						"timestamp":    fmt.Sprintf("0x%x", blk.Timestamp),
						"transactions": txList,
						"proposer":     blk.Proposer.String(),
					}, nil
				}
			}
			return nil, nil

	// ── Account methods ──
	case "eth_getBalance":
		var p []string
		if err := json.Unmarshal(params, &p); err != nil || len(p) < 1 {
			return nil, fmt.Errorf("invalid params")
		}
		addr := strings.ToLower(strings.TrimPrefix(p[0], "0x"))
		acc := rpc.chain.State.GetAccount(addr)
		if acc == nil {
			return "0x0", nil
		}
		return fmt.Sprintf("0x%x", acc.Balance), nil

	case "eth_getTransactionCount":
		var p []string
		if err := json.Unmarshal(params, &p); err != nil || len(p) < 1 {
			return nil, fmt.Errorf("invalid params")
		}
		addr := strings.ToLower(strings.TrimPrefix(p[0], "0x"))
		acc := rpc.chain.State.GetAccount(addr)
		if acc == nil {
			return "0x0", nil
		}
		return fmt.Sprintf("0x%x", acc.Nonce), nil

	// ── Debug: introspect live in-memory state (issue #143 diagnostics) ──
	// Lists every account key + balance currently held by the RPC server's
	// chain.State. Used to verify genesis seeding is actually live (truth-first:
	// see the running node's state, not reconstruct it).
	case "way_debugAccountCount":
		return fmt.Sprintf("%d", len(rpc.chain.State.Accounts)), nil

	case "way_debugAccounts":
		type acctView struct {
			Address string `json:"address"`
			Balance string `json:"balance"`
		}
		views := make([]acctView, 0, len(rpc.chain.State.Accounts))
		for addr, acc := range rpc.chain.State.Accounts {
			bal := "nil"
			if acc.Balance != nil {
				bal = "0x" + acc.Balance.Text(16)
			}
			views = append(views, acctView{Address: addr, Balance: bal})
		}
		return views, nil

	// ── Call / Estimate ──
	case "eth_call":
		var p []map[string]interface{}
		if err := json.Unmarshal(params, &p); err != nil || len(p) < 1 {
			return nil, fmt.Errorf("invalid params")
		}
		call := p[0]

		to, _ := call["to"].(string)
		dataStr, _ := call["data"].(string)
		from, _ := call["from"].(string)

		data, err := hex.DecodeString(strings.TrimPrefix(dataStr, "0x"))
		if err != nil {
			return "0x", nil
		}
		from = strings.ToLower(strings.TrimPrefix(from, "0x"))
		to = strings.ToLower(strings.TrimPrefix(to, "0x"))

		// Route through EVM (precompile or revm contract execution)
		snapshot := rpc.chain.State.Clone()
		callEVM := evm.NewEVM(snapshot, evm.ConsensusLane, rpc.chain.Height,
			uint64(time.Now().Unix()), 10008, 30_000_000, "")
		ctx := &evm.CallContext{
			Caller:   from,
			Address:  to,
			Value:    big.NewInt(0),
			GasLimit: 30_000_000,
			Calldata: data,
			ReadOnly: true,
		}
		result := callEVM.Execute(ctx)
		if result.Error != nil {
			return "0x", nil
		}
		return "0x" + hex.EncodeToString(result.ReturnData), nil
	case "eth_estimateGas":
		return "0x5208", nil // 21000 gas

	// ── Gas ──
	case "eth_gasPrice":
		return "0x9502f900", nil // 2.5 gwei

	// ── WayChain custom methods ──
	case "way_getDoxLevel":
		var p []string
		if err := json.Unmarshal(params, &p); err != nil || len(p) < 1 {
			return nil, fmt.Errorf("invalid params")
		}
		addr := strings.ToLower(strings.TrimPrefix(p[0], "0x"))
		acc := rpc.chain.State.GetAccount(addr)
		if acc == nil {
			return "0x0", nil
		}
		return fmt.Sprintf("0x%x", acc.DoxDevLevel), nil

	case "way_getBalance":
		var p []string
		if err := json.Unmarshal(params, &p); err != nil || len(p) < 1 {
			return nil, fmt.Errorf("invalid params")
		}
		addr := strings.ToLower(strings.TrimPrefix(p[0], "0x"))
		acc := rpc.chain.State.GetAccount(addr)
		if acc == nil {
			return "0x0", nil
		}
		return fmt.Sprintf("0x%s", acc.Balance.Text(16)), nil

	case "way_fundGenesis":
		var p []string
		if err := json.Unmarshal(params, &p); err != nil || len(p) < 2 {
			return nil, fmt.Errorf("invalid params: expected [\"addr\", \"amount\"]")
		}
		addr := strings.ToLower(strings.TrimPrefix(p[0], "0x"))
		amtStr := strings.TrimPrefix(p[1], "0x")
		amt, ok := new(big.Int).SetString(amtStr, 16)
		if !ok {
			return nil, fmt.Errorf("invalid amount: %s", p[1])
		}
		rpc.mu.Lock()
		acc := rpc.chain.State.GetOrCreateAccount(addr)
		if acc.Balance == nil {
			acc.Balance = new(big.Int)
		}
		acc.Balance.Add(acc.Balance, amt)
		if acc.DoxDevLevel < 3 {
			acc.DoxDevLevel = 3
		}
		// Persist to disk if store is configured
		if rpc.chain.Store != nil {
			_ = rpc.chain.Store.SaveAllAccounts(rpc.chain.State)
		}
		rpc.mu.Unlock()
		return fmt.Sprintf("0x%s", acc.Balance.Text(16)), nil

	case "way_getBlockCount":
		rpc.mu.RLock()
		count := len(rpc.chain.Blocks)
		rpc.mu.RUnlock()
		return strconv.Itoa(count), nil

	// ── Network stats read surfaces (EXPL-3 #19) ──
	case "way_validatorCount":
		if rpc.validators != nil {
			return strconv.Itoa(rpc.validators.Count()), nil
		}
		return "0", nil

	case "way_accountCount":
		rpc.mu.RLock()
		defer rpc.mu.RUnlock()
		n := 0
		for _, acc := range rpc.chain.State.Accounts {
			if acc == nil {
				continue
			}
			// count accounts with any balance or deployed code
			if (acc.Balance != nil && acc.Balance.Sign() > 0) || len(acc.Code) > 0 {
				n++
			}
		}
		return strconv.Itoa(n), nil

	case "way_totalTxCount":
		rpc.mu.RLock()
		total := 0
		for _, b := range rpc.chain.Blocks {
			total += len(b.Transactions)
		}
		rpc.mu.RUnlock()
		return strconv.Itoa(total), nil

	case "way_pendingTxCount":
		rpc.mu.RLock()
		pending := rpc.chain.Pool.Len()
		rpc.mu.RUnlock()
		return strconv.Itoa(pending), nil

	// ── Wallet P3 panel read surfaces ──
	// These expose existing precompile READ functions without going through
	// eth_call (which the public RPC blocks for precompiles). Read-only.
	case "way_govProposals":
		return evm.GovernanceListProposals(rpc.chain.State), nil

	case "way_twoWayStats":
		vaults, debt := evm.GetTwoWayStats(rpc.chain.State)
		return map[string]interface{}{
			"vaults":   fmt.Sprintf("0x%x", vaults),
			"totalDebt": fmt.Sprintf("0x%x", debt),
		}, nil

	case "way_bridgeStats":
		committed, withdrawn := evm.GetBridgeStats(rpc.chain.State)
		return map[string]interface{}{
			"committed": fmt.Sprintf("0x%x", committed),
			"withdrawn": fmt.Sprintf("0x%x", withdrawn),
		}, nil

	// ── Quest / TaskRegistry read surfaces (0x23) ──
	// Expose live quest state without going through eth_call (which the
	// public RPC blocks for precompiles). Read-only.
	case "way_taskStatus":
		var p []string
		if err := json.Unmarshal(params, &p); err != nil || len(p) < 2 {
			return nil, fmt.Errorf("invalid params: expected [\"taskId_hex\", \"claimant_hex\"]")
		}
		taskId := strings.ToLower(strings.TrimPrefix(p[0], "0x"))
		claimant := strings.ToLower(strings.TrimPrefix(p[1], "0x"))
		idBytes, err := hex.DecodeString(taskId)
		if err != nil {
			return "none", nil
		}
		return evm.TaskStatusOf(rpc.chain.State, idBytes, claimant), nil

	case "way_questPoolRemaining":
		rem := evm.QuestPoolRemaining(rpc.chain.State)
		return "0x" + rem.Text(16), nil

	case "way_questGetAutopilot":
		ap := evm.QuestGetAutopilot(rpc.chain.State)
		if ap == "" {
			return "", nil
		}
		return ap, nil

	case "way_wayTotalSupply":
		return "0x" + evm.QuestTotalSupply(rpc.chain.State).Text(16), nil

	case "way_1wayTotalSupply":
		// Live 1WAY stablecoin supply: sums each vault's BTC-locked 1WAY
		// balance, so it flexes with the Bitcoin committed to vaults (NOT a
		// fixed constant). Distinct from way_wayTotalSupply, which returns
		// WAY's total supply (WAY is the native gas token).
		return "0x" + evm.Get1WayTotalSupply(rpc.chain.State).Text(16), nil

	case "way_questCap":
		return "0x" + evm.QuestCap(rpc.chain.State).Text(16), nil

	// ── Economic Health indicators (on-chain macroeconomics) ──
	// The chain computes the four decentralized indicators + phase from real
	// TaskRegistry (0x23) payout events. This is the read surface the
	// EconoAnalytics oracle + dashboard consume. Truth lives here (Go core),
	// not in the app-layer Solidity mirror.
	case "way_econoIndicators":
		return evm.GetEconoIndicators(rpc.chain.State, rpc.chain.Height), nil

	case "way_econoPolicy":
		p := evm.GetEconoPolicy()
		return map[string]interface{}{
			"phase":     p.Phase,
			"phaseLabel": func() string {
				if p.Phase == 1 {
					return "Expansion"
				}
				return "Consolidation"
			}(),
			"burnBps":  p.BurnBps,
			"grantBps": p.GrantBps,
		}, nil

	// ── SWAY emission projection (READ-ONLY telemetry) ──
	// Founder 2026-07-18: "we will need to see the numbers before that gets
	// hard coded." This shows what 3%-of-GBP emission would produce, with NO
	// mint authority. Does not change supply.
	case "way_swayEmissionProjection":
		gbp := evm.EconoGBPEquiv()
		proj3 := evm.SwayProjectedEmissionFromGBP(300) // 3% of yearly earnings
		return map[string]interface{}{
			"gdpEquivalentThisEpoch": gbp,
			"proposedPctBps":        300,
			"projectedSwayPerYear":  proj3.String(),
			"hardCeiling":           evm.SwayHardCeiling,
			"note":                  "READ-ONLY projection. 3% is a proposed figure, not yet hardcoded or minted.",
		}, nil

	// ── Contract Deployment ──
	case "way_deployCode":
		var p []string
		if err := json.Unmarshal(params, &p); err != nil || len(p) < 2 {
			return nil, fmt.Errorf("invalid params: expected [\"deployer_hex\", \"bytecode_hex\"]")
		}
		deployer := strings.ToLower(strings.TrimPrefix(p[0], "0x"))
		bytecodeHex := strings.TrimPrefix(p[1], "0x")
		bytecode, err := hex.DecodeString(bytecodeHex)
		if err != nil {
			return nil, fmt.Errorf("invalid bytecode: %v", err)
		}
		addr, err := rpc.chain.EVM.DeployContractFromCode(deployer, bytecode, evm.ClassA)
		if err != nil {
			return nil, fmt.Errorf("deploy failed: %v", err)
		}
		return "0x" + addr, nil

	// ── Transaction methods ──

	case "eth_sendRawTransaction":
		var p []string
		if err := json.Unmarshal(params, &p); err != nil || len(p) < 1 {
			return nil, fmt.Errorf("invalid params: expected [\"0xhex_encoded_tx\"]")
		}
		rawHex := strings.TrimPrefix(p[0], "0x")
		tx, err := DeserializeTxHex(rawHex)
		if err != nil {
			return nil, fmt.Errorf("invalid tx encoding: %v", err)
		}

		rpc.mu.Lock()
		defer rpc.mu.Unlock()

		sender := rpc.chain.State.GetOrCreateAccount(tx.From)

		// Verify signature
		if len(tx.Signature) > 0 {
			pub, err := ParsePubKey(tx.From)
			if err != nil {
				return nil, fmt.Errorf("invalid from address: %v", err)
			}
			if !ed25519.Verify(pub, tx.Hash[:], tx.Signature) {
				return nil, fmt.Errorf("invalid signature")
			}
		}

		// Nonce check
		if tx.Nonce != sender.Nonce {
			return nil, fmt.Errorf("invalid nonce: got %d, expected %d", tx.Nonce, sender.Nonce)
		}

		// Gas price default
		if tx.GasPrice == 0 {
			tx.GasPrice = 1
		}

		// Balance check
		txCost := new(big.Int).SetUint64(tx.GasLimit * tx.GasPrice)
		txCost.Add(txCost, tx.Value)
		if sender.Balance.Cmp(txCost) < 0 {
			return nil, fmt.Errorf("insufficient balance: have %d, need %d", sender.Balance, txCost)
		}

		// Deploy gate: if To is empty, this is a contract creation
		if tx.To == "" {
			if err := evm.CanDeployContract(sender.DoxDevLevel); err != nil {
				return nil, err
			}
		}

		// ADD TO POOL — this is the step that was missing
		rpc.chain.Pool.Add(*tx)

		// Broadcast transaction to P2P peers
		BroadcastTransaction(rpc.p2pNode, tx)

		txHash := "0x" + hex.EncodeToString(tx.Hash[:])
		return txHash, nil

	case "eth_getTransactionByHash":
		var p []string
		if err := json.Unmarshal(params, &p); err != nil || len(p) < 1 {
			return nil, fmt.Errorf("invalid params: expected [\"0xtxhash\"]")
		}
		searchHash := strings.TrimPrefix(p[0], "0x")
		var searchBytes [32]byte
		if h, err := hex.DecodeString(searchHash); err == nil && len(h) == 32 {
			copy(searchBytes[:], h)
		}

		// 1. Search pending pool (in-memory)
		rpc.mu.RLock()
		for _, tx := range rpc.chain.Pool.Consensus {
			txHex := hex.EncodeToString(tx.Hash[:])
			if strings.EqualFold(txHex, searchHash) {
				result := tx.ToJSON()
				rpc.mu.RUnlock()
				return result, nil
			}
		}
		for _, tx := range rpc.chain.Pool.Oracle {
			txHex := hex.EncodeToString(tx.Hash[:])
			if strings.EqualFold(txHex, searchHash) {
				result := tx.ToJSON()
				rpc.mu.RUnlock()
				return result, nil
			}
		}
		for _, tx := range rpc.chain.Pool.Private {
			txHex := hex.EncodeToString(tx.Hash[:])
			if strings.EqualFold(txHex, searchHash) {
				result := tx.ToJSON()
				rpc.mu.RUnlock()
				return result, nil
			}
		}

		// 2. Search in-memory blocks
		for _, block := range rpc.chain.Blocks {
			for _, tx := range block.Transactions {
				txHex := hex.EncodeToString(tx.Hash[:])
				if strings.EqualFold(txHex, searchHash) {
					result := tx.ToJSON()
					rpc.mu.RUnlock()
					return result, nil
				}
			}
		}
		rpc.mu.RUnlock()

		// 3. Search persistent store (historical blocks)
		tx, _, err := rpc.chain.LoadTxFromStore(searchBytes)
		if err == nil && tx != nil {
			return tx.ToJSON(), nil
		}
		return nil, nil

	case "eth_getTransactionReceipt":
		var p []string
		if err := json.Unmarshal(params, &p); err != nil || len(p) < 1 {
			return nil, fmt.Errorf("invalid params: expected [\"0xtxhash\"]")
		}
		searchHash := strings.TrimPrefix(p[0], "0x")
		var searchBytes [32]byte
		if h, err := hex.DecodeString(searchHash); err == nil && len(h) == 32 {
			copy(searchBytes[:], h)
		}

		rpc.mu.RLock()
		// Search in-memory blocks first
		for blockIdx, block := range rpc.chain.Blocks {
			for _, tx := range block.Transactions {
				txHex := hex.EncodeToString(tx.Hash[:])
				if strings.EqualFold(txHex, searchHash) {
					receipt := buildReceipt(tx, blockIdx, block.Hash)
					rpc.mu.RUnlock()
					return receipt, nil
				}
			}
		}
		rpc.mu.RUnlock()

		// Search persistent store
		tx, height, err := rpc.chain.LoadTxFromStore(searchBytes)
		if err == nil && tx != nil && height > 0 {
			blockHash := fmt.Sprintf("%x", tx.Hash)
			receipt := buildReceipt(*tx, int(height), [32]byte{})
			receipt["blockHash"] = "0x" + blockHash
			return receipt, nil
		}
		return nil, nil

	case "eth_getLogs":
		// EXPL-2: return real logs. The node stores per-block logs in
		// BlockWithTx.Logs (precompile + time-task + contract events that the
		// FFI surfaces). Filter by fromBlock/toBlock, address, and topics.
		var filter struct {
			FromBlock string   `json:"fromBlock"`
			ToBlock   string   `json:"toBlock"`
			Address   []string `json:"address"`
			Topics    [][]string `json:"topics"`
		}
		// Params is the JSON-RPC array; the first element is the filter object.
		if len(params) > 0 {
			var arr []json.RawMessage
			if err := json.Unmarshal(params, &arr); err == nil && len(arr) > 0 {
				_ = json.Unmarshal(arr[0], &filter)
			}
		}
		out := []interface{}{}
		blocks := rpc.chain.Blocks
		for bIdx, block := range blocks {
			// block range filter (hex or "latest")
			if filter.FromBlock != "" && filter.FromBlock != "latest" {
				if bn, ok := parseHexBlock(filter.FromBlock); ok && uint64(bIdx) < bn {
					continue
				}
			}
			if filter.ToBlock != "" && filter.ToBlock != "latest" {
				if bn, ok := parseHexBlock(filter.ToBlock); ok && uint64(bIdx) > bn {
					continue
				}
			}
			for _, tx := range block.Transactions {
				txHash := "0x" + hex.EncodeToString(tx.Hash[:])
				for li, log := range tx.Logs {
					if !logMatchesFilter(log, filter.Address, filter.Topics) {
						continue
					}
					out = append(out, LogToRPC(log, uint64(bIdx), txHash, li))
				}
			}
			// also surface block-level logs (time-tasks) without a tx
			for li, log := range block.Logs {
				// skip ones already attributed to a tx
				if logAttributed(block, log) {
					continue
				}
				if !logMatchesFilter(log, filter.Address, filter.Topics) {
					continue
				}
				out = append(out, LogToRPC(log, uint64(bIdx), "", li))
			}
		}
		return out, nil

	case "eth_getBlockTransactionCountByNumber":
		var p []interface{}
		if err := json.Unmarshal(params, &p); err != nil || len(p) < 1 {
			return nil, fmt.Errorf("invalid params")
		}
		blockNumStr := fmt.Sprintf("%v", p[0])
		var blockNum int
		if strings.HasPrefix(blockNumStr, "0x") {
			fmt.Sscanf(blockNumStr, "0x%x", &blockNum)
		} else if blockNumStr == "latest" || blockNumStr == "pending" {
			blockNum = len(rpc.chain.Blocks) - 1
		}
		if blockNum < 0 || blockNum >= len(rpc.chain.Blocks) {
			return "0x0", nil
		}
		return fmt.Sprintf("0x%x", len(rpc.chain.Blocks[blockNum].Transactions)), nil

	// ── WebSocket Subscription methods (handled via WS, but accept HTTP too) ──
	case "eth_subscribe":
		return nil, fmt.Errorf("eth_subscribe requires a WebSocket connection")

	case "eth_unsubscribe":
		return nil, fmt.Errorf("eth_unsubscribe requires a WebSocket connection")

	default:
		return nil, fmt.Errorf("method not found: %s", method)
	}
}

func (rpc *RPCServer) writeResult(w http.ResponseWriter, id interface{}, result interface{}) {
	json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      id,
	})
}

func (rpc *RPCServer) writeError(w http.ResponseWriter, id interface{}, code int, msg string) {
	json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		Error:   &RPCError{Code: code, Message: msg},
		ID:      id,
	})
}

// createAddress computes a contract address (WayChain version: SHA256(deployer + nonce))
func createAddress(deployer string, nonce uint64) [20]byte {
	input := fmt.Sprintf("%s:%d", deployer, nonce)
	hash := sha256.Sum256([]byte(input))
	var addr [20]byte
	copy(addr[:], hash[:20])
	return addr
}

// buildReceipt creates a standardized tx receipt map.
// EXPL-2: reports the real gasUsed (captured in ProduceBlock) and the tx's
// actual logs — no hardcoded values.
func buildReceipt(tx Transaction, blockIdx int, blockHash [32]byte) map[string]interface{} {
	txHex := hex.EncodeToString(tx.Hash[:])
	bh := fmt.Sprintf("%x", blockHash)
	logs := txLogsToRPC(tx.Logs, uint64(blockIdx), "0x"+txHex)
	to := tx.To
	if to == "" {
		deployAddr := fmt.Sprintf("%x", createAddress(tx.From, tx.Nonce))
		return map[string]interface{}{
			"transactionHash":   "0x" + txHex,
			"blockHash":         "0x" + bh,
			"blockNumber":       fmt.Sprintf("0x%x", blockIdx),
			"from":              "0x" + tx.From,
			"to":                nil,
			"contractAddress":   "0x" + deployAddr,
			"status":            "0x1",
			"gasUsed":           fmt.Sprintf("0x%x", tx.GasUsed),
			"cumulativeGasUsed": fmt.Sprintf("0x%x", tx.GasUsed),
			"logs":              logs,
		}
	}
	return map[string]interface{}{
		"transactionHash":   "0x" + txHex,
		"blockHash":         "0x" + bh,
		"blockNumber":       fmt.Sprintf("0x%x", blockIdx),
		"from":              "0x" + tx.From,
		"to":                "0x" + to,
		"status":            "0x1",
		"gasUsed":           fmt.Sprintf("0x%x", tx.GasUsed),
		"cumulativeGasUsed": fmt.Sprintf("0x%x", tx.GasUsed),
		"logs":              logs,
	}
}

// txLogsToRPC converts a tx's EVM logs to the Ethereum-compatible receipt shape.
func txLogsToRPC(logs []*evm.LogEntry, blockNum uint64, txHash string) []interface{} {
	out := make([]interface{}, 0, len(logs))
	for i, l := range logs {
		out = append(out, LogToRPC(l, blockNum, txHash, i))
	}
	return out
}

// min returns the smaller of a and b
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parseHexBlock parses a hex ("0x..") or decimal block number string.
func parseHexBlock(s string) (uint64, bool) {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return 0, false
	}
	var n uint64
	if _, err := fmt.Sscanf(s, "%x", &n); err == nil {
		return n, true
	}
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
		return n, true
	}
	return 0, false
}

// logMatchesFilter checks an EVM log against an eth_getLogs filter.
// Address filter: log.Address must match one of the requested addresses.
// Topics filter: positional prefix match (Ethereum semantics) — topic[i] of
// the log must be in the requested set for position i; nil/empty = any.
//
// Both sides are compared WITHOUT a "0x" prefix (raw hex), so the filter
// accepts addresses/topics with or without the prefix.
func logMatchesFilter(log *evm.LogEntry, addrs []string, topics [][]string) bool {
	if len(addrs) > 0 {
		match := false
		for _, a := range addrs {
			if strings.EqualFold(log.Address, strings.TrimPrefix(a, "0x")) {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	for i, set := range topics {
		if len(set) == 0 {
			continue // wildcard at this position
		}
		if i >= len(log.Topics) {
			return false
		}
		want := hex.EncodeToString(log.Topics[i][:])
		hit := false
		for _, t := range set {
			if strings.EqualFold(want, strings.TrimPrefix(t, "0x")) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// logAttributed reports whether a block-level log is already covered by a
// transaction's own log list (so we don't emit it twice in eth_getLogs).
func logAttributed(block *BlockWithTx, log *evm.LogEntry) bool {
	for _, tx := range block.Transactions {
		for _, l := range tx.Logs {
			if l == log {
				return true
			}
		}
	}
	return false
}

// ── WebSocket Handler ──

// handleWS handles a WebSocket connection for JSON-RPC subscriptions
func (rpc *RPCServer) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		fmt.Printf("  ⚠️ WS accept error: %v\n", err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "connection closed")

	fmt.Printf("  🔌 WS client connected\n")

	// Clean up subscriptions when connection closes
	defer rpc.subs.CleanupConn(conn)

	for {
		_, msg, err := conn.Read(nhooyrioCtx)
		if err != nil {
			// Connection closed
			break
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			continue
		}

		// Handle subscription methods
		switch req.Method {
		case "eth_subscribe":
			var p []interface{}
			if err := json.Unmarshal(req.Params, &p); err != nil || len(p) < 1 {
				rpc.writeWSSubscribeError(conn, req.ID, "invalid params")
				continue
			}
			subType, ok := p[0].(string)
			if !ok {
				rpc.writeWSSubscribeError(conn, req.ID, "invalid subscription type")
				continue
			}
			var params interface{}
			if len(p) > 1 {
				params = p[1]
			}
			subID, err := rpc.subs.Subscribe(subType, params, conn)
			if err != nil {
				rpc.writeWSSubscribeError(conn, req.ID, err.Error())
				continue
			}
			rpc.writeWSResult(conn, req.ID, subID)

		case "eth_unsubscribe":
			var p []string
			if err := json.Unmarshal(req.Params, &p); err != nil || len(p) < 1 {
				rpc.writeWSSubscribeError(conn, req.ID, "invalid params")
				continue
			}
			ok := rpc.subs.Unsubscribe(p[0])
			rpc.writeWSResult(conn, req.ID, ok)

		default:
			// For non-subscription methods, delegate to HTTP handler logic
			// and return result over WS
			result, err := rpc.handleMethod(req.Method, req.Params)
			if err != nil {
				rpc.writeWSError(conn, req.ID, err.Error())
			} else {
				rpc.writeWSResult(conn, req.ID, result)
			}
		}
	}
}

// writeWSResult sends a JSON-RPC result over WebSocket
func (rpc *RPCServer) writeWSResult(conn *websocket.Conn, id interface{}, result interface{}) {
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}
	data, _ := json.Marshal(msg)
	conn.Write(nhooyrioCtx, websocket.MessageText, data)
}

// writeWSError sends a JSON-RPC error over WebSocket
func (rpc *RPCServer) writeWSError(conn *websocket.Conn, id interface{}, message string) {
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]interface{}{"code": -32000, "message": message},
	}
	data, _ := json.Marshal(msg)
	conn.Write(nhooyrioCtx, websocket.MessageText, data)
}

// writeWSSubscribeError sends a JSON-RPC error for a subscribe request
func (rpc *RPCServer) writeWSSubscribeError(conn *websocket.Conn, id interface{}, message string) {
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]interface{}{"code": -32602, "message": message},
	}
	data, _ := json.Marshal(msg)
	conn.Write(nhooyrioCtx, websocket.MessageText, data)
}

// RunRPCDemo starts an RPC server and demonstrates queries
func RunRPCDemo() {
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" WayChain JSON-RPC Server — Demo")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	chain := NewChain()

	// Set up some test accounts
	alice := chain.State.GetOrCreateAccount("alice")
	alice.Balance.SetUint64(1_000_000)
	alice.DoxDevLevel = 3
	alice.Nonce = 5

	bob := chain.State.GetOrCreateAccount("bob")
	bob.Balance.SetUint64(500_000)

	// Produce a block
	vs := NewValidatorSet()
	vs.Add(NewValidatorID(0x01), 5000)
	proposer := vs.SelectProposer(1)
	chain.ProduceBlock(proposer)
	chain.ProduceBlock(proposer)
	chain.ProduceBlock(proposer)

	fmt.Println("Test accounts:")
	fmt.Printf("  Alice: 0x616c696365 | %d WAY | nonce: %d | Dox_Dev L%d\n",
		alice.Balance, alice.Nonce, alice.DoxDevLevel)
	fmt.Printf("  Bob:   0x626f62 | %d WAY\n", bob.Balance)
	fmt.Printf("  Blocks: %d\n", len(chain.Blocks))
	fmt.Println()

	// Start RPC server
	rpc := NewRPCServer(chain, 9545)
	go rpc.Start()
	defer rpc.Stop()

	time.Sleep(100 * time.Millisecond)

	// Make test calls
	baseURL := "http://127.0.0.1:9545"
	methods := []string{
		`{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}`,
		`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2}`,
		`{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x616c696365"],"id":3}`,
		`{"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["0x616c696365"],"id":4}`,
		`{"jsonrpc":"2.0","method":"way_getDoxLevel","params":["0x616c696365"],"id":5}`,
	}

	for _, payload := range methods {
		resp, err := http.Post(baseURL, "application/json", strings.NewReader(payload))
		if err != nil {
			fmt.Printf("  ❌ Request failed: %v\n", err)
			continue
		}
		var result JSONRPCResponse
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		var req JSONRPCRequest
		json.Unmarshal([]byte(payload), &req)

		if result.Result != nil {
			fmt.Printf("  ✅ %s → %v\n", req.Method, result.Result)
		} else if result.Error != nil {
			fmt.Printf("  ❌ %s → error: %s\n", req.Method, result.Error.Message)
		}
	}

	fmt.Println()
	fmt.Println("═══ RPC Demo Complete ═══")
	fmt.Println("Endpoints tested: chainId, blockNumber, balance, nonce, doxLevel")
}
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// callRPC is a tiny JSON-RPC client used by the verification tests.
func callRPC(t *testing.T, url, method string, params interface{}) map[string]interface{} {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": method, "params": params, "id": 1,
	})
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("rpc post failed: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("rpc decode failed: %v (body=%s)", err, raw)
	}
	return out
}

// TestWayReadMethodsEmptyState verifies the three new wallet-facing read
// methods respond cleanly on an empty chain (no proposals, zero stats).
func TestWayReadMethodsEmptyState(t *testing.T) {
	chain := NewChain()
	rpc := NewRPCServer(chain, 19545)
	go rpc.Start()
	defer rpc.Stop()
	time.Sleep(150 * time.Millisecond)
	url := "http://127.0.0.1:19545"

	// way_twoWayStats — empty => 0x0
	out := callRPC(t, url, "way_twoWayStats", []interface{}{})
	if out["error"] != nil {
		t.Fatalf("way_twoWayStats error: %v", out["error"])
	}
	stats := out["result"].(map[string]interface{})
	if stats["vaults"] != "0x0" || stats["totalDebt"] != "0x0" {
		t.Fatalf("unexpected twoWayStats: %v", stats)
	}

	// way_bridgeStats — empty => 0x0
	out = callRPC(t, url, "way_bridgeStats", []interface{}{})
	if out["error"] != nil {
		t.Fatalf("way_bridgeStats error: %v", out["error"])
	}
	bs := out["result"].(map[string]interface{})
	if bs["committed"] != "0x0" || bs["withdrawn"] != "0x0" {
		t.Fatalf("unexpected bridgeStats: %v", bs)
	}

	// way_govProposals — empty => []
	out = callRPC(t, url, "way_govProposals", []interface{}{})
	if out["error"] != nil {
		t.Fatalf("way_govProposals error: %v", out["error"])
	}
	prop := out["result"].([]interface{})
	if len(prop) != 0 {
		t.Fatalf("expected 0 proposals, got %d", len(prop))
	}
}

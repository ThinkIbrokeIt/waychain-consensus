package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"nhooyr.io/websocket"
)

var nhooyrioCtx = context.Background()

// ── Subscription Types ──
const (
	SubNewHeads              = "newHeads"
	SubNewPendingTransactions = "newPendingTransactions"
	SubLogs                  = "logs"
)

// Subscription represents an active WebSocket subscription
type Subscription struct {
	ID     string
	Type   string
	params interface{}
	conn   *websocket.Conn
	done   chan struct{}
}

// SubscriptionManager manages active WebSocket subscriptions
type SubscriptionManager struct {
	mu          sync.RWMutex
	subs        map[string]*Subscription
	nextID      atomic.Uint64
	connSubs    map[*websocket.Conn]map[string]bool // conn → set of subIDs
}

// NewSubscriptionManager creates a new subscription manager
func NewSubscriptionManager() *SubscriptionManager {
	return &SubscriptionManager{
		subs:     make(map[string]*Subscription),
		connSubs: make(map[*websocket.Conn]map[string]bool),
	}
}

// Subscribe creates a new subscription and starts pushing events
func (sm *SubscriptionManager) Subscribe(subType string, params interface{}, conn *websocket.Conn) (string, error) {
	id := fmt.Sprintf("0x%x", sm.nextID.Add(1))

	sub := &Subscription{
		ID:     id,
		Type:   subType,
		params: params,
		conn:   conn,
		done:   make(chan struct{}),
	}

	sm.mu.Lock()
	sm.subs[id] = sub
	if sm.connSubs[conn] == nil {
		sm.connSubs[conn] = make(map[string]bool)
	}
	sm.connSubs[conn][id] = true
	sm.mu.Unlock()

	return id, nil
}

// Unsubscribe removes a subscription
func (sm *SubscriptionManager) Unsubscribe(subID string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sub, ok := sm.subs[subID]
	if !ok {
		return false
	}

	// Clean up the connection mapping
	if sm.connSubs[sub.conn] != nil {
		delete(sm.connSubs[sub.conn], subID)
		if len(sm.connSubs[sub.conn]) == 0 {
			delete(sm.connSubs, sub.conn)
		}
	}

	close(sub.done)
	delete(sm.subs, subID)
	return true
}

// CleanupConn removes all subscriptions for a disconnected connection
func (sm *SubscriptionManager) CleanupConn(conn *websocket.Conn) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.connSubs[conn] == nil {
		return
	}
	for subID := range sm.connSubs[conn] {
		if sub, ok := sm.subs[subID]; ok {
			close(sub.done)
		}
		delete(sm.subs, subID)
	}
	delete(sm.connSubs, conn)
}

// BroadcastNewHead sends a new block to all newHeads subscribers
func (sm *SubscriptionManager) BroadcastNewHead(block *BlockWithTx) {
	sm.mu.RLock()
	subs := make([]*Subscription, 0)
	for _, sub := range sm.subs {
		if sub.Type == SubNewHeads {
			subs = append(subs, sub)
		}
	}
	sm.mu.RUnlock()

	// Build block notification
	notification := map[string]interface{}{
		"number":       fmt.Sprintf("0x%x", block.Height),
		"hash":         fmt.Sprintf("0x%x", block.Hash),
		"parentHash":   fmt.Sprintf("0x%x", block.PrevHash),
		"timestamp":    fmt.Sprintf("0x%x", block.Timestamp),
		"transactions": len(block.Transactions),
		"proposer":     block.Proposer.String(),
	}

	for _, sub := range subs {
		select {
		case <-sub.done:
		default:
			sm.sendNotification(sub.conn, sub.ID, notification)
		}
	}
}

// BroadcastPendingTx sends a new pending tx hash to all pendingTx subscribers
func (sm *SubscriptionManager) BroadcastPendingTx(tx *Transaction) {
	sm.mu.RLock()
	subs := make([]*Subscription, 0)
	for _, sub := range sm.subs {
		if sub.Type == SubNewPendingTransactions {
			subs = append(subs, sub)
		}
	}
	sm.mu.RUnlock()

	txHash := fmt.Sprintf("0x%x", tx.Hash)

	for _, sub := range subs {
		select {
		case <-sub.done:
		default:
			sm.sendNotification(sub.conn, sub.ID, txHash)
		}
	}
}

// sendNotification sends a subscription notification over WebSocket
// Format: {"jsonrpc":"2.0","method":"eth_subscription","params":{"subscription":"ID","result":DATA}}
func (sm *SubscriptionManager) sendNotification(conn *websocket.Conn, subID string, data interface{}) {
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_subscription",
		"params": map[string]interface{}{
			"subscription": subID,
			"result":       data,
		},
	}

	raw, err := json.Marshal(msg)
	if err != nil {
		return
	}

	err = conn.Write(nhooyrioCtx, websocket.MessageText, raw)
	if err != nil {
		sm.CleanupConn(conn)
	}
}

// nhooyrioCtx is used as a context for WebSocket operations

package main

import (
	"fmt"
	"testing"
	"time"
)

// TestP2PMessagePropagation tests that messages sent by one node are received by peers
func TestP2PMessagePropagation(t *testing.T) {
	// Create 3 nodes on different ports
	node1 := NewP2PNode("node-1", "127.0.0.1:0")
	node2 := NewP2PNode("node-2", "127.0.0.1:0")
	node3 := NewP2PNode("node-3", "127.0.0.1:0")

	if err := node1.Start(); err != nil {
		t.Fatalf("Node 1 start failed: %v", err)
	}
	if err := node2.Start(); err != nil {
		t.Fatalf("Node 2 start failed: %v", err)
	}
	if err := node3.Start(); err != nil {
		t.Fatalf("Node 3 start failed: %v", err)
	}
	defer node1.Stop()
	defer node2.Stop()
	defer node3.Stop()

	// Get actual listen addresses
	addr2 := node2.listener.Addr().String()
	addr3 := node3.listener.Addr().String()

	// Connect node1 → node2 and node1 → node3
	if err := node1.Connect(addr2); err != nil {
		t.Fatalf("Connect to node2 failed: %v", err)
	}
	if err := node1.Connect(addr3); err != nil {
		t.Fatalf("Connect to node3 failed: %v", err)
	}

	// Wait for connections to establish
	time.Sleep(200 * time.Millisecond)

	// Verify peer counts
	node1.peerLock.RLock()
	peers1 := len(node1.Peers)
	node1.peerLock.RUnlock()
	if peers1 < 2 {
		t.Fatalf("Node 1 should have 2 peers, got %d", peers1)
	}

	// Send a message from node1
	testMsg := P2PMessage{
		Type:    MsgTx,
		From:    node1.ID,
		Seq:     node1.nextSeq(),
		Payload: []byte("test-tx:abc123"),
	}
	node1.Broadcast(testMsg)

	// Wait for propagation
	time.Sleep(300 * time.Millisecond)

	// Check node2 received it
	select {
	case received := <-node2.Incoming:
		if string(received.Payload) != "test-tx:abc123" {
			t.Fatalf("Node 2 received wrong message: %s", string(received.Payload))
		}
		t.Logf("✅ Node 2 received message from Node 1")
	default:
		t.Fatal("Node 2 did not receive message from Node 1")
	}

	// Check node3 received it
	select {
	case received := <-node3.Incoming:
		if string(received.Payload) != "test-tx:abc123" {
			t.Fatalf("Node 3 received wrong message: %s", string(received.Payload))
		}
		t.Logf("✅ Node 3 received message from Node 1")
	default:
		t.Fatal("Node 3 did not receive message from Node 1")
	}
}

// TestP2PBlockPropagation tests block propagation across the network
func TestP2PBlockPropagation(t *testing.T) {
	node1 := NewP2PNode("block-node-1", "127.0.0.1:0")
	node2 := NewP2PNode("block-node-2", "127.0.0.1:0")

	if err := node1.Start(); err != nil {
		t.Fatalf("Node 1 start failed: %v", err)
	}
	if err := node2.Start(); err != nil {
		t.Fatalf("Node 2 start failed: %v", err)
	}
	defer node1.Stop()
	defer node2.Stop()

	addr2 := node2.listener.Addr().String()
	if err := node1.Connect(addr2); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Create and broadcast a block
	block := &BlockWithTx{
		Height:    42,
		Timestamp: time.Now().Unix(),
	}
	block.Hash = block.ComputeHash()

	blockMsg := P2PMessage{
		Type:    MsgBlock,
		From:    node1.ID,
		Seq:     node1.nextSeq(),
		Payload: serializeBlock(block),
	}
	node1.Broadcast(blockMsg)

	time.Sleep(300 * time.Millisecond)

	// Verify node2 received the block
	select {
	case received := <-node2.Incoming:
		if received.Type != MsgBlock {
			t.Fatalf("Expected block message, got type %d", received.Type)
		}
		t.Logf("✅ Block propagated: %s", string(received.Payload))
	default:
		t.Fatal("Node 2 did not receive block")
	}
}

// TestP2PMeshTopology tests a 3-node mesh where all nodes connect to each other
func TestP2PMeshTopology(t *testing.T) {
	nodes := make([]*P2PNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = NewP2PNode(fmt.Sprintf("mesh-%d", i+1), "127.0.0.1:0")
		if err := nodes[i].Start(); err != nil {
			t.Fatalf("Node %d start failed: %v", i+1, err)
		}
		defer nodes[i].Stop()
	}

	time.Sleep(100 * time.Millisecond)

	// Connect in mesh: 0→1, 0→2, 1→2
	addrs := make([]string, 3)
	for i, n := range nodes {
		addrs[i] = n.listener.Addr().String()
	}

	nodes[0].Connect(addrs[1])
	time.Sleep(50 * time.Millisecond)
	nodes[0].Connect(addrs[2])
	time.Sleep(50 * time.Millisecond)
	nodes[1].Connect(addrs[2])
	time.Sleep(200 * time.Millisecond)

	// Verify mesh connectivity
	for i, n := range nodes {
		n.peerLock.RLock()
		peerCount := len(n.Peers)
		n.peerLock.RUnlock()
		if peerCount < 2 {
			t.Fatalf("Node %d should have 2 peers in mesh, got %d", i+1, peerCount)
		}
	}

	// Broadcast from node 0 — should reach nodes 1 and 2
	nodes[0].Broadcast(P2PMessage{
		Type:    MsgTx,
		From:    nodes[0].ID,
		Seq:     nodes[0].nextSeq(),
		Payload: []byte("mesh-test-tx"),
	})

	time.Sleep(300 * time.Millisecond)

	received := 0
	for i := 1; i < 3; i++ {
		select {
		case msg := <-nodes[i].Incoming:
			if string(msg.Payload) == "mesh-test-tx" {
				received++
			}
		default:
		}
	}

	if received != 2 {
		t.Fatalf("Expected 2 nodes to receive message, got %d", received)
	}

	t.Logf("✅ Mesh topology: 3 nodes, all connected, message propagated to all peers")
}

// TestP2PNodeRestart tests that a node can restart and reconnect
func TestP2PNodeRestart(t *testing.T) {
	node1 := NewP2PNode("stable-node", "127.0.0.1:0")
	node2 := NewP2PNode("restart-node", "127.0.0.1:0")

	if err := node1.Start(); err != nil {
		t.Fatalf("Node 1 start failed: %v", err)
	}
	if err := node2.Start(); err != nil {
		t.Fatalf("Node 2 start failed: %v", err)
	}

	addr1 := node1.listener.Addr().String()

	// Connect node2 → node1
	node2.Connect(addr1)
	time.Sleep(200 * time.Millisecond)

	// Stop node2
	node2.Stop()
	time.Sleep(100 * time.Millisecond)

	// Restart node2 on same port
	node2 = NewP2PNode("restart-node", "127.0.0.1:0")
	if err := node2.Start(); err != nil {
		t.Fatalf("Node 2 restart failed: %v", err)
	}
	defer node1.Stop()
	defer node2.Stop()

	// Reconnect
	node2.Connect(addr1)
	time.Sleep(200 * time.Millisecond)

	// Verify connection
	node2.peerLock.RLock()
	peers := len(node2.Peers)
	node2.peerLock.RUnlock()
	if peers < 1 {
		t.Fatalf("Node 2 should have 1 peer after restart, got %d", peers)
	}

	t.Logf("✅ Node restart: disconnected, restarted, reconnected successfully")
}

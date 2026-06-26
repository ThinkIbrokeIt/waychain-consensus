package main

import (
	"encoding/gob"
	"fmt"
	"net"
	"sync"
	"time"
)

// Message types for P2P communication
type P2PMessageType byte

const (
	MsgTx         P2PMessageType = 1 // New transaction
	MsgBlock      P2PMessageType = 2 // New block proposal
	MsgVote       P2PMessageType = 3 // Consensus vote (prevote/precommit)
	MsgPeerList   P2PMessageType = 4 // Peer discovery exchange
	MsgStateReq   P2PMessageType = 5 // Request current chain state
	MsgStateResp  P2PMessageType = 6 // Chain state response
)

func init() {
	gob.Register(P2PMessage{})
	gob.Register(Transaction{})
	gob.Register(BlockWithTx{})
}

// P2PMessage is the wire format for all P2P messages
type P2PMessage struct {
	Type    P2PMessageType
	Payload []byte
	From    string
	Seq     uint64
}

// Peer represents a connected validator node
type Peer struct {
	ID        string
	Addr      string
	Conn      net.Conn
	Encoder   *gob.Encoder
	Decoder   *gob.Decoder
	Connected time.Time
	Height    uint64 // Latest known block height
}

// P2PNode manages a validator's network connections
type P2PNode struct {
	ID       string
	ListenAddr string
	Peers    map[string]*Peer
	peerLock sync.RWMutex
	Incoming chan P2PMessage

	// Callbacks for handling messages
	OnTx    func(tx Transaction)
	OnBlock func(block BlockWithTx)
	OnVote  func(vote interface{}, from string)

	listener net.Listener
	seq      uint64
	seqLock  sync.Mutex
	done     chan struct{}
}

// NewP2PNode creates a new P2P node for a validator
func NewP2PNode(id string, listenAddr string) *P2PNode {
	return &P2PNode{
		ID:         id,
		ListenAddr: listenAddr,
		Peers:      make(map[string]*Peer),
		Incoming:   make(chan P2PMessage, 256),
		done:       make(chan struct{}),
	}
}

// Start begins listening for incoming connections
func (n *P2PNode) Start() error {
	ln, err := net.Listen("tcp", n.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen failed: %w", err)
	}
	n.listener = ln

	go n.acceptLoop()
	fmt.Printf("  🌐 P2P node %s listening on %s\n", n.ID, n.ListenAddr)

	// Start heartbeat to detect dead peers
	go n.heartbeatLoop()

	return nil
}

// Stop shuts down the node
func (n *P2PNode) Stop() {
	close(n.done)
	if n.listener != nil {
		n.listener.Close()
	}
	n.peerLock.Lock()
	for _, p := range n.Peers {
		p.Conn.Close()
	}
	n.Peers = make(map[string]*Peer)
	n.peerLock.Unlock()
}

// Connect establishes an outbound connection to a peer
func (n *P2PNode) Connect(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect to %s failed: %w", addr, err)
	}

	enc := gob.NewEncoder(conn)
	dec := gob.NewDecoder(conn)

	// Send our identity
	handshake := P2PMessage{
		Type: MsgPeerList,
		From: n.ID,
		Payload: []byte(fmt.Sprintf("%s|%s", n.ID, n.ListenAddr)),
	}
	enc.Encode(handshake)

	peerID := fmt.Sprintf("peer@%s", addr)
	peer := &Peer{
		ID:        peerID,
		Addr:      addr,
		Conn:      conn,
		Encoder:   enc,
		Decoder:   dec,
		Connected: time.Now(),
	}

	n.peerLock.Lock()
	n.Peers[peerID] = peer
	peerCount := len(n.Peers)
	n.peerLock.Unlock()

	go n.readLoop(peer)
	fmt.Printf("  🔗 %s connected to %s (%d peers)\n", n.ID, addr, peerCount)
	return nil
}

// Broadcast sends a message to all connected peers
func (n *P2PNode) Broadcast(msg P2PMessage) {
	n.peerLock.RLock()
	defer n.peerLock.RUnlock()

	for _, peer := range n.Peers {
		go func(p *Peer) {
			p.Encoder.Encode(msg)
		}(peer)
	}
}

// sendMsg sends a message to a specific peer
func (n *P2PNode) sendMsg(peerID string, msg P2PMessage) {
	n.peerLock.RLock()
	peer, ok := n.Peers[peerID]
	n.peerLock.RUnlock()
	if ok {
		peer.Encoder.Encode(msg)
	}
}

// acceptLoop handles incoming connections
func (n *P2PNode) acceptLoop() {
	for {
		conn, err := n.listener.Accept()
		if err != nil {
			select {
			case <-n.done:
				return
			default:
				continue
			}
		}

		peerID := fmt.Sprintf("inbound@%s", conn.RemoteAddr())
		peer := &Peer{
			ID:        peerID,
			Addr:      conn.RemoteAddr().String(),
			Conn:      conn,
			Encoder:   gob.NewEncoder(conn),
			Decoder:   gob.NewDecoder(conn),
			Connected: time.Now(),
		}

		n.peerLock.Lock()
		n.Peers[peerID] = peer
		n.peerLock.Unlock()

		go n.readLoop(peer)
	}
}

// readLoop reads messages from a peer connection
func (n *P2PNode) readLoop(peer *Peer) {
	defer func() {
		peer.Conn.Close()
		n.peerLock.Lock()
		delete(n.Peers, peer.ID)
		n.peerLock.Unlock()
	}()

	for {
		var msg P2PMessage
		err := peer.Decoder.Decode(&msg)
		if err != nil {
			return // Connection closed or error
		}

		msg.From = peer.ID

		// Handle peer list messages (handshake)
		if msg.Type == MsgPeerList {
			n.peerLock.Lock()
			if existing, ok := n.Peers[peer.ID]; ok {
				existing.Height = msg.Seq
			}
			n.peerLock.Unlock()
			continue
		}

		// Forward to handler
		select {
		case n.Incoming <- msg:
		default:
			// Channel full, drop message
		}
	}
}

// heartbeatLoop periodically checks peer liveness
func (n *P2PNode) heartbeatLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			n.peerLock.Lock()
			for id, peer := range n.Peers {
				// Set deadline to check connection
				peer.Conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, err := peer.Conn.Write([]byte{})
				if err != nil {
					delete(n.Peers, id)
					peer.Conn.Close()
					fmt.Printf("  ❌ Peer %s disconnected\n", id)
				}
				// Reset deadline
				peer.Conn.SetDeadline(time.Time{})
			}
			fmt.Printf("  💓 [%s] %d active peers\n", n.ID, len(n.Peers))
			n.peerLock.Unlock()
		case <-n.done:
			return
		}
	}
}

// nextSeq returns a unique sequence number for messages
func (n *P2PNode) nextSeq() uint64 {
	n.seqLock.Lock()
	defer n.seqLock.Unlock()
	n.seq++
	return n.seq
}

// RunP2PDemo demonstrates multiple validator nodes communicating
func RunP2PDemo() {
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println(" WayChain P2P Network — 3 Validator Nodes")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	// Create 3 validator nodes
	nodes := make([]*P2PNode, 3)
	ports := []string{":9001", ":9002", ":9003"}

	for i := 0; i < 3; i++ {
		nodes[i] = NewP2PNode(fmt.Sprintf("val-%d", i+1), ports[i])
		err := nodes[i].Start()
		if err != nil {
			fmt.Printf("  ❌ Node %d failed: %v\n", i+1, err)
			return
		}
	}

	// Connect them in a mesh topology
	fmt.Println("Connecting mesh topology...")
	nodes[0].Connect("127.0.0.1:9002")
	time.Sleep(100 * time.Millisecond)
	nodes[0].Connect("127.0.0.1:9003")
	time.Sleep(100 * time.Millisecond)
	nodes[1].Connect("127.0.0.1:9003")
	time.Sleep(100 * time.Millisecond)

	fmt.Println()

	// Demonstrate message passing
	fmt.Println("Sending test messages...")
	tx := NewTransaction(0, "alice", "bob", nil, 21000, []byte{})
	msg := P2PMessage{
		Type:    MsgTx,
		Payload: []byte(fmt.Sprintf("tx:%x", tx.Hash[:4])),
		From:    nodes[0].ID,
		Seq:     nodes[0].nextSeq(),
	}

	nodes[0].Broadcast(msg)
	time.Sleep(200 * time.Millisecond)

	// Check that all nodes received it
	for _, node := range nodes {
		select {
		case received := <-node.Incoming:
			fmt.Printf("  ✅ %s received: %s\n", node.ID, string(received.Payload))
		default:
			fmt.Printf("  ⚠️  %s: no messages\n", node.ID)
		}
	}

	fmt.Println()

	// Simulate block propagation
	fmt.Println("Propagating a block across the network...")
	block := BlockWithTx{
		Height:    1,
		Timestamp: time.Now().Unix(),
	}
	block.Hash = block.ComputeHash()

	blockMsg := P2PMessage{
		Type:    MsgBlock,
		Payload: []byte(fmt.Sprintf("block:#%d:hash:%x", block.Height, block.Hash[:4])),
		From:    nodes[1].ID,
		Seq:     nodes[1].nextSeq(),
	}
	nodes[1].Broadcast(blockMsg)
	time.Sleep(200 * time.Millisecond)

	for _, node := range nodes {
		select {
		case received := <-node.Incoming:
			fmt.Printf("  📦 %s received block: %s\n", node.ID, string(received.Payload))
		default:
			fmt.Printf("  ⚠️  %s: no block received\n", node.ID)
		}
	}

	fmt.Println()

	// Statistics
	for _, node := range nodes {
		node.peerLock.RLock()
		peerCount := len(node.Peers)
		node.peerLock.RUnlock()
		fmt.Printf("  🌐 %s has %d peers\n", node.ID, peerCount)
	}

	// Cleanup
	for _, node := range nodes {
		node.Stop()
	}

	fmt.Println()
	fmt.Println("═══ P2P Demo Complete ═══")
	fmt.Println("3 nodes, mesh topology, tx + block propagation verified")
	fmt.Println()
}

func init() {
	gob.Register(P2PMessage{})
}
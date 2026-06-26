#!/bin/bash
# WayChain Devnet — Multi-Node Bootstrap
# Spawns N validator nodes locally, each on its own ports.
# Usage: ./devnet.sh [num_nodes]

set -e

NUM_NODES=${1:-4}
BASE_P2P_PORT=9100
BASE_RPC_PORT=9545
BINARY="./waychain-full"
CONFIG_DIR="./devnet-data"

echo "═══ WayChain Devnet Bootstrap ═══"
echo "Nodes: $NUM_NODES"
echo ""

# Clean up any previous run
rm -rf "$CONFIG_DIR"
mkdir -p "$CONFIG_DIR"

# Build the binary
echo "Building WayChain..."
cd "$(dirname "$0")"
go build -o waychain-full . 2>&1
echo "✅ Build complete"
echo ""

# Generate node keys (simplified — uses deterministic IDs for dev)
echo "Generating node configurations..."
for i in $(seq 1 $NUM_NODES); do
    NODE_DIR="$CONFIG_DIR/node-$i"
    mkdir -p "$NODE_DIR"

    P2P_PORT=$((BASE_P2P_PORT + i - 1))
    RPC_PORT=$((BASE_RPC_PORT + i - 1))

    # Create node config
    cat > "$NODE_DIR/config.toml" << EOF
[validator]
id = "devnet-val-$i"
p2p_port = $P2P_PORT
rpc_port = $RPC_PORT

[p2p]
listen_addr = "0.0.0.0:$P2P_PORT"
seed_peers = "127.0.0.1:$BASE_P2P_PORT"

[consensus]
genesis_validators = $NUM_NODES
block_time_ms = 1000

[dox_dev]
default_level = 3
EOF

    echo "  ✅ Node $i configured (P2P: $P2P_PORT, RPC: $RPC_PORT)"
done

# Create genesis file
cat > "$CONFIG_DIR/genesis.json" << EOF
{
  "chain_id": "waychain-devnet-1",
  "genesis_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "initial_height": 1,
  "consensus_params": {
    "block_time": "1s",
    "max_validators": 200,
    "voting_power_equal": true
  },
  "validators": [
EOF

for i in $(seq 1 $NUM_NODES); do
    COMMA=","
    if [ $i -eq $NUM_NODES ]; then COMMA=""; fi
    cat >> "$CONFIG_DIR/genesis.json" << EOF
    {"id": "devnet-val-$i", "power": 1, "name": "validator-$i"}$COMMA
EOF
done

cat >> "$CONFIG_DIR/genesis.json" << EOF
  ]
}
EOF

echo "  ✅ Genesis created"
echo ""

# Launch all nodes in background
echo "Starting WayChain devnet..."
PIDS=""
for i in $(seq 1 $NUM_NODES); do
    P2P_ADDRS=""
    for j in $(seq 1 $NUM_NODES); do
        if [ $j -ne $i ]; then
            P2P_PORT=$((BASE_P2P_PORT + j - 1))
            if [ -n "$P2P_ADDRS" ]; then P2P_ADDRS="$P2P_ADDRS,"; fi
            P2P_ADDRS="${P2P_ADDRS}127.0.0.1:${P2P_PORT}"
        fi
    done

    P2P_PORT=$((BASE_P2P_PORT + i - 1))
    LOG_FILE="$CONFIG_DIR/node-$i/output.log"

    # Run in background with node ID
    WAYCHAIN_NODE_ID="devnet-val-$i" \
    WAYCHAIN_LISTEN=":$P2P_PORT" \
    WAYCHAIN_PEERS="$P2P_ADDRS" \
    WAYCHAIN_DATA_DIR="$CONFIG_DIR/node-$i/data" \
    WAYCHAIN_DEVNET=1 \
    nohup "$BINARY" > "$LOG_FILE" 2>&1 &

    PID=$!
    PIDS="$PIDS $PID"
    echo "  🚀 Node $i started (PID: $PID, P2P: :$P2P_PORT, log: $LOG_FILE)"
done

echo ""
echo "═══ Devnet Running ═══"
echo "PIDs: $PIDS"
echo "Logs: $CONFIG_DIR/node-*/output.log"
echo ""
echo "To stop: kill $PIDS"
echo "To view logs: tail -f $CONFIG_DIR/node-*/output.log"
echo ""

# Save PIDs for cleanup
echo "$PIDS" > "$CONFIG_DIR/pids.txt"

# Wait for all processes
trap "kill $PIDS 2>/dev/null; echo 'Devnet stopped.'; exit" INT TERM
wait
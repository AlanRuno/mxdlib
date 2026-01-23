#!/bin/bash
set -e

LOG_FILE="/tmp/setup.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=== Starting MXD Node Setup at $(date) ==="

# Install basic dependencies
echo "Installing base packages..."
apt-get update
apt-get install -y build-essential cmake git libssl-dev pkg-config libsodium-dev libgmp-dev libc-bin libcjson-dev libcurl4-openssl-dev librocksdb-dev libminiupnpc-dev libmicrohttpd-dev

# Clone the repository
echo "Cloning mxdlib repository..."
cd /opt
if [ -d "mxdlib" ]; then
    rm -rf mxdlib
fi
git clone https://github.com/AlanRuno/mxdlib.git
cd mxdlib

# Run the dependency installation script
echo "Installing custom dependencies (libuv, uvwasi, liboqs, wasm3)..."
chmod +x install_dependencies_linux.sh
./install_dependencies_linux.sh

# Build the project
echo "Building mxdlib..."
mkdir -p build
cd build
cmake ..
make -j$(nproc)

# Create data directory
mkdir -p data

# Get instance metadata to determine node index
INSTANCE_NAME=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/name" -H "Metadata-Flavor: Google")
NODE_INDEX=${INSTANCE_NAME##*-}
echo "This is node $NODE_INDEX ($INSTANCE_NAME)"

# Write config file with isolated test network
echo "Writing configuration..."
cat > default_config.json << 'CONFIGEOF'
{
    "node_id": "test_node",
    "network_type": "testnet",
    "port": 8000,
    "data_dir": "./data",
    "node_name": "MXD Test Node",
    "initial_stake": 100.0,
    "preferred_sign_algo": 1,
    "bootstrap_nodes": [],
    "metrics": {
        "update_interval": 1000,
        "display_interval": 5000,
        "performance_threshold": 10,
        "max_latency": 3000,
        "error_threshold": 10
    },
    "validation": {
        "min_tps": 10,
        "stake_table_update_interval": 60000
    },
    "network": {
        "max_peers": 50,
        "connection_timeout": 5000
    },
    "log_level": "info",
    "pool": {
        "max_size": 10000,
        "cleanup_interval": 3600
    }
}
CONFIGEOF

# Signal that this node is ready
echo "READY" > /tmp/node_ready

# Wait for other nodes to be created (2 minutes)
echo "Waiting for other nodes to be created..."
sleep 120

# Get external IPs of all test nodes and update bootstrap_nodes
echo "Discovering peer nodes..."
PEERS=""
PEERS_ENV=""
for i in 0 1 2 3 4 5 6 7 8 9; do
    IP=$(gcloud compute instances describe mxd-genesis-test-$i --zone=us-central1-a --format="get(networkInterfaces[0].accessConfigs[0].natIP)" 2>/dev/null || echo "")
    if [ -n "$IP" ] && [ "$IP" != "" ]; then
        if [ -n "$PEERS" ]; then
            PEERS="$PEERS,"
            PEERS_ENV="$PEERS_ENV,"
        fi
        PEERS="$PEERS\"$IP:8000\""
        PEERS_ENV="$PEERS_ENV$IP:8000"
        echo "Found peer: $IP:8000"
    fi
done

# Update config with discovered peers
echo "Updating config with bootstrap nodes..."
cat > default_config.json << EOF
{
    "node_id": "test_node_$NODE_INDEX",
    "network_type": "testnet",
    "port": 8000,
    "data_dir": "./data",
    "node_name": "MXD Test Node $NODE_INDEX",
    "initial_stake": 100.0,
    "preferred_sign_algo": 1,
    "bootstrap_nodes": [$PEERS],
    "metrics": {
        "update_interval": 1000,
        "display_interval": 5000,
        "performance_threshold": 10,
        "max_latency": 3000,
        "error_threshold": 10
    },
    "validation": {
        "min_tps": 10,
        "stake_table_update_interval": 60000
    },
    "network": {
        "max_peers": 50,
        "connection_timeout": 5000
    },
    "log_level": "info",
    "pool": {
        "max_size": 10000,
        "cleanup_interval": 3600
    }
}
EOF

echo "Final config:"
cat default_config.json

# Wait a bit more for all nodes to update their configs
sleep 30

# Start the node with environment variable to bypass API bootstrap fetch
echo "Starting MXD node at $(date)..."
echo "Using bootstrap nodes: $PEERS_ENV"
export MXD_BOOTSTRAP_NODES="$PEERS_ENV"
./lib/mxd_node --http-api 8081 > /tmp/mxd.log 2>&1 &
MXD_PID=$!
echo "MXD node started with PID $MXD_PID"

# Wait and check if the node is running
sleep 10
if kill -0 $MXD_PID 2>/dev/null; then
    echo "MXD node is running"
else
    echo "ERROR: MXD node failed to start"
    cat /tmp/mxd.log
    exit 1
fi

echo "=== Setup complete at $(date) ==="

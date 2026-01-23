#!/bin/bash
# First, disable and stop the systemd service to prevent it from auto-starting
systemctl disable mxd-node 2>/dev/null || true
systemctl stop mxd-node 2>/dev/null || true
pkill -9 -f mxd_node 2>/dev/null || true
sleep 2

# Clear all data including any existing config
rm -rf /opt/mxdlib/build/data/*
rm -f /tmp/mxd.log
rm -f /opt/mxdlib/build/default_config.json

# Write the new config BEFORE waiting
cd /opt/mxdlib/build
cat > default_config.json << 'CONFIGEOF'
{
    "node_id": "test_node",
    "network_type": "isolated_test_v1",
    "port": 8000,
    "data_dir": "./data",
    "node_name": "MXD Test Node",
    "initial_stake": 100.0,
    "preferred_sign_algo": 1,
    "bootstrap_nodes": [
        "34.69.130.116:8000",
        "34.9.148.231:8000",
        "34.170.110.41:8000",
        "136.113.63.73:8000",
        "34.57.137.242:8000",
        "34.45.66.193:8000",
        "136.112.135.164:8000",
        "35.192.183.124:8000",
        "34.132.211.147:8000",
        "136.113.221.248:8000"
    ],
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

# Verify config was written
if [ ! -f default_config.json ]; then
    echo "ERROR: Failed to write config file" >> /tmp/reset.log
    exit 1
fi

echo "Config file written, waiting for all nodes to be ready (60 seconds)..." >> /tmp/reset.log

# Wait for all nodes to be ready (60 seconds)
sleep 60

# Start fresh - log to both file and syslog
./lib/mxd_node --config /opt/mxdlib/build/default_config.json --http-api 8081 2>&1 | tee /tmp/mxd.log | logger -t mxd_node &
echo "MXD node started fresh at $(date)" >> /tmp/reset.log

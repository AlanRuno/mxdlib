#!/bin/bash

#==============================================================================
# Enable Smart Contracts on Testnet Nodes
#
# This script:
# 1. Deploys contracts-enabled configs to all nodes
# 2. Restarts nodes to apply new config
# 3. Verifies contracts initialization
#==============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
GCP_ZONE="us-central1-a"
TEMPLATE_CONFIG="config_with_contracts.json"

# GCP testnet nodes
declare -a NODES=(
    "mxd-test-node-testing-0"
    "mxd-test-node-testing-1"
    "mxd-test-node-testing-2"
    "mxd-test-node-testing-3"
    "mxd-test-node-testing-4"
    "mxd-test-node-testing-5"
    "mxd-test-node-testing-6"
    "mxd-test-node-testing-7"
    "mxd-test-node-testing-8"
    "mxd-test-node-testing-9"
)

#==============================================================================
# Helper Functions
#==============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

gcp_exec() {
    local node=$1
    local cmd=$2
    gcloud compute ssh "$node" --zone="$GCP_ZONE" --command="$cmd" 2>&1
}

#==============================================================================
# Create config for each node
#==============================================================================

log_step "Creating node-specific configs with contracts enabled"

for i in {0..9}; do
    node_config="node${i}_config.json"

    # Copy template and replace placeholders
    sed "s/NODE_ID_PLACEHOLDER/testnet-node-${i}/g; s/NODE_NUM/${i}/g" \
        "$TEMPLATE_CONFIG" > "$node_config"

    log_success "Created $node_config"
done

#==============================================================================
# Deploy configs to nodes
#==============================================================================

log_step "Deploying contracts-enabled configs to all nodes"

for i in {0..9}; do
    node="${NODES[$i]}"
    node_config="node${i}_config.json"

    echo ""
    log_info "Deploying to $node..."

    # Stop service
    log_info "Stopping mxd-node service..."
    gcp_exec "$node" "sudo systemctl stop mxd-node || true" > /dev/null
    sleep 2

    # Create backup of old config
    gcp_exec "$node" "sudo mkdir -p /opt/mxdlib/config_backups" > /dev/null
    gcp_exec "$node" "sudo cp /opt/mxdlib/build/lib/config.json /opt/mxdlib/config_backups/config.backup.\$(date +%Y%m%d_%H%M%S) 2>/dev/null || true" > /dev/null

    # Upload new config
    gcloud compute scp "$node_config" "$node:/tmp/config.json" --zone="$GCP_ZONE" 2>&1 | grep -v "^Updating" || true

    # Move config to correct location
    gcp_exec "$node" "sudo mkdir -p /opt/mxdlib/build/lib" > /dev/null
    gcp_exec "$node" "sudo mv /tmp/config.json /opt/mxdlib/build/lib/config.json" > /dev/null
    gcp_exec "$node" "sudo chmod 644 /opt/mxdlib/build/lib/config.json" > /dev/null

    log_success "Config deployed to $node"

    # Start service
    log_info "Starting mxd-node service..."
    gcp_exec "$node" "sudo systemctl start mxd-node" > /dev/null
    sleep 3

    # Verify service status
    if gcp_exec "$node" "sudo systemctl is-active mxd-node" | grep -q "active"; then
        log_success "$node service started"
    else
        log_error "$node service failed to start"
        log_info "Showing last 10 log lines:"
        gcp_exec "$node" "sudo journalctl -u mxd-node -n 10 --no-pager"
    fi
done

#==============================================================================
# Verify Contracts Initialization
#==============================================================================

echo ""
log_step "Verifying contracts initialization (waiting 10 seconds for startup)..."
sleep 10

SUCCESS_COUNT=0
FAILURE_COUNT=0

for i in {0..9}; do
    node="${NODES[$i]}"

    log_info "Checking $node..."

    # Check for contracts initialization logs
    CONTRACTS_LOG=$(gcp_exec "$node" "sudo journalctl -u mxd-node --since '1 minute ago' | grep -E '(contracts.*initialized|Smart contracts module)' | tail -3" 2>&1)

    if echo "$CONTRACTS_LOG" | grep -q "Smart contracts module initialized"; then
        log_success "$node: Contracts enabled and initialized ✅"
        ((SUCCESS_COUNT++))
    elif echo "$CONTRACTS_LOG" | grep -q "disabled"; then
        log_error "$node: Contracts still disabled ❌"
        ((FAILURE_COUNT++))
    else
        log_error "$node: Could not verify contracts status"
        ((FAILURE_COUNT++))
    fi
done

#==============================================================================
# Summary
#==============================================================================

echo ""
echo -e "${CYAN}════════════════════════════════════════════${NC}"
echo -e "${CYAN}  SMART CONTRACTS ENABLEMENT COMPLETE${NC}"
echo -e "${CYAN}════════════════════════════════════════════${NC}"
echo ""
echo "Results:"
echo "  ✓ Contracts enabled:  $SUCCESS_COUNT nodes"
if [ $FAILURE_COUNT -gt 0 ]; then
    echo -e "  ${RED}✗ Failed:             $FAILURE_COUNT nodes${NC}"
else
    echo "  ✗ Failed:             0 nodes"
fi
echo ""

if [ $FAILURE_COUNT -gt 0 ]; then
    log_error "Some nodes failed to enable contracts"
    exit 1
else
    log_success "All nodes have contracts enabled!"

    echo ""
    echo "Next steps:"
    echo "  1. Deploy a test contract:"
    echo "     ./deploy_test_contract.sh"
    echo ""
    echo "  2. Execute contract functions:"
    echo "     ./test_contract_execution.sh"
    echo ""
    echo "  3. Monitor contracts:"
    echo "     gcloud compute ssh <node> --zone=$GCP_ZONE --command='sudo journalctl -u mxd-node -f | grep contracts'"
    echo ""
fi

# Cleanup temp configs
rm -f node*_config.json

exit 0

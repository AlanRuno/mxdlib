#!/bin/bash

#==============================================================================
# Deploy Simple Math Contract to MXD Testnet
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
CONTRACT_HEX=$(cat simple_math.hex)
NODE_IP="34.61.51.191"  # Node 0
API_PORT="8081"

echo -e "${CYAN}════════════════════════════════════════${NC}"
echo -e "${CYAN}  Deploying Simple Math Contract${NC}"
echo -e "${CYAN}════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}[INFO]${NC} Contract: simple_math.wasm"
echo -e "${BLUE}[INFO]${NC} Size: 308 bytes"
echo -e "${BLUE}[INFO]${NC} Target: http://${NODE_IP}:${API_PORT}"
echo ""

# Create deployment JSON
DEPLOY_JSON=$(cat <<EOF
{
  "code": "${CONTRACT_HEX}",
  "deployer": "0000000000000000000000000000000000000000"
}
EOF
)

echo -e "${BLUE}[INFO]${NC} Deploying contract via API..."
echo ""

# Deploy contract
RESPONSE=$(curl -s -X POST "http://${NODE_IP}:${API_PORT}/contract/deploy" \
  -H "Content-Type: application/json" \
  -d "${DEPLOY_JSON}" \
  --connect-timeout 30 \
  --max-time 60)

echo -e "${BLUE}[RESPONSE]${NC}"
echo "$RESPONSE" | jq '.' || echo "$RESPONSE"
echo ""

# Check if deployment was successful
if echo "$RESPONSE" | jq -e '.success' > /dev/null 2>&1; then
    CONTRACT_HASH=$(echo "$RESPONSE" | jq -r '.contract_hash')
    GAS_USED=$(echo "$RESPONSE" | jq -r '.gas_used')

    echo -e "${GREEN}[✓]${NC} Contract deployed successfully!"
    echo ""
    echo "Contract Details:"
    echo "  Hash: ${CONTRACT_HASH}"
    echo "  Gas Used: ${GAS_USED}"
    echo ""

    # Save contract hash for later use
    echo "${CONTRACT_HASH}" > deployed_contract_hash.txt
    echo -e "${BLUE}[INFO]${NC} Contract hash saved to: deployed_contract_hash.txt"
    echo ""

    echo "Available Functions:"
    echo "  • add(a, b) - Add two numbers"
    echo "  • multiply(a, b) - Multiply two numbers"
    echo "  • subtract(a, b) - Subtract b from a"
    echo "  • divide(a, b) - Divide a by b"
    echo "  • factorial(n) - Calculate factorial of n"
    echo "  • is_even(n) - Check if n is even (returns 1 or 0)"
    echo "  • power(a, b) - Calculate a^b"
    echo "  • compute_heavy(iterations) - Test gas metering"
    echo ""
    echo "Next Steps:"
    echo "  1. Test contract execution:"
    echo "     ./test_contract.sh ${CONTRACT_HASH} add 5 3"
    echo ""
    echo "  2. List all contracts:"
    echo "     curl http://${NODE_IP}:${API_PORT}/contracts | jq"
    echo ""
    echo "  3. Get contract info:"
    echo "     curl http://${NODE_IP}:${API_PORT}/contract/${CONTRACT_HASH} | jq"
    echo ""

    exit 0
else
    echo -e "${RED}[✗]${NC} Contract deployment failed!"
    echo ""

    # Check for specific error messages
    if echo "$RESPONSE" | grep -q "Smart contracts are disabled"; then
        echo -e "${YELLOW}[WARNING]${NC} Smart contracts are not enabled on this node"
        echo "Run: cd ../.. && ./testnet/enable_contracts.sh"
    elif echo "$RESPONSE" | grep -q "Connection refused"; then
        echo -e "${YELLOW}[WARNING]${NC} Cannot connect to node API"
        echo "Check if node is running and API port ${API_PORT} is accessible"
    fi

    exit 1
fi

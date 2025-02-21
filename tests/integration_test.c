#include "../include/mxd_blockchain.h"
#include "../include/mxd_blockchain_sync.h"
#include "../include/mxd_rsc.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_ntp.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_crypto.h"
#include "../include/blockchain/mxd_rsc_internal.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#define TEST_NODE_COUNT 5
#define MIN_TX_RATE 10
#define MAX_LATENCY_MS 3000
#define MAX_CONSECUTIVE_ERRORS 10
#define TEST_TRANSACTIONS 20

static void test_node_lifecycle(void) {
    TEST_START("Node Lifecycle Integration Test");
    
    // Initialize test nodes
    mxd_node_stake_t nodes[TEST_NODE_COUNT];
    double total_stake = 0.0;
    uint32_t error_count = 0;
    uint64_t tx_start_time = get_current_time_ms();
    uint32_t tx_count = 0;
    
    // Initialize UTXO database
    TEST_ASSERT(mxd_init_utxo_db() == 0, "UTXO database initialization");
    
    // Create and configure nodes
    for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
        // Generate unique address for each node
        char passphrase[256];
        uint8_t property_key[64];
        uint8_t public_key[256];
        uint8_t private_key[128];
        char address[42];
        
        TEST_ASSERT(mxd_generate_passphrase(passphrase, sizeof(passphrase)) == 0,
                    "Passphrase generation");
        TEST_ASSERT(mxd_derive_property_key(passphrase, "1234", property_key) == 0,
                    "Property key derivation");
        TEST_ASSERT(mxd_generate_keypair(property_key, public_key, private_key) == 0,
                    "Keypair generation");
        TEST_ASSERT(mxd_generate_address(public_key, address, sizeof(address)) == 0,
                    "Address generation");
        TEST_ASSERT(mxd_validate_address(address) == 0, "Address validation");
        
        // Initialize node configuration
        memset(&nodes[i], 0, sizeof(mxd_node_stake_t));
        snprintf(nodes[i].node_id, sizeof(nodes[i].node_id), "node-%zu", i);
        nodes[i].stake_amount = 100.0 + (i * 10.0);  // Significant stakes
        nodes[i].active = 1;
        memcpy(nodes[i].public_key, public_key, sizeof(public_key));
        
        // Initialize metrics
        TEST_ASSERT(mxd_init_node_metrics(&nodes[i].metrics) == 0,
                   "Node metrics initialization");
        nodes[i].metrics.response_count = MXD_MIN_RESPONSE_COUNT;
        nodes[i].metrics.min_response_time = 100;
        nodes[i].metrics.max_response_time = 200;
        nodes[i].metrics.avg_response_time = 150;
        nodes[i].metrics.last_update = get_current_time_ms();
        
        total_stake += nodes[i].stake_amount;
    }
    
    // Test P2P network setup
    uint64_t start_time = get_current_time_ms();
    for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
        uint16_t port = 12345 + i;
        TEST_ASSERT(mxd_init_p2p(port, nodes[i].public_key) == 0,
                   "P2P initialization");
        TEST_ASSERT(mxd_start_p2p() == 0, "P2P startup");
        
        // Connect to previous nodes
        for (size_t j = 0; j < i; j++) {
            TEST_ASSERT(mxd_add_peer("127.0.0.1", 12345 + j) == 0,
                       "Peer connection");
        }
        
        mxd_stop_p2p();  // Stop before next node starts
    }
    uint64_t network_latency = get_current_time_ms() - start_time;
    TEST_ASSERT(network_latency <= MAX_LATENCY_MS,
               "Network setup within latency limit");
    
    // Test blockchain synchronization
    start_time = get_current_time_ms();
    TEST_ASSERT(mxd_sync_blockchain() == 0, "Blockchain synchronization");
    uint64_t sync_latency = get_current_time_ms() - start_time;
    TEST_ASSERT(sync_latency <= MAX_LATENCY_MS,
               "Blockchain sync within latency limit");
    
    // Test transaction processing
    TEST_TX_RATE_START("Transaction Processing");
    
    mxd_transaction_t transactions[TEST_TRANSACTIONS];
    uint8_t genesis_hash[64] = {0};
    
    // Create genesis transaction
    mxd_transaction_t genesis_tx;
    TEST_ASSERT(mxd_create_transaction(&genesis_tx) == 0,
               "Genesis transaction creation");
    TEST_ASSERT(mxd_add_tx_output(&genesis_tx, nodes[0].public_key, 1000.0) == 0,
               "Genesis output addition");
    TEST_ASSERT(mxd_calculate_tx_hash(&genesis_tx, genesis_hash) == 0,
               "Genesis hash calculation");
    
    // Process transactions through nodes
    for (int i = 0; i < TEST_TRANSACTIONS; i++) {
        TEST_ASSERT(mxd_create_transaction(&transactions[i]) == 0,
                   "Transaction creation");
        TEST_ASSERT(mxd_add_tx_input(&transactions[i], genesis_hash, 0,
                   nodes[0].public_key) == 0, "Input addition");
        TEST_ASSERT(mxd_add_tx_output(&transactions[i], nodes[1].public_key,
                   10.0) == 0, "Output addition");
        
        uint64_t validation_start = get_current_time_ms();
        for (size_t j = 0; j < TEST_NODE_COUNT; j++) {
            int validation_result = mxd_validate_transaction(&transactions[i]);
            if (validation_result != 0) {
                error_count++;
                TEST_ERROR_COUNT(error_count, MAX_CONSECUTIVE_ERRORS);
            } else {
                error_count = 0;
                TEST_TX_RATE_UPDATE("Transaction Processing", MIN_TX_RATE);
                
                uint64_t validation_time = get_current_time_ms() - validation_start;
                TEST_ASSERT(validation_time <= MAX_LATENCY_MS,
                           "Transaction validation within latency limit");
                
                TEST_ASSERT(mxd_update_node_metrics(&nodes[j], validation_time,
                    get_current_time_ms()) == 0, "Metrics update");
            }
        }
    }
    
    // Test rapid stake consensus
    TEST_ASSERT(mxd_update_rapid_table(nodes, TEST_NODE_COUNT, total_stake) == 0,
               "Rapid stake table update");
    
    // Test tip distribution
    double total_tip = 100.0;
    TEST_ASSERT(mxd_distribute_tips(nodes, TEST_NODE_COUNT, total_tip) == 0,
               "Tip distribution");
    
    // Verify tip distribution follows whitepaper pattern
    double remaining = total_tip;
    for (size_t i = 0; i < TEST_NODE_COUNT; i++) {
        double expected_tip;
        if (i == TEST_NODE_COUNT - 1) {
            expected_tip = remaining;
        } else {
            expected_tip = remaining * 0.5;
            remaining -= expected_tip;
        }
        TEST_ASSERT(fabs(nodes[i].metrics.tip_share - expected_tip) < 0.0001,
                   "Tip distribution matches whitepaper pattern");
    }
    
    // Cleanup
    for (int i = 0; i < TEST_TRANSACTIONS; i++) {
        mxd_free_transaction(&transactions[i]);
    }
    mxd_free_transaction(&genesis_tx);
    mxd_init_utxo_db();
    
    TEST_END("Node Lifecycle Integration Test");
}

int main(void) {
    // Initialize NTP for time synchronization
    TEST_ASSERT(mxd_init_ntp() == 0, "NTP initialization");
    
    test_node_lifecycle();
    
    return 0;
}

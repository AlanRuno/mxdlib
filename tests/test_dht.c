#include "../include/mxd_dht.h"
#include "../include/mxd_crypto.h"
#include "../include/blockchain/mxd_dht_internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Test node ID generation and distance calculation
static void test_node_id(void) {
    printf("Testing node ID generation...\n");
    
    // Generate two node IDs from different public keys
    uint8_t pub_key1[32] = {1};
    uint8_t pub_key2[32] = {2};
    
    assert(mxd_init_dht(pub_key1) == 0);
    mxd_node_id_t id1;
    memcpy(id1.id, dht_state.routing_table.local_id.id, 20);
    
    mxd_stop_dht();
    
    assert(mxd_init_dht(pub_key2) == 0);
    mxd_node_id_t id2;
    memcpy(id2.id, dht_state.routing_table.local_id.id, 20);
    
    // Verify IDs are different
    assert(memcmp(id1.id, id2.id, 20) != 0);
    
    printf("Node ID test passed\n");
}

// Test k-bucket operations
static void test_k_buckets(void) {
    printf("Testing k-bucket operations...\n");
    
    uint8_t pub_key[32] = {1};
    assert(mxd_init_dht(pub_key) == 0);
    
    // Initialize DHT with test key
    uint8_t test_key[32] = {1};
    assert(mxd_init_dht(test_key) == 0);
    assert(mxd_start_dht(8000) == 0); // Start DHT service

    // Wait for DHT to initialize
    usleep(100000); // 100ms

    // Add nodes to buckets
    int successful_nodes = 0;
    for (int i = 0; i < K_PARAM && successful_nodes < K_PARAM/2; i++) {
        char addr[32];
        snprintf(addr, sizeof(addr), "192.168.1.%d", i);
        uint8_t node_id[20] = {0};
        node_id[0] = i; // Ensure unique node IDs
        if (mxd_dht_add_node(addr, 8000 + i, node_id) == 0) {
            successful_nodes++;
        }
        usleep(10000); // Small delay between adds
    }

    // Verify at least half of K_PARAM nodes were added
    assert(successful_nodes >= K_PARAM/2);

    // Stop DHT service
    assert(mxd_stop_dht() == 0);
    
    // Verify bucket sizes
    for (size_t i = 0; i < BUCKET_COUNT; i++) {
        assert(dht_state.routing_table.buckets[i].node_count <= K_PARAM);
    }
    
    printf("K-bucket test passed\n");
}

// Test value storage and retrieval
static void test_value_storage(void) {
    printf("Testing value storage...\n");
    
    // Store value
    const char *key = "test_key";
    const char *value = "test_value";
    assert(mxd_dht_store((uint8_t *)key, strlen(key),
                         (uint8_t *)value, strlen(value)) == 0);
    
    // Retrieve value
    uint8_t retrieved[256];
    size_t length = sizeof(retrieved);
    assert(mxd_dht_find_value((uint8_t *)key, strlen(key),
                             retrieved, &length) == 0);
    
    // Verify value
    assert(length == strlen(value));
    assert(memcmp(retrieved, value, length) == 0);
    
    printf("Value storage test passed\n");
}

// Test node discovery
static void test_node_discovery(void) {
    printf("Testing node discovery...\n");
    
    // Start DHT
    assert(mxd_start_dht(8000) == 0);
    
    // Add some test nodes
    for (int i = 0; i < 10; i++) {
        char addr[32];
        snprintf(addr, sizeof(addr), "192.168.1.%d", i);
        uint8_t node_id[20] = {i};
        assert(mxd_dht_add_node(addr, 8000 + i, node_id) == 0);
    }
    
    // Find nodes closest to a target
    mxd_node_id_t target = {{0}};
    mxd_dht_node_t nodes[K_PARAM];
    size_t node_count = K_PARAM;
    assert(mxd_dht_find_nodes(&target, nodes, &node_count) == 0);
    
    // Verify we got some nodes back
    assert(node_count > 0);
    
    // Stop DHT
    assert(mxd_stop_dht() == 0);
    
    printf("Node discovery test passed\n");
}

// Test NAT traversal
static void test_nat_traversal(void) {
    printf("Testing NAT traversal...\n");
    
    // Enable NAT traversal
    assert(mxd_dht_enable_nat_traversal() == 0);
    
    // Verify it's enabled
    mxd_dht_stats_t stats;
    assert(mxd_dht_get_stats(&stats) == 0);
    assert(dht_state.nat_traversal == 1);
    
    // Disable NAT traversal
    assert(mxd_dht_disable_nat_traversal() == 0);
    
    // Verify it's disabled
    assert(mxd_dht_get_stats(&stats) == 0);
    assert(dht_state.nat_traversal == 0);
    
    printf("NAT traversal test passed\n");
}

// Test statistics
static void test_statistics(void) {
    printf("Testing DHT statistics...\n");
    
    mxd_dht_stats_t stats;
    assert(mxd_dht_get_stats(&stats) == 0);
    
    // Initial stats should be zero
    assert(stats.total_nodes == 0);
    assert(stats.active_nodes == 0);
    assert(stats.stored_values == 0);
    
    // Add some nodes and values
    for (int i = 0; i < 5; i++) {
        char addr[32];
        snprintf(addr, sizeof(addr), "192.168.1.%d", i);
        uint8_t node_id[20] = {i};
        assert(mxd_dht_add_node(addr, 8000 + i, node_id) == 0);
        
        char key[32], value[32];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);
        assert(mxd_dht_store((uint8_t *)key, strlen(key),
                            (uint8_t *)value, strlen(value)) == 0);
    }
    
    // Verify updated stats
    assert(mxd_dht_get_stats(&stats) == 0);
    assert(stats.total_nodes == 5);
    assert(stats.active_nodes == 5);
    assert(stats.stored_values == 5);
    
    printf("Statistics test passed\n");
}

int main(void) {
    printf("Starting DHT tests...\n");
    
    test_node_id();
    test_k_buckets();
    test_value_storage();
    test_node_discovery();
    test_nat_traversal();
    test_statistics();
    
    printf("All DHT tests passed!\n");
    return 0;
}

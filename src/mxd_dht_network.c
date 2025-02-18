#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mxd_dht.h"
#include "mxd_config.h"

// Test functions for DHT network operations
int test_node_id(void) {
    uint8_t node_id[32];
    mxd_generate_node_id(node_id);
    return memcmp(node_id, "\0\0\0\0", 4) != 0;
}

int test_buckets(void) {
    mxd_bucket_t bucket;
    mxd_init_bucket(&bucket);
    return bucket.size == 0;
}

int run_network_tests(const char* config_file) {
    printf("Running network tests with config: %s\n", config_file);
    
    // Load configuration
    mxd_config_t config;
    if (mxd_load_config(config_file, &config) != 0) {
        printf("Failed to load configuration\n");
        return 1;
    }
    
    // Initialize DHT node
    if (mxd_init_node(&config) != 0) {
        printf("Failed to initialize DHT node\n");
        return 1;
    }
    
    printf("DHT node initialized successfully\n");
    printf("Waiting for network stabilization...\n");
    sleep(5);
    
    // Run basic connectivity tests
    if (!test_node_id()) {
        printf("Node ID test failed\n");
        return 1;
    }
    
    if (!test_buckets()) {
        printf("K-bucket test failed\n");
        return 1;
    }
    
    printf("Network tests completed successfully\n");
    return 0;
}

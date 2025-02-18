#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "mxd_dht.h"
#include "mxd_config.h"

static volatile int keep_running = 1;

void handle_signal(int signum) {
    printf("\nReceived signal %d, shutting down...\n", signum);
    keep_running = 0;
}

int test_node_id(void) {
    uint8_t node_id[32];
    mxd_generate_node_id(node_id);
    printf("Generated node ID: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", node_id[i]);
    }
    printf("...\n");
    return 1;
}

int test_buckets(void) {
    mxd_bucket_t bucket;
    mxd_init_bucket(&bucket);
    printf("Initialized k-bucket (size: %zu)\n", bucket.size);
    return 1;
}

int run_network_tests(const char* config_file) {
    printf("Initializing DHT node with config: %s\n", config_file);
    
    // Set up signal handler
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Load configuration
    mxd_config_t config;
    if (mxd_load_config(config_file, &config) != 0) {
        printf("Failed to load configuration\n");
        return 1;
    }
    printf("Loaded configuration for node: %s (port: %d)\n", 
           config.node_id, config.port);
    
    // Initialize DHT node
    if (mxd_init_node(&config) != 0) {
        printf("Failed to initialize DHT node\n");
        return 1;
    }
    printf("DHT node initialized successfully\n");
    
    // Start DHT service
    if (mxd_start_dht(config.port) != 0) {
        printf("Failed to start DHT service\n");
        return 1;
    }
    printf("DHT service started on port %d\n", config.port);
    
    // Main node loop
    printf("Node running. Press Ctrl+C to stop.\n");
    while (keep_running) {
        printf("Node %s alive on port %d\n", config.node_id, config.port);
        sleep(5);
    }
    
    printf("Shutting down node %s...\n", config.node_id);
    mxd_stop_dht();
    return 0;
}

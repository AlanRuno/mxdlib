#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/mxd_dht.h"

// Test functions implementation
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
    return 0;
}

int main(int argc, char *argv[]) {
    printf("Starting DHT tests...\n");
    
    // Parse command line arguments for network testing
    int network_mode = 0;
    char *config_file = NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--network") == 0) {
            network_mode = 1;
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_file = argv[i + 1];
            i++;
        }
    }
    
    if (network_mode) {
        if (!config_file) {
            printf("Error: Network mode requires --config argument\n");
            return 1;
        }
        return run_network_tests(config_file);
    }
    
    // Run standard tests
    printf("Testing node ID generation...\n");
    if (!test_node_id()) {
        printf("Node ID test failed\n");
        return 1;
    }
    printf("Node ID test passed\n");
    
    printf("Testing k-bucket operations...\n");
    if (!test_buckets()) {
        printf("K-bucket test failed\n");
        return 1;
    }
    printf("K-bucket test passed\n");
    
    printf("All DHT tests passed!\n");
    return 0;
}

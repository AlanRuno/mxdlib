#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "mxd_dht.h"
#include "mxd_config.h"

static int dht_initialized = 0;
static uint16_t dht_port = 0;
static int nat_enabled = 0;
static char node_id[64] = {0};

void mxd_generate_node_id(uint8_t* node_id) {
    for (int i = 0; i < MXD_NODE_ID_SIZE; i++) {
        node_id[i] = (uint8_t)i;
    }
}

void mxd_init_bucket(mxd_bucket_t* bucket) {
    bucket->size = 0;
    memset(bucket->nodes, 0, sizeof(bucket->nodes));
}

int mxd_init_node(const void* config) {
    if (!config) {
        printf("Error: NULL config provided\n");
        fflush(stdout);
        return 1;
    }
    
    const mxd_config_t* cfg = (const mxd_config_t*)config;
    printf("Initializing DHT node %s (port %d)\n", cfg->node_id, cfg->port);
    fflush(stdout);
    
    strncpy(node_id, cfg->node_id, sizeof(node_id) - 1);
    dht_initialized = 1;
    return 0;
}

int mxd_init_dht(const uint8_t* public_key) {
    if (!dht_initialized) {
        printf("Error: Node not initialized\n");
        fflush(stdout);
        return 1;
    }
    printf("Initializing DHT with public key for node %s\n", node_id);
    fflush(stdout);
    return 0;
}

int mxd_start_dht(uint16_t port) {
    if (!dht_initialized) {
        printf("Error: DHT not initialized\n");
        fflush(stdout);
        return 1;
    }
    
    dht_port = port;
    printf("DHT service started on port %d for node %s\n", port, node_id);
    fflush(stdout);
    return 0;
}

int mxd_stop_dht(void) {
    if (!dht_initialized) {
        return 0;
    }
    
    printf("Stopping DHT service on port %d for node %s\n", dht_port, node_id);
    fflush(stdout);
    dht_initialized = 0;
    dht_port = 0;
    return 0;
}

int mxd_dht_find_nodes(const mxd_node_id_t* target, mxd_dht_node_t* nodes, size_t* count) {
    if (!dht_initialized || !target || !nodes || !count) {
        return 1;
    }
    *count = 0;
    return 0;
}

int mxd_dht_enable_nat_traversal(void) {
    if (!dht_initialized) {
        return 1;
    }
    nat_enabled = 1;
    printf("NAT traversal enabled for node %s\n", node_id);
    fflush(stdout);
    return 0;
}

int mxd_dht_disable_nat_traversal(void) {
    if (!dht_initialized) {
        return 1;
    }
    nat_enabled = 0;
    printf("NAT traversal disabled for node %s\n", node_id);
    fflush(stdout);
    return 0;
}

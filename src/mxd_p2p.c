#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "mxd_config.h"
#include "mxd_dht.h"
#include "mxd_p2p.h"

static int p2p_initialized = 0;
static uint16_t p2p_port = 0;
static uint8_t node_public_key[32] = {0};
static mxd_config_t node_config;

int mxd_init_p2p(uint16_t port, const uint8_t* public_key) {
    if (p2p_initialized) {
        return 0;
    }
    
    p2p_port = port;
    memcpy(node_public_key, public_key, 32);
    
    // Initialize node configuration
    memset(&node_config, 0, sizeof(node_config));
    node_config.port = port;
    snprintf(node_config.node_id, sizeof(node_config.node_id), "peer_%d", port);
    snprintf(node_config.data_dir, sizeof(node_config.data_dir), "data");
    
    p2p_initialized = 1;
    printf("P2P initialized on port %d\n", port);
    return 0;
}

int mxd_start_p2p(void) {
    if (!p2p_initialized) {
        printf("P2P not initialized\n");
        return 1;
    }
    printf("P2P started on port %d\n", p2p_port);
    return 0;
}

int mxd_stop_p2p(void) {
    if (!p2p_initialized) {
        return 0;
    }
    p2p_initialized = 0;
    printf("P2P stopped\n");
    return 0;
}

int mxd_add_peer(const char* address, uint16_t port) {
    if (!p2p_initialized) {
        return 1;
    }
    printf("Added peer %s:%d\n", address, port);
    return 0;
}

int mxd_broadcast_message(mxd_message_type_t type, const void* payload, size_t payload_length) {
    if (!p2p_initialized) {
        return 1;
    }
    printf("Broadcasting message type %d\n", type);
    return 0;
}

int mxd_start_peer_discovery(void) {
    if (!p2p_initialized) {
        printf("Error: P2P not initialized\n");
        return 1;
    }
    
    // Initialize DHT for peer discovery
    if (mxd_init_node(&node_config) != 0) {
        printf("Error: Failed to initialize DHT node\n");
        return 1;
    }
    
    if (mxd_start_dht(p2p_port) != 0) {
        printf("Error: Failed to start DHT service\n");
        return 1;
    }
    
    printf("Peer discovery started\n");
    return 0;
}

int mxd_stop_peer_discovery(void) {
    mxd_stop_dht();
    printf("Peer discovery stopped\n");
    return 0;
}

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "mxd_config.h"
#include "mxd_crypto.h"
#include "mxd_dht.h"
#include "mxd_p2p.h"

#define MXD_NETWORK_MAGIC 0x4D584431 // "MXD1" in ASCII

static int p2p_initialized = 0;
static uint16_t p2p_port = 0;
static uint8_t node_public_key[32] = {0};
static mxd_config_t node_config;
static uint64_t last_message_time = 0;
static size_t messages_this_second = 0;
static uint32_t consecutive_errors = 0;
static mxd_message_handler_t message_handler = NULL;

// Set message handler callback
int mxd_set_message_handler(mxd_message_handler_t handler) {
    if (!p2p_initialized) {
        return -1;
    }
    message_handler = handler;
    return 0;
}

// Handle incoming message
static int handle_incoming_message(const char *address, uint16_t port, 
                                 const mxd_message_header_t *header, 
                                 const void *payload) {
    if (!address || !header || !payload) {
        return -1;
    }

    // Check rate limit
    if (check_rate_limit() != 0) {
        return -1;
    }

    // Validate message
    if (validate_message(header, payload) != 0) {
        consecutive_errors++;
        if (consecutive_errors >= 10) {
            return -1;
        }
        return -1;
    }

    // Reset error count on successful validation
    consecutive_errors = 0;

    // Call message handler if registered
    if (message_handler) {
        message_handler(address, port, header->type, payload, header->length);
    }

    return 0;
}

// Message validation function
static int validate_message(const mxd_message_header_t *header, const void *payload) {
    if (!header || !payload) {
        return -1;
    }

    // Check magic number
    if (header->magic != MXD_NETWORK_MAGIC) {
        return -1;
    }

    // Check message size
    if (header->length > MXD_MAX_MESSAGE_SIZE) {
        return -1;
    }
    
    // Validate message type
    if (header->type > MXD_MSG_TRANSACTIONS) {
        return -1;
    }

    // Compute and verify SHA-512 checksum
    uint8_t computed_checksum[64];
    if (mxd_sha512(payload, header->length, computed_checksum) != 0) {
        return -1;
    }
    
    return memcmp(header->checksum, computed_checksum, 64) == 0 ? 0 : -1;
}

// Rate limiting function
static int check_rate_limit(void) {
    uint64_t current_time = time(NULL);
    
    if (current_time != last_message_time) {
        last_message_time = current_time;
        messages_this_second = 0;
    }
    
    if (++messages_this_second > 100) {
        return -1; // Rate limit exceeded
    }
    
    return 0;
}

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
    if (!p2p_initialized || !payload || payload_length > MXD_MAX_MESSAGE_SIZE) {
        return -1;
    }

    // Check rate limit
    if (check_rate_limit() != 0) {
        return -1;
    }

    // Prepare message header
    mxd_message_header_t header = {
        .magic = MXD_NETWORK_MAGIC,
        .type = type,
        .length = payload_length
    };
    
    // Calculate checksum
    if (mxd_sha512(payload, payload_length, header.checksum) != 0) {
        return -1;
    }

    // Get list of peers
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    if (mxd_get_peers(peers, &peer_count) != 0) {
        return -1;
    }

    // Broadcast to all peers
    uint32_t errors = 0;
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].state != MXD_PEER_CONNECTED) {
            continue;
        }

        // Check peer latency
        if (peers[i].latency > 3000) { // 3 second maximum latency
            continue;
        }

        if (mxd_send_message(peers[i].address, peers[i].port, type, payload, payload_length) != 0) {
            errors++;
            if (errors >= 10) { // Maximum consecutive errors
                consecutive_errors = errors;
                return -1;
            }
        } else {
            errors = 0; // Reset error count on successful send
        }
    }

    consecutive_errors = errors;
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

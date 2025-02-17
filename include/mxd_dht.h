#ifndef MXD_DHT_H
#define MXD_DHT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// DHT node ID (160-bit Kademlia ID)
typedef struct {
    uint8_t id[20];  // SHA-1 hash of node's public key
} mxd_node_id_t;

// DHT node information
typedef struct {
    mxd_node_id_t id;
    char address[64];
    uint16_t port;
    uint64_t last_seen;
    uint32_t rtt;        // Round-trip time in milliseconds
    uint8_t active;      // Node activity status
} mxd_dht_node_t;

// K-bucket structure (Kademlia)
typedef struct {
    mxd_dht_node_t *nodes;
    size_t node_count;
    size_t k;           // Maximum nodes per bucket (k-parameter)
} mxd_k_bucket_t;

// DHT routing table
typedef struct {
    mxd_k_bucket_t *buckets;
    size_t bucket_count;
    mxd_node_id_t local_id;
} mxd_routing_table_t;

// Initialize DHT with local node ID
int mxd_init_dht(const uint8_t *public_key);

// Start DHT operations
int mxd_start_dht(uint16_t port);

// Stop DHT operations
int mxd_stop_dht(void);

// Add node to routing table
int mxd_dht_add_node(const char *address, uint16_t port, const uint8_t *node_id);

// Remove node from routing table
int mxd_dht_remove_node(const mxd_node_id_t *node_id);

// Find closest nodes to target ID
int mxd_dht_find_nodes(const mxd_node_id_t *target, mxd_dht_node_t *nodes, size_t *node_count);

// Store value in DHT
int mxd_dht_store(const uint8_t *key, size_t key_length, const uint8_t *value, size_t value_length);

// Find value in DHT
int mxd_dht_find_value(const uint8_t *key, size_t key_length, uint8_t *value, size_t *value_length);

// Enable NAT traversal
int mxd_dht_enable_nat_traversal(void);

// Disable NAT traversal
int mxd_dht_disable_nat_traversal(void);

// Get DHT statistics
typedef struct {
    size_t total_nodes;
    size_t active_nodes;
    size_t stored_values;
    uint64_t uptime;
    uint64_t messages_sent;
    uint64_t messages_received;
} mxd_dht_stats_t;

int mxd_dht_get_stats(mxd_dht_stats_t *stats);

#ifdef __cplusplus
}
#endif

#endif // MXD_DHT_H

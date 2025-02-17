#include "../include/mxd_dht.h"
#include "../include/mxd_crypto.h"
#include "../include/blockchain/mxd_dht_internal.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// Global DHT state
mxd_dht_state_t dht_state = {0};

// Node distance structure for sorting
typedef struct {
    mxd_dht_node_t node;
    uint8_t distance[20];
} node_distance_t;

// Kademlia constants
#define K_PARAM 20          // Size of k-buckets
#define ALPHA 3             // Number of parallel lookups
#define BUCKET_COUNT 160    // Number of k-buckets (one per bit)
#define REFRESH_INTERVAL 60 // Bucket refresh interval in seconds

// DHT message types
typedef enum {
    DHT_PING = 1,
    DHT_PONG,
    DHT_FIND_NODE,
    DHT_FIND_NODE_REPLY,
    DHT_STORE,
    DHT_FIND_VALUE,
    DHT_FIND_VALUE_REPLY
} mxd_dht_message_type_t;

// DHT message header
typedef struct {
    uint32_t magic;     // "MXD\0"
    uint8_t version;    // Protocol version
    uint8_t type;       // Message type
    mxd_node_id_t sender_id;
    uint8_t signature[64];  // Message signature
} mxd_dht_message_header_t;

// DHT value storage
typedef struct {
    uint8_t key[20];       // SHA-1 hash of original key
    uint8_t *value;        // Stored value
    size_t value_length;   // Length of value
    time_t expiry;         // Expiration time
} mxd_stored_value_t;

// DHT state
static struct {
    int socket;
    uint16_t port;
    pthread_t main_thread;
    pthread_t refresh_thread;
    volatile int running;
    mxd_routing_table_t routing_table;
    pthread_mutex_t table_mutex;
    uint8_t nat_traversal;
    mxd_dht_stats_t stats;
    mxd_stored_value_t *stored_values;
    size_t value_count;
    size_t value_capacity;
    pthread_mutex_t storage_mutex;
} dht_state = {0};

// Calculate distance between two node IDs (XOR metric)
static void calculate_distance(const mxd_node_id_t *a, const mxd_node_id_t *b, uint8_t *distance) {
    for (int i = 0; i < 20; i++) {
        distance[i] = a->id[i] ^ b->id[i];
    }
}

// Compare distances
static int compare_distances(const uint8_t *d1, const uint8_t *d2) {
    for (int i = 0; i < 20; i++) {
        if (d1[i] != d2[i]) {
            return d1[i] < d2[i] ? -1 : 1;
        }
    }
    return 0;
}

// Get bucket index for node ID
static int get_bucket_index(const mxd_node_id_t *id) {
    uint8_t distance[20];
    calculate_distance(&dht_state.routing_table.local_id, id, distance);
    
    // Find first set bit
    for (int i = 0; i < 20; i++) {
        if (distance[i] == 0) continue;
        
        for (int j = 7; j >= 0; j--) {
            if (distance[i] & (1 << j)) {
                return i * 8 + (7 - j);
            }
        }
    }
    
    return 159; // All bits zero (should never happen with different IDs)
}

// Initialize k-bucket
static int init_k_bucket(mxd_k_bucket_t *bucket) {
    bucket->nodes = malloc(K_PARAM * sizeof(mxd_dht_node_t));
    if (!bucket->nodes) {
        return -1;
    }
    
    bucket->node_count = 0;
    bucket->k = K_PARAM;
    return 0;
}

// Initialize DHT with local node ID
int mxd_init_dht(const uint8_t *public_key) {
    if (!public_key) {
        return -1;
    }
    
    // Calculate local node ID (SHA-1 of public key)
    uint8_t hash[20];
    if (mxd_sha1(public_key, 32, hash) != 0) {
        return -1;
    }
    memcpy(dht_state.routing_table.local_id.id, hash, 20);
    
    // Initialize routing table
    dht_state.routing_table.buckets = malloc(BUCKET_COUNT * sizeof(mxd_k_bucket_t));
    if (!dht_state.routing_table.buckets) {
        return -1;
    }
    
    for (size_t i = 0; i < BUCKET_COUNT; i++) {
        if (init_k_bucket(&dht_state.routing_table.buckets[i]) != 0) {
            for (size_t j = 0; j < i; j++) {
                free(dht_state.routing_table.buckets[j].nodes);
            }
            free(dht_state.routing_table.buckets);
            return -1;
        }
    }
    
    dht_state.routing_table.bucket_count = BUCKET_COUNT;
    
    // Initialize mutexes
    if (pthread_mutex_init(&dht_state.table_mutex, NULL) != 0 ||
        pthread_mutex_init(&dht_state.storage_mutex, NULL) != 0) {
        for (size_t i = 0; i < BUCKET_COUNT; i++) {
            free(dht_state.routing_table.buckets[i].nodes);
        }
        free(dht_state.routing_table.buckets);
        pthread_mutex_destroy(&dht_state.table_mutex);
        return -1;
    }
    
    // Initialize storage
    dht_state.stored_values = NULL;
    dht_state.value_count = 0;
    dht_state.value_capacity = 0;
    
    // Initialize statistics
    memset(&dht_state.stats, 0, sizeof(dht_state.stats));
    
    return 0;
}

// Forward declarations for thread functions
static void *dht_main_thread(void *arg) {
    uint8_t buffer[65536];
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    while (dht_state.running) {
        // Receive message
        ssize_t received = recvfrom(dht_state.socket, buffer, sizeof(buffer), 0,
                                  (struct sockaddr *)&addr, &addr_len);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000); // Sleep 1ms if no data
                continue;
            }
            break;
        }

        // Parse message header
        if (received < sizeof(mxd_dht_message_header_t)) {
            continue;
        }

        mxd_dht_message_header_t *header = (mxd_dht_message_header_t *)buffer;
        if (header->magic != 0x4D584400) { // "MXD\0"
            continue;
        }

        // Handle message based on type
        switch (header->type) {
            case DHT_PING:
                // Send pong response
                header->type = DHT_PONG;
                sendto(dht_state.socket, header, sizeof(*header), 0,
                      (struct sockaddr *)&addr, addr_len);
                break;

            case DHT_FIND_NODE:
                // Find closest nodes and respond
                if (received < sizeof(*header) + 20) break;
                mxd_node_id_t *target = (mxd_node_id_t *)(buffer + sizeof(*header));
                mxd_dht_node_t nodes[K_PARAM];
                size_t node_count = K_PARAM;
                
                if (mxd_dht_find_nodes(target, nodes, &node_count) == 0) {
                    // Send response
                    header->type = DHT_FIND_NODE_REPLY;
                    memcpy(buffer + sizeof(*header), nodes,
                          node_count * sizeof(mxd_dht_node_t));
                    sendto(dht_state.socket, buffer,
                          sizeof(*header) + node_count * sizeof(mxd_dht_node_t),
                          0, (struct sockaddr *)&addr, addr_len);
                }
                break;

            case DHT_STORE:
                // Store value in local storage
                if (received < sizeof(*header) + 24) break; // Min key size
                uint32_t key_length = *(uint32_t *)(buffer + sizeof(*header));
                if (received < sizeof(*header) + 24 + key_length) break;
                
                uint32_t value_length = *(uint32_t *)(buffer + sizeof(*header) + 4 + key_length);
                if (received < sizeof(*header) + 24 + key_length + value_length) break;
                
                uint8_t *key = buffer + sizeof(*header) + 8;
                uint8_t *value = key + key_length;
                
                // Store value locally
                pthread_mutex_lock(&dht_state.storage_mutex);
                
                // Calculate key hash
                uint8_t key_hash[20];
                if (mxd_sha1(key, key_length, key_hash) == 0) {
                    // Check if key already exists
                    for (size_t i = 0; i < dht_state.value_count; i++) {
                        if (memcmp(dht_state.stored_values[i].key, key_hash, 20) == 0) {
                            // Update existing value
                            uint8_t *new_value = realloc(dht_state.stored_values[i].value, value_length);
                            if (new_value) {
                                dht_state.stored_values[i].value = new_value;
                                memcpy(dht_state.stored_values[i].value, value, value_length);
                                dht_state.stored_values[i].value_length = value_length;
                                dht_state.stored_values[i].expiry = time(NULL) + 86400; // 24 hours
                            }
                            pthread_mutex_unlock(&dht_state.storage_mutex);
                            break;
                        }
                    }
                    
                    // Add new value if not found
                    if (dht_state.value_count == dht_state.value_capacity) {
                        size_t new_capacity = dht_state.value_capacity ? dht_state.value_capacity * 2 : 16;
                        mxd_stored_value_t *new_values = realloc(dht_state.stored_values,
                                                               new_capacity * sizeof(mxd_stored_value_t));
                        if (new_values) {
                            dht_state.stored_values = new_values;
                            dht_state.value_capacity = new_capacity;
                        }
                    }
                    
                    if (dht_state.value_count < dht_state.value_capacity) {
                        mxd_stored_value_t *stored = &dht_state.stored_values[dht_state.value_count];
                        memcpy(stored->key, key_hash, 20);
                        stored->value = malloc(value_length);
                        if (stored->value) {
                            memcpy(stored->value, value, value_length);
                            stored->value_length = value_length;
                            stored->expiry = time(NULL) + 86400; // 24 hours
                            dht_state.value_count++;
                            dht_state.stats.stored_values++;
                        }
                    }
                }
                
                pthread_mutex_unlock(&dht_state.storage_mutex);
                break;
        }

        // Update node stats
        dht_state.stats.messages_received++;
        
        // Add sender to routing table if not already present
        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, sender_ip, sizeof(sender_ip));
        mxd_dht_add_node(sender_ip, ntohs(addr.sin_port), header->sender_id.id);
    }

    return NULL;
}

static void *dht_refresh_thread(void *arg) {
    while (dht_state.running) {
        pthread_mutex_lock(&dht_state.table_mutex);
        
        // Refresh buckets
        for (size_t i = 0; i < BUCKET_COUNT; i++) {
            mxd_k_bucket_t *bucket = &dht_state.routing_table.buckets[i];
            time_t current_time = time(NULL);
            
            // Remove inactive nodes
            for (size_t j = 0; j < bucket->node_count; j++) {
                if (current_time - bucket->nodes[j].last_seen > REFRESH_INTERVAL) {
                    // Node is inactive
                    if (bucket->nodes[j].active) {
                        bucket->nodes[j].active = 0;
                        dht_state.stats.active_nodes--;
                    }
                    
                    // Try to ping node
                    mxd_dht_message_header_t header = {
                        .magic = 0x4D584400,
                        .version = 1,
                        .type = DHT_PING,
                        .sender_id = dht_state.routing_table.local_id
                    };
                    
                    struct sockaddr_in addr = {0};
                    addr.sin_family = AF_INET;
                    addr.sin_port = htons(bucket->nodes[j].port);
                    if (inet_pton(AF_INET, bucket->nodes[j].address, &addr.sin_addr) > 0) {
                        sendto(dht_state.socket, &header, sizeof(header), 0,
                              (struct sockaddr *)&addr, sizeof(addr));
                        dht_state.stats.messages_sent++;
                    }
                }
            }
        }
        
        pthread_mutex_unlock(&dht_state.table_mutex);
        
        // Clean up expired values
        pthread_mutex_lock(&dht_state.storage_mutex);
        time_t current_time = time(NULL);
        size_t i = 0;
        while (i < dht_state.value_count) {
            if (current_time > dht_state.stored_values[i].expiry) {
                // Remove expired value
                free(dht_state.stored_values[i].value);
                if (i < dht_state.value_count - 1) {
                    memmove(&dht_state.stored_values[i],
                           &dht_state.stored_values[i + 1],
                           (dht_state.value_count - i - 1) * sizeof(mxd_stored_value_t));
                }
                dht_state.value_count--;
                dht_state.stats.stored_values--;
            } else {
                i++;
            }
        }
        pthread_mutex_unlock(&dht_state.storage_mutex);
        
        sleep(REFRESH_INTERVAL);
    }
    
    return NULL;
}

// Compare node distances for sorting
static int compare_node_distances(const void *a, const void *b) {
    const node_distance_t *da = (const node_distance_t *)a;
    const node_distance_t *db = (const node_distance_t *)b;
    return compare_distances(da->distance, db->distance);
}

// Send store message to a node
static int send_store_message(const mxd_dht_node_t *node,
                            const uint8_t *key, size_t key_length,
                            const uint8_t *value, size_t value_length) {
    if (!node || !key || !value) {
        return -1;
    }

    // Create message header
    mxd_dht_message_header_t header = {
        .magic = 0x4D584400,  // "MXD\0"
        .version = 1,
        .type = DHT_STORE,
        .sender_id = dht_state.routing_table.local_id
    };

    // Sign message
    uint8_t message_hash[64];
    mxd_sha512(key, key_length, message_hash);
    // TODO: Sign message_hash using local private key

    // Send message
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(node->port);
    if (inet_pton(AF_INET, node->address, &addr.sin_addr) <= 0) {
        return -1;
    }

    // Send header
    if (sendto(dht_state.socket, &header, sizeof(header), 0,
               (struct sockaddr *)&addr, sizeof(addr)) != sizeof(header)) {
        return -1;
    }

    // Send key and value
    if (sendto(dht_state.socket, key, key_length, 0,
               (struct sockaddr *)&addr, sizeof(addr)) != key_length) {
        return -1;
    }
    if (sendto(dht_state.socket, value, value_length, 0,
               (struct sockaddr *)&addr, sizeof(addr)) != value_length) {
        return -1;
    }

    return 0;
}

// Query value from a node
static int query_value(const mxd_dht_node_t *node,
                      const uint8_t *key, size_t key_length,
                      uint8_t *value, size_t *value_length) {
    if (!node || !key || !value || !value_length) {
        return -1;
    }

    // Create message header
    mxd_dht_message_header_t header = {
        .magic = 0x4D584400,  // "MXD\0"
        .version = 1,
        .type = DHT_FIND_VALUE,
        .sender_id = dht_state.routing_table.local_id
    };

    // Send message
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(node->port);
    if (inet_pton(AF_INET, node->address, &addr.sin_addr) <= 0) {
        return -1;
    }

    // Send header
    if (sendto(dht_state.socket, &header, sizeof(header), 0,
               (struct sockaddr *)&addr, sizeof(addr)) != sizeof(header)) {
        return -1;
    }

    // Send key
    if (sendto(dht_state.socket, key, key_length, 0,
               (struct sockaddr *)&addr, sizeof(addr)) != key_length) {
        return -1;
    }

    // Wait for response
    fd_set read_fds;
    struct timeval timeout;
    FD_ZERO(&read_fds);
    FD_SET(dht_state.socket, &read_fds);
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if (select(dht_state.socket + 1, &read_fds, NULL, NULL, &timeout) <= 0) {
        return -1;
    }

    // Receive response header
    mxd_dht_message_header_t response;
    socklen_t addr_len = sizeof(addr);
    if (recvfrom(dht_state.socket, &response, sizeof(response), 0,
                 (struct sockaddr *)&addr, &addr_len) != sizeof(response)) {
        return -1;
    }

    if (response.type != DHT_FIND_VALUE_REPLY) {
        return -1;
    }

    // Receive value
    ssize_t received = recvfrom(dht_state.socket, value, *value_length, 0,
                               (struct sockaddr *)&addr, &addr_len);
    if (received < 0) {
        return -1;
    }

    *value_length = received;
    return 0;
}

// Start DHT operations
int mxd_start_dht(uint16_t port) {
    if (dht_state.running) {
        return -1;
    }
    
    // Create UDP socket
    dht_state.socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (dht_state.socket < 0) {
        return -1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(dht_state.socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(dht_state.socket);
        return -1;
    }
    
    // Bind socket
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(dht_state.socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(dht_state.socket);
        return -1;
    }
    
    dht_state.port = port;
    dht_state.running = 1;
    
    // Start main thread
    if (pthread_create(&dht_state.main_thread, NULL, dht_main_thread, NULL) != 0) {
        dht_state.running = 0;
        close(dht_state.socket);
        return -1;
    }
    
    // Start refresh thread
    if (pthread_create(&dht_state.refresh_thread, NULL, dht_refresh_thread, NULL) != 0) {
        dht_state.running = 0;
        pthread_join(dht_state.main_thread, NULL);
        close(dht_state.socket);
        return -1;
    }
    
    return 0;
}

// Stop DHT operations
int mxd_stop_dht(void) {
    if (!dht_state.running) {
        return -1;
    }
    
    dht_state.running = 0;
    
    // Wait for threads to finish
    pthread_join(dht_state.main_thread, NULL);
    pthread_join(dht_state.refresh_thread, NULL);
    
    // Close socket
    close(dht_state.socket);
    
    // Clean up routing table
    pthread_mutex_lock(&dht_state.table_mutex);
    for (size_t i = 0; i < BUCKET_COUNT; i++) {
        free(dht_state.routing_table.buckets[i].nodes);
    }
    free(dht_state.routing_table.buckets);
    pthread_mutex_unlock(&dht_state.table_mutex);
    
    // Clean up stored values
    pthread_mutex_lock(&dht_state.storage_mutex);
    for (size_t i = 0; i < dht_state.value_count; i++) {
        free(dht_state.stored_values[i].value);
    }
    free(dht_state.stored_values);
    pthread_mutex_unlock(&dht_state.storage_mutex);
    
    // Destroy mutex
    pthread_mutex_destroy(&dht_state.table_mutex);
    
    return 0;
}

// Add node to routing table
int mxd_dht_add_node(const char *address, uint16_t port, const uint8_t *node_id) {
    if (!address || !node_id || !dht_state.running) {
        return -1;
    }
    
    mxd_node_id_t id;
    memcpy(id.id, node_id, 20);
    
    // Get appropriate bucket
    int bucket_idx = get_bucket_index(&id);
    
    pthread_mutex_lock(&dht_state.table_mutex);
    
    mxd_k_bucket_t *bucket = &dht_state.routing_table.buckets[bucket_idx];
    
    // Check if node already exists
    for (size_t i = 0; i < bucket->node_count; i++) {
        if (memcmp(bucket->nodes[i].id.id, id.id, 20) == 0) {
            // Update existing node
            strncpy(bucket->nodes[i].address, address, sizeof(bucket->nodes[i].address) - 1);
            bucket->nodes[i].port = port;
            bucket->nodes[i].last_seen = time(NULL);
            pthread_mutex_unlock(&dht_state.table_mutex);
            return 0;
        }
    }
    
    // Add new node if bucket not full
    if (bucket->node_count < bucket->k) {
        mxd_dht_node_t *node = &bucket->nodes[bucket->node_count];
        memcpy(node->id.id, id.id, 20);
        strncpy(node->address, address, sizeof(node->address) - 1);
        node->port = port;
        node->last_seen = time(NULL);
        node->rtt = 0;
        node->active = 1;
        bucket->node_count++;
        dht_state.stats.total_nodes++;
        dht_state.stats.active_nodes++;
    }
    
    pthread_mutex_unlock(&dht_state.table_mutex);
    return 0;
}

// Remove node from routing table
int mxd_dht_remove_node(const mxd_node_id_t *node_id) {
    if (!node_id || !dht_state.running) {
        return -1;
    }
    
    int bucket_idx = get_bucket_index(node_id);
    
    pthread_mutex_lock(&dht_state.table_mutex);
    
    mxd_k_bucket_t *bucket = &dht_state.routing_table.buckets[bucket_idx];
    
    // Find and remove node
    for (size_t i = 0; i < bucket->node_count; i++) {
        if (memcmp(bucket->nodes[i].id.id, node_id->id, 20) == 0) {
            // Shift remaining nodes
            if (i < bucket->node_count - 1) {
                memmove(&bucket->nodes[i], &bucket->nodes[i + 1],
                        (bucket->node_count - i - 1) * sizeof(mxd_dht_node_t));
            }
            bucket->node_count--;
            dht_state.stats.total_nodes--;
            if (bucket->nodes[i].active) {
                dht_state.stats.active_nodes--;
            }
            pthread_mutex_unlock(&dht_state.table_mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&dht_state.table_mutex);
    return -1;
}

// Find closest nodes to target ID
int mxd_dht_find_nodes(const mxd_node_id_t *target, mxd_dht_node_t *nodes, size_t *node_count) {
    if (!target || !nodes || !node_count || *node_count == 0 || !dht_state.running) {
        return -1;
    }
    
    // Calculate distances to all nodes
    typedef struct {
        mxd_dht_node_t node;
        uint8_t distance[20];
    } node_distance_t;
    
    node_distance_t *distances = NULL;
    size_t total_nodes = 0;
    
    pthread_mutex_lock(&dht_state.table_mutex);
    
    // Count total nodes
    for (size_t i = 0; i < BUCKET_COUNT; i++) {
        total_nodes += dht_state.routing_table.buckets[i].node_count;
    }
    
    if (total_nodes == 0) {
        pthread_mutex_unlock(&dht_state.table_mutex);
        *node_count = 0;
        return 0;
    }
    
    // Allocate space for distances
    distances = malloc(total_nodes * sizeof(node_distance_t));
    if (!distances) {
        pthread_mutex_unlock(&dht_state.table_mutex);
        return -1;
    }
    
    // Calculate distances
    size_t dist_count = 0;
    for (size_t i = 0; i < BUCKET_COUNT; i++) {
        mxd_k_bucket_t *bucket = &dht_state.routing_table.buckets[i];
        for (size_t j = 0; j < bucket->node_count; j++) {
            memcpy(&distances[dist_count].node, &bucket->nodes[j], sizeof(mxd_dht_node_t));
            calculate_distance(target, &bucket->nodes[j].id, distances[dist_count].distance);
            dist_count++;
        }
    }
    
    pthread_mutex_unlock(&dht_state.table_mutex);
    
    // Sort by distance
    qsort(distances, dist_count, sizeof(node_distance_t), compare_node_distances);
    
    // Copy closest nodes
    size_t count = dist_count < *node_count ? dist_count : *node_count;
    for (size_t i = 0; i < count; i++) {
        memcpy(&nodes[i], &distances[i].node, sizeof(mxd_dht_node_t));
    }
    *node_count = count;
    
    free(distances);
    return 0;
}

// Store value in DHT
int mxd_dht_store(const uint8_t *key, size_t key_length,
                  const uint8_t *value, size_t value_length) {
    if (!key || !value || key_length == 0 || value_length == 0 || !dht_state.running) {
        return -1;
    }
    
    // Calculate key ID
    mxd_node_id_t key_id;
    if (mxd_sha1(key, key_length, key_id.id) != 0) {
        return -1;
    }
    
    // Find closest nodes
    mxd_dht_node_t nodes[K_PARAM];
    size_t node_count = K_PARAM;
    if (mxd_dht_find_nodes(&key_id, nodes, &node_count) != 0) {
        return -1;
    }
    
    // Send store messages
    for (size_t i = 0; i < node_count; i++) {
        send_store_message(&nodes[i], key, key_length, value, value_length);
    }
    
    dht_state.stats.stored_values++;
    return 0;
}

// Find value in DHT
int mxd_dht_find_value(const uint8_t *key, size_t key_length,
                       uint8_t *value, size_t *value_length) {
    if (!key || !value || !value_length || key_length == 0 || !dht_state.running) {
        return -1;
    }
    
    // Calculate key ID
    mxd_node_id_t key_id;
    if (mxd_sha1(key, key_length, key_id.id) != 0) {
        return -1;
    }
    
    // Find closest nodes
    mxd_dht_node_t nodes[K_PARAM];
    size_t node_count = K_PARAM;
    if (mxd_dht_find_nodes(&key_id, nodes, &node_count) != 0) {
        return -1;
    }
    
    // Query nodes for value
    for (size_t i = 0; i < node_count; i++) {
        if (query_value(&nodes[i], key, key_length, value, value_length) == 0) {
            return 0;
        }
    }
    
    return -1;
}

// Enable NAT traversal
int mxd_dht_enable_nat_traversal(void) {
    if (!dht_state.running) {
        return -1;
    }
    
    dht_state.nat_traversal = 1;
    return 0;
}

// Disable NAT traversal
int mxd_dht_disable_nat_traversal(void) {
    if (!dht_state.running) {
        return -1;
    }
    
    dht_state.nat_traversal = 0;
    return 0;
}

// Get DHT statistics
int mxd_dht_get_stats(mxd_dht_stats_t *stats) {
    if (!stats || !dht_state.running) {
        return -1;
    }
    
    memcpy(stats, &dht_state.stats, sizeof(mxd_dht_stats_t));
    return 0;
}

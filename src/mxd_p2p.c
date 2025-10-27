#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include "mxd_config.h"
#include "mxd_crypto.h"
#include "mxd_dht.h"
#include "mxd_p2p.h"
#include "mxd_logging.h"
#include "mxd_secrets.h"

static struct {
    char address[256];
    uint16_t port;
    int active;
} manual_peers[MXD_MAX_PEERS];
static size_t manual_peer_count = 0;
static pthread_mutex_t manual_peer_mutex = PTHREAD_MUTEX_INITIALIZER;


static int p2p_initialized = 0;
static uint16_t p2p_port = 0;
static uint8_t node_public_key[32] = {0};
static mxd_config_t node_config;
static uint64_t last_message_time = 0;
static size_t messages_this_second = 0;
static uint64_t last_tx_time = 0;
static size_t tx_this_second = 0;
static uint32_t consecutive_errors = 0;
static mxd_message_handler_t message_handler = NULL;
static int error_simulation_count = 0;

static int server_socket = -1;
static pthread_t server_thread;
static pthread_t connection_threads[MXD_MAX_PEERS];
static volatile int server_running = 0;
static pthread_mutex_t peer_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int socket;
    char address[256];
    uint16_t port;
    time_t connected_at;
    time_t last_keepalive_sent;
    time_t last_keepalive_received;
    int active;
    int keepalive_failures;
} peer_connection_t;

static peer_connection_t active_connections[MXD_MAX_PEERS];
static size_t active_connection_count = 0;

typedef struct {
    char address[256];
    uint16_t port;
    time_t last_message_sent;
    time_t last_message_received;
    uint32_t messages_sent;
    uint32_t messages_received;
    int active;
} unified_peer_t;

static unified_peer_t unified_peers[MXD_MAX_PEERS];
static size_t unified_peer_count = 0;
static pthread_mutex_t unified_peer_mutex = PTHREAD_MUTEX_INITIALIZER;

#define MXD_KEEPALIVE_INTERVAL 30
#define MXD_KEEPALIVE_TIMEOUT 90
#define MXD_MAX_KEEPALIVE_FAILURES 3

static pthread_t keepalive_thread;
static volatile int keepalive_running = 0;

static void update_unified_peer_sent(const char *address, uint16_t port) {
    pthread_mutex_lock(&unified_peer_mutex);
    
    int found = 0;
    int inactive_slot = -1;
    
    for (size_t i = 0; i < unified_peer_count; i++) {
        if (strcmp(unified_peers[i].address, address) == 0 && unified_peers[i].port == port) {
            unified_peers[i].last_message_sent = time(NULL);
            unified_peers[i].messages_sent++;
            unified_peers[i].active = 1;
            found = 1;
            break;
        }
        if (!unified_peers[i].active && inactive_slot == -1) {
            inactive_slot = i;
        }
    }
    
    if (!found) {
        int slot = (inactive_slot >= 0) ? inactive_slot : unified_peer_count;
        
        if (slot < MXD_MAX_PEERS) {
            strncpy(unified_peers[slot].address, address, sizeof(unified_peers[0].address) - 1);
            unified_peers[slot].address[sizeof(unified_peers[0].address) - 1] = '\0';
            unified_peers[slot].port = port;
            unified_peers[slot].last_message_sent = time(NULL);
            unified_peers[slot].last_message_received = 0;
            unified_peers[slot].messages_sent = 1;
            unified_peers[slot].messages_received = 0;
            unified_peers[slot].active = 1;
            
            if (inactive_slot < 0) {
                unified_peer_count++;
            }
        }
    }
    
    pthread_mutex_unlock(&unified_peer_mutex);
}

static void update_unified_peer_received(const char *address, uint16_t port) {
    pthread_mutex_lock(&unified_peer_mutex);
    
    int found = 0;
    int inactive_slot = -1;
    
    for (size_t i = 0; i < unified_peer_count; i++) {
        if (strcmp(unified_peers[i].address, address) == 0 && unified_peers[i].port == port) {
            unified_peers[i].last_message_received = time(NULL);
            unified_peers[i].messages_received++;
            unified_peers[i].active = 1;
            found = 1;
            break;
        }
        if (!unified_peers[i].active && inactive_slot == -1) {
            inactive_slot = i;
        }
    }
    
    if (!found) {
        int slot = (inactive_slot >= 0) ? inactive_slot : unified_peer_count;
        
        if (slot < MXD_MAX_PEERS) {
            strncpy(unified_peers[slot].address, address, sizeof(unified_peers[0].address) - 1);
            unified_peers[slot].address[sizeof(unified_peers[0].address) - 1] = '\0';
            unified_peers[slot].port = port;
            unified_peers[slot].last_message_sent = 0;
            unified_peers[slot].last_message_received = time(NULL);
            unified_peers[slot].messages_sent = 0;
            unified_peers[slot].messages_received = 1;
            unified_peers[slot].active = 1;
            
            if (inactive_slot < 0) {
                unified_peer_count++;
            }
        }
    }
    
    pthread_mutex_unlock(&unified_peer_mutex);
}

static void reset_rate_limit(void) {
    last_message_time = 0;
    messages_this_second = 0;
    last_tx_time = 0;
    tx_this_second = 0;
    consecutive_errors = 0;
    error_simulation_count = 0;
}

// Public function to reset rate limiting
int mxd_reset_rate_limit(void) {
    if (!p2p_initialized) {
        return -1;
    }
    reset_rate_limit();
    return 0;
}

// Message validation function
static int validate_message(const mxd_message_header_t *header, const void *payload) {
    if (!header || !payload) {
        return -1;
    }

    // Check magic number
    const mxd_secrets_t *secrets = mxd_get_secrets();
    if (!secrets) {
        MXD_LOG_ERROR("p2p", "Secrets not initialized");
        return -1;
    }
    uint32_t expected_magic = secrets->network_magic;
    if (header->magic != expected_magic) {
        MXD_LOG_WARN("p2p", "Invalid network magic received");
        return -1;
    }

    // Check message size
    if (header->length > MXD_MAX_MESSAGE_SIZE) {
        MXD_LOG_WARN("p2p", "Message size %zu exceeds maximum %d", header->length, MXD_MAX_MESSAGE_SIZE);
        return -1;
    }
    
    // Validate message type
    if (header->type > MXD_MSG_RAPID_TABLE_UPDATE) {
        MXD_LOG_WARN("p2p", "Invalid message type %d", header->type);
        return -1;
    }
    
    // Additional input validation
    if (header->length == 0) {
        MXD_LOG_WARN("p2p", "Empty message payload");
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
static int check_rate_limit(mxd_message_type_t type) {
    uint64_t current_time = time(NULL);

    // Reset counters if time has changed
    if (current_time != last_message_time) {
        last_message_time = current_time;
        messages_this_second = 0;
    }
    if (current_time != last_tx_time) {
        last_tx_time = current_time;
        tx_this_second = 0;
    }

    // Check appropriate rate limit
    if (type == MXD_MSG_TRANSACTIONS) {
        // Allow exactly 10 transactions per second
        if (tx_this_second >= 10) {
            return -1;
        }
        tx_this_second++;
    } else {
        // Allow exactly 100 messages per second
        if (messages_this_second >= 100) {
            return -1;
        }
        messages_this_second++;
    }

    return 0;
}

// Set message handler callback
int mxd_set_message_handler(mxd_message_handler_t handler) {
    if (!p2p_initialized) {
        return -1;
    }
    message_handler = handler;
    return 0;
}

static void handle_get_peers_message(const char *address, uint16_t port, const void *payload, size_t length) {
    uint16_t peer_listening_port = port;
    
    if (length >= sizeof(uint16_t)) {
        memcpy(&peer_listening_port, payload, sizeof(uint16_t));
        MXD_LOG_INFO("p2p", "GET_PEERS from %s:%d (listening on port %d)", address, port, peer_listening_port);
        
        if (mxd_dht_add_peer(address, peer_listening_port) == 0) {
            MXD_LOG_INFO("p2p", "Added requesting peer %s:%d to DHT", address, peer_listening_port);
        }
    } else {
        MXD_LOG_WARN("p2p", "GET_PEERS message from %s:%d missing listening port", address, port);
    }
    
    mxd_dht_node_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    
    if (mxd_dht_get_peers(peers, &peer_count) != 0) {
        MXD_LOG_WARN("p2p", "Failed to get peers for GET_PEERS request from %s:%d", address, port);
        return;
    }
    
    size_t payload_size = sizeof(uint32_t) + (peer_count * (256 + sizeof(uint16_t)));
    uint8_t *response = malloc(payload_size);
    if (!response) {
        MXD_LOG_ERROR("p2p", "Failed to allocate memory for PEERS response");
        return;
    }
    
    uint32_t count = (uint32_t)peer_count;
    memcpy(response, &count, sizeof(uint32_t));
    
    size_t offset = sizeof(uint32_t);
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].active) {
            memcpy(response + offset, peers[i].address, 256);
            offset += 256;
            memcpy(response + offset, &peers[i].port, sizeof(uint16_t));
            offset += sizeof(uint16_t);
        }
    }
    
    if (mxd_send_message(address, peer_listening_port, MXD_MSG_PEERS, response, offset) != 0) {
        MXD_LOG_WARN("p2p", "Failed to send PEERS response to %s:%d", address, peer_listening_port);
    } else {
        MXD_LOG_INFO("p2p", "Sent %u peers to %s:%d", count, address, peer_listening_port);
    }
    
    free(response);
}

static void handle_peers_message(const char *address, uint16_t port, const void *payload, size_t length) {
    if (length < sizeof(uint32_t)) {
        MXD_LOG_WARN("p2p", "Invalid PEERS message from %s:%d", address, port);
        return;
    }
    
    uint32_t peer_count;
    memcpy(&peer_count, payload, sizeof(uint32_t));
    
    size_t expected_size = sizeof(uint32_t) + (peer_count * (256 + sizeof(uint16_t)));
    if (length < expected_size) {
        MXD_LOG_WARN("p2p", "Truncated PEERS message from %s:%d", address, port);
        return;
    }
    
    size_t offset = sizeof(uint32_t);
    for (uint32_t i = 0; i < peer_count && i < MXD_MAX_PEERS; i++) {
        char peer_addr[256];
        uint16_t peer_port;
        
        memcpy(peer_addr, (uint8_t*)payload + offset, 256);
        offset += 256;
        memcpy(&peer_port, (uint8_t*)payload + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        
        if (peer_port != p2p_port || strcmp(peer_addr, "127.0.0.1") != 0) {
            mxd_dht_add_peer(peer_addr, peer_port);
            MXD_LOG_INFO("p2p", "Learned new peer from %s:%d -> %s:%d", address, port, peer_addr, peer_port);
        }
    }
}

static void handle_ping_message(const char *address, uint16_t port) {
    MXD_LOG_DEBUG("p2p", "Received PING from %s:%d, sending PONG", address, port);
    
    pthread_mutex_lock(&peer_mutex);
    for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
        if (active_connections[i].active && 
            strcmp(active_connections[i].address, address) == 0 &&
            active_connections[i].port == port) {
            active_connections[i].last_keepalive_received = time(NULL);
            active_connections[i].keepalive_failures = 0;
            break;
        }
    }
    pthread_mutex_unlock(&peer_mutex);
    
    uint8_t pong_payload = 1;
    mxd_send_message(address, port, MXD_MSG_PONG, &pong_payload, sizeof(pong_payload));
}

static void handle_pong_message(const char *address, uint16_t port) {
    MXD_LOG_DEBUG("p2p", "Received PONG from %s:%d", address, port);
    
    pthread_mutex_lock(&peer_mutex);
    for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
        if (active_connections[i].active && 
            strcmp(active_connections[i].address, address) == 0 &&
            active_connections[i].port == port) {
            active_connections[i].last_keepalive_received = time(NULL);
            active_connections[i].keepalive_failures = 0;
            break;
        }
    }
    pthread_mutex_unlock(&peer_mutex);
}

static int handle_incoming_message(const char *address, uint16_t port, 
                                 const mxd_message_header_t *header, 
                                 const void *payload) {
    if (!address || !header || !payload) {
        return -1;
    }

    if (validate_message(header, payload) != 0) {
        consecutive_errors++;
        if (consecutive_errors >= 10) {
            return -1;
        }
        return 0;
    }

    consecutive_errors = 0;
    
    update_unified_peer_received(address, port);

    switch (header->type) {
        case MXD_MSG_PING:
            handle_ping_message(address, port);
            break;
        case MXD_MSG_PONG:
            handle_pong_message(address, port);
            break;
        case MXD_MSG_GET_PEERS:
            handle_get_peers_message(address, port, payload, header->length);
            break;
        case MXD_MSG_PEERS:
            handle_peers_message(address, port, payload, header->length);
            break;
        default:
            if (message_handler) {
                message_handler(address, port, header->type, payload, header->length);
            }
            break;
    }

    return 0;
}

static void* keepalive_thread_func(void* arg) {
    (void)arg;
    
    MXD_LOG_INFO("p2p", "Keepalive thread started");
    
    while (keepalive_running) {
        sleep(MXD_KEEPALIVE_INTERVAL);
        
        if (!keepalive_running) break;
        
        time_t now = time(NULL);
        
        pthread_mutex_lock(&unified_peer_mutex);
        
        for (size_t i = 0; i < unified_peer_count; i++) {
            if (!unified_peers[i].active) continue;
            
            if (unified_peers[i].last_message_received > 0) {
                time_t time_since_last_received = now - unified_peers[i].last_message_received;
                
                if (time_since_last_received > MXD_KEEPALIVE_TIMEOUT) {
                    MXD_LOG_WARN("p2p", "Peer %s:%d timed out (no response for %ld seconds), marking inactive",
                               unified_peers[i].address, unified_peers[i].port, 
                               time_since_last_received);
                    unified_peers[i].active = 0;
                    continue;
                }
            }
            
            time_t time_since_last_sent = (unified_peers[i].last_message_sent > 0) ? 
                                          (now - unified_peers[i].last_message_sent) : MXD_KEEPALIVE_INTERVAL;
            
            if (time_since_last_sent >= MXD_KEEPALIVE_INTERVAL) {
                uint8_t ping_payload = 1;
                if (mxd_send_message(unified_peers[i].address, unified_peers[i].port,
                                   MXD_MSG_PING, &ping_payload, sizeof(ping_payload)) == 0) {
                    MXD_LOG_DEBUG("p2p", "Sent keepalive PING to %s:%d", 
                               unified_peers[i].address, unified_peers[i].port);
                } else {
                    MXD_LOG_DEBUG("p2p", "Failed to send keepalive to %s:%d",
                               unified_peers[i].address, unified_peers[i].port);
                }
            }
        }
        
        pthread_mutex_unlock(&unified_peer_mutex);
        
        pthread_mutex_lock(&peer_mutex);
        
        for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
            if (!active_connections[i].active) continue;
            
            time_t time_since_last_received = now - active_connections[i].last_keepalive_received;
            
            if (time_since_last_received > MXD_KEEPALIVE_TIMEOUT) {
                MXD_LOG_WARN("p2p", "Incoming connection %s:%d timed out, closing socket",
                           active_connections[i].address, active_connections[i].port);
                close(active_connections[i].socket);
                active_connections[i].active = 0;
                active_connection_count--;
            }
        }
        
        pthread_mutex_unlock(&peer_mutex);
    }
    
    MXD_LOG_INFO("p2p", "Keepalive thread stopped");
    return NULL;
}

static void* connection_handler(void* arg) {
    peer_connection_t *conn = (peer_connection_t*)arg;
    
    MXD_LOG_INFO("p2p", "Connection handler started for %s:%d", conn->address, conn->port);
    
    while (conn->active && server_running) {
        mxd_message_header_t header;
        ssize_t bytes_read = recv(conn->socket, &header, sizeof(header), 0);
        
        if (bytes_read != sizeof(header)) {
            if (bytes_read == 0) {
                MXD_LOG_INFO("p2p", "Peer %s:%d disconnected", conn->address, conn->port);
            } else if (bytes_read < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                MXD_LOG_WARN("p2p", "Error reading header from %s:%d: %s", 
                           conn->address, conn->port, strerror(errno));
            }
            break;
        }
        
        if (header.length > MXD_MAX_MESSAGE_SIZE) {
            MXD_LOG_WARN("p2p", "Message too large from %s:%d: %u bytes", 
                       conn->address, conn->port, header.length);
            break;
        }
        
        uint8_t *payload = malloc(header.length);
        if (!payload) {
            MXD_LOG_ERROR("p2p", "Failed to allocate %u bytes for message", header.length);
            break;
        }
        
        size_t total_read = 0;
        while (total_read < header.length) {
            bytes_read = recv(conn->socket, payload + total_read, header.length - total_read, 0);
            if (bytes_read <= 0) {
                if (bytes_read < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    MXD_LOG_WARN("p2p", "Error reading payload from %s:%d", conn->address, conn->port);
                }
                break;
            }
            total_read += bytes_read;
        }
        
        if (total_read == header.length) {
            handle_incoming_message(conn->address, conn->port, &header, payload);
        }
        
        free(payload);
    }
    
    close(conn->socket);
    conn->active = 0;
    MXD_LOG_INFO("p2p", "Connection handler stopped for %s:%d", conn->address, conn->port);
    
    return NULL;
}

static void* server_thread_func(void* arg) {
    (void)arg;
    
    MXD_LOG_INFO("p2p", "P2P server thread started");
    
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            if (server_running && errno != EINTR) {
                MXD_LOG_ERROR("p2p", "Accept failed: %s", strerror(errno));
            }
            continue;
        }
        
        pthread_mutex_lock(&peer_mutex);
        
        char *client_ip = inet_ntoa(client_addr.sin_addr);
        uint16_t client_port = ntohs(client_addr.sin_port);
        
        int duplicate_found = 0;
        for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
            if (active_connections[i].active &&
                strcmp(active_connections[i].address, client_ip) == 0 &&
                active_connections[i].port == client_port) {
                duplicate_found = 1;
                break;
            }
        }
        
        if (duplicate_found) {
            MXD_LOG_INFO("p2p", "Duplicate connection from %s:%d rejected", client_ip, client_port);
            close(client_socket);
            pthread_mutex_unlock(&peer_mutex);
            continue;
        }
        
        int slot = -1;
        for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
            if (!active_connections[i].active) {
                slot = i;
                break;
            }
        }
        
        if (slot < 0) {
            MXD_LOG_WARN("p2p", "Max connections reached, rejecting connection");
            close(client_socket);
            pthread_mutex_unlock(&peer_mutex);
            continue;
        }
        
        time_t now = time(NULL);
        active_connections[slot].socket = client_socket;
        strncpy(active_connections[slot].address, client_ip, sizeof(active_connections[slot].address) - 1);
        active_connections[slot].port = client_port;
        active_connections[slot].connected_at = now;
        active_connections[slot].last_keepalive_sent = now;
        active_connections[slot].last_keepalive_received = now;
        active_connections[slot].keepalive_failures = 0;
        active_connections[slot].active = 1;
        
        if (pthread_create(&connection_threads[slot], NULL, connection_handler, &active_connections[slot]) != 0) {
            MXD_LOG_ERROR("p2p", "Failed to create connection thread");
            close(client_socket);
            active_connections[slot].active = 0;
        } else {
            pthread_detach(connection_threads[slot]);
            active_connection_count++;
            MXD_LOG_INFO("p2p", "Accepted connection from %s:%d (slot %d)", client_ip, client_port, slot);
        }
        
        pthread_mutex_unlock(&peer_mutex);
    }
    
    MXD_LOG_INFO("p2p", "P2P server thread stopped");
    return NULL;
}

int mxd_init_p2p(uint16_t port, const uint8_t* public_key) {
    if (mxd_init_secrets(NULL) != 0) {
        MXD_LOG_WARN("p2p", "Secrets initialization failed, using defaults");
    }
    
    if (p2p_initialized) {
        return 0;
    }
    
    reset_rate_limit();
    consecutive_errors = 0;
    last_message_time = 0;
    last_tx_time = 0;
    messages_this_second = 0;
    tx_this_second = 0;
    
    p2p_port = port;
    memcpy(node_public_key, public_key, 32);
    
    memset(&node_config, 0, sizeof(node_config));
    node_config.port = port;
    snprintf(node_config.node_id, sizeof(node_config.node_id), "peer_%d", port);
    snprintf(node_config.data_dir, sizeof(node_config.data_dir), "data");
    
    memset(active_connections, 0, sizeof(active_connections));
    active_connection_count = 0;
    
    memset(manual_peers, 0, sizeof(manual_peers));
    manual_peer_count = 0;
    
    p2p_initialized = 1;
    MXD_LOG_INFO("p2p", "P2P initialized on port %d", port);
    return 0;
}

int mxd_start_p2p(void) {
    if (!p2p_initialized) {
        MXD_LOG_ERROR("p2p", "P2P not initialized");
        return 1;
    }
    
    if (server_running) {
        MXD_LOG_WARN("p2p", "P2P server already running");
        return 0;
    }
    
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        MXD_LOG_ERROR("p2p", "Failed to create socket: %s", strerror(errno));
        return 1;
    }
    
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        MXD_LOG_WARN("p2p", "Failed to set SO_REUSEADDR: %s", strerror(errno));
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(p2p_port);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        MXD_LOG_ERROR("p2p", "Failed to bind to port %d: %s", p2p_port, strerror(errno));
        close(server_socket);
        server_socket = -1;
        return 1;
    }
    
    if (listen(server_socket, 10) < 0) {
        MXD_LOG_ERROR("p2p", "Failed to listen on socket: %s", strerror(errno));
        close(server_socket);
        server_socket = -1;
        return 1;
    }
    
    server_running = 1;
    if (pthread_create(&server_thread, NULL, server_thread_func, NULL) != 0) {
        MXD_LOG_ERROR("p2p", "Failed to create server thread: %s", strerror(errno));
        close(server_socket);
        server_socket = -1;
        server_running = 0;
        return 1;
    }
    
    keepalive_running = 1;
    if (pthread_create(&keepalive_thread, NULL, keepalive_thread_func, NULL) != 0) {
        MXD_LOG_ERROR("p2p", "Failed to create keepalive thread: %s", strerror(errno));
        keepalive_running = 0;
    } else {
        pthread_detach(keepalive_thread);
        MXD_LOG_INFO("p2p", "Keepalive thread started");
    }
    
    MXD_LOG_INFO("p2p", "P2P server started on port %d", p2p_port);
    return 0;
}

int mxd_stop_p2p(void) {
    if (!p2p_initialized) {
        return 0;
    }
    
    keepalive_running = 0;
    server_running = 0;
    
    if (server_socket >= 0) {
        shutdown(server_socket, SHUT_RDWR);
        close(server_socket);
        server_socket = -1;
    }
    
    pthread_mutex_lock(&peer_mutex);
    for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
        if (active_connections[i].active) {
            close(active_connections[i].socket);
            active_connections[i].active = 0;
        }
    }
    active_connection_count = 0;
    pthread_mutex_unlock(&peer_mutex);
    
    pthread_join(server_thread, NULL);
    
    p2p_initialized = 0;
    MXD_LOG_INFO("p2p", "P2P stopped");
    return 0;
}

int mxd_add_peer(const char* address, uint16_t port) {
    if (!p2p_initialized || !address) {
        return 1;
    }
    
    pthread_mutex_lock(&manual_peer_mutex);
    
    for (size_t i = 0; i < manual_peer_count; i++) {
        if (manual_peers[i].port == port && 
            strcmp(manual_peers[i].address, address) == 0) {
            manual_peers[i].active = 1;
            pthread_mutex_unlock(&manual_peer_mutex);
            MXD_LOG_INFO("p2p", "Peer %s:%d already exists", address, port);
            return 0;
        }
    }
    
    if (manual_peer_count >= MXD_MAX_PEERS) {
        pthread_mutex_unlock(&manual_peer_mutex);
        MXD_LOG_WARN("p2p", "Manual peer list full");
        return 1;
    }
    
    strncpy(manual_peers[manual_peer_count].address, address, sizeof(manual_peers[0].address) - 1);
    manual_peers[manual_peer_count].address[sizeof(manual_peers[0].address) - 1] = '\0';
    manual_peers[manual_peer_count].port = port;
    manual_peers[manual_peer_count].active = 1;
    manual_peer_count++;
    
    pthread_mutex_unlock(&manual_peer_mutex);
    
    mxd_dht_add_peer(address, port);
    
    MXD_LOG_INFO("p2p", "Added peer %s:%d (total manual peers: %zu)", address, port, manual_peer_count);
    return 0;
}

// Get list of connected peers
int mxd_get_peers(mxd_peer_t* peers, size_t* peer_count) {
    if (!peers || !peer_count) {
        MXD_LOG_INFO("p2p", "mxd_get_peers failed: invalid parameters");
        return -1;
    }
    
    size_t max_peers = *peer_count;
    *peer_count = 0;
    
    if (max_peers == 0) {
        return 0;
    }
    
    size_t dht_peer_count = max_peers;
    mxd_dht_node_t dht_nodes[MXD_MAX_PEERS];
    
    if (mxd_dht_get_peers(dht_nodes, &dht_peer_count) == 0) {
        for (size_t i = 0; i < dht_peer_count && i < max_peers; i++) {
            if (dht_nodes[i].active) {
                strncpy(peers[i].address, dht_nodes[i].address, sizeof(peers[i].address) - 1);
                peers[i].address[sizeof(peers[i].address) - 1] = '\0';
                peers[i].port = dht_nodes[i].port;
                peers[i].state = MXD_PEER_CONNECTED;
                peers[i].latency = 1000;
                peers[i].last_seen = time(NULL);
                (*peer_count)++;
            }
        }
        MXD_LOG_INFO("p2p", "Retrieved %zu peers from DHT", *peer_count);
    }
    
    return 0;
}

int mxd_send_message_with_retry(const char* address, uint16_t port, 
                                       mxd_message_type_t type, const void* payload, 
                                       size_t payload_length, int max_retries) {
    int retry_delay_ms = 1000;
    const int max_delay_ms = 60000;
    
    for (int attempt = 0; attempt < max_retries; attempt++) {
        int result = mxd_send_message(address, port, type, payload, payload_length);
        if (result == 0) {
            if (attempt > 0) {
                MXD_LOG_INFO("p2p", "Successfully connected to %s:%d after %d retries", 
                           address, port, attempt);
            }
            return 0;
        }
        
        if (attempt < max_retries - 1) {
            MXD_LOG_WARN("p2p", "Connection attempt %d/%d to %s:%d failed, retrying in %d ms", 
                       attempt + 1, max_retries, address, port, retry_delay_ms);
            usleep(retry_delay_ms * 1000);
            retry_delay_ms = (retry_delay_ms * 2 > max_delay_ms) ? max_delay_ms : retry_delay_ms * 2;
        }
    }
    
    MXD_LOG_ERROR("p2p", "Failed to connect to %s:%d after %d attempts", address, port, max_retries);
    return -1;
}

int mxd_send_message(const char* address, uint16_t port, 
                    mxd_message_type_t type, const void* payload, 
                    size_t payload_length) {
    if (!p2p_initialized || !address || !payload || 
        payload_length > MXD_MAX_MESSAGE_SIZE) {
        return -1;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        MXD_LOG_WARN("p2p", "Failed to create socket for sending: %s", strerror(errno));
        return -1;
    }
    
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, address, &peer_addr.sin_addr) <= 0) {
        MXD_LOG_WARN("p2p", "Invalid address: %s", address);
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        MXD_LOG_WARN("p2p", "Failed to connect to %s:%d: %s", address, port, strerror(errno));
        close(sock);
        return -1;
    }
    
    const mxd_secrets_t *secrets = mxd_get_secrets();
    if (!secrets) {
        MXD_LOG_ERROR("p2p", "Secrets not initialized");
        close(sock);
        return -1;
    }
    
    mxd_message_header_t header = {
        .magic = secrets->network_magic,
        .type = type,
        .length = payload_length
    };
    
    if (mxd_sha512(payload, payload_length, header.checksum) != 0) {
        close(sock);
        return -1;
    }
    
    if (send(sock, &header, sizeof(header), 0) != sizeof(header)) {
        MXD_LOG_WARN("p2p", "Failed to send header to %s:%d", address, port);
        close(sock);
        return -1;
    }
    
    size_t total_sent = 0;
    while (total_sent < payload_length) {
        ssize_t sent = send(sock, (uint8_t*)payload + total_sent, payload_length - total_sent, 0);
        if (sent <= 0) {
            MXD_LOG_WARN("p2p", "Failed to send payload to %s:%d", address, port);
            close(sock);
            return -1;
        }
        total_sent += sent;
    }
    
    close(sock);
    
    update_unified_peer_sent(address, port);
    
    return 0;
}

int mxd_broadcast_message(mxd_message_type_t type, const void* payload, size_t payload_length) {
    if (!p2p_initialized || !payload) {
        consecutive_errors++;
        if (consecutive_errors > 10) {
            return -1;
        }
        return 0;
    }

    if (payload_length > MXD_MAX_MESSAGE_SIZE || type > MXD_MSG_RAPID_TABLE_UPDATE) {
        return -1;
    }

    consecutive_errors = 0;

    const mxd_secrets_t *secrets = mxd_get_secrets();
    if (!secrets) {
        MXD_LOG_ERROR("p2p", "Secrets not initialized");
        return -1;
    }
    
    mxd_message_header_t header = {
        .magic = secrets->network_magic,
        .type = type,
        .length = payload_length
    };
    
    if (mxd_sha512(payload, payload_length, header.checksum) != 0) {
        return -1;
    }

    if (check_rate_limit(type) != 0) {
        return -1;
    }

    mxd_dht_node_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    
    mxd_dht_get_peers(peers, &peer_count);
    
    int success_count = 0;
    
    pthread_mutex_lock(&manual_peer_mutex);
    for (size_t i = 0; i < manual_peer_count; i++) {
        if (manual_peers[i].active) {
            if (mxd_send_message(manual_peers[i].address, manual_peers[i].port, type, payload, payload_length) == 0) {
                success_count++;
            }
        }
    }
    pthread_mutex_unlock(&manual_peer_mutex);
    
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].active) {
            if (mxd_send_message(peers[i].address, peers[i].port, type, payload, payload_length) == 0) {
                success_count++;
            }
        }
    }
    
    MXD_LOG_DEBUG("p2p", "Broadcast to %d peers", success_count);
    
    return success_count > 0 ? 0 : -1;
}

int mxd_start_peer_discovery(void) {
    if (!p2p_initialized) {
        MXD_LOG_ERROR("p2p", "P2P not initialized");
        return 1;
    }
    
    // Initialize DHT for peer discovery
    if (mxd_init_node(&node_config) != 0) {
        MXD_LOG_ERROR("p2p", "Failed to initialize DHT node");
        return 1;
    }
    
    if (mxd_start_dht(p2p_port) != 0) {
        MXD_LOG_ERROR("p2p", "Failed to start DHT service");
        return 1;
    }
    
    MXD_LOG_INFO("p2p", "Peer discovery started");
    return 0;
}

int mxd_stop_peer_discovery(void) {
    mxd_stop_dht();
    MXD_LOG_INFO("p2p", "Peer discovery stopped");
    return 0;
}

int mxd_get_connection_count(void) {
    if (!p2p_initialized) {
        return 0;
    }
    
    pthread_mutex_lock(&peer_mutex);
    size_t count = active_connection_count;
    pthread_mutex_unlock(&peer_mutex);
    
    return (int)count;
}

int mxd_get_known_peer_count(void) {
    size_t dht_count = MXD_MAX_PEERS;
    mxd_dht_node_t dht_nodes[MXD_MAX_PEERS];
    
    if (mxd_dht_get_peers(dht_nodes, &dht_count) != 0) {
        return 0;
    }
    
    size_t active_count = 0;
    for (size_t i = 0; i < dht_count; i++) {
        if (dht_nodes[i].active) {
            active_count++;
        }
    }
    
    return (int)active_count;
}

int mxd_get_peer_connections(mxd_peer_info_t* peer_info, size_t* count) {
    if (!peer_info || !count || !p2p_initialized) {
        return -1;
    }
    
    size_t max_count = *count;
    *count = 0;
    
    pthread_mutex_lock(&peer_mutex);
    for (size_t i = 0; i < MXD_MAX_PEERS && *count < max_count; i++) {
        if (active_connections[i].active) {
            strncpy(peer_info[*count].address, active_connections[i].address, 
                   sizeof(peer_info[*count].address) - 1);
            peer_info[*count].address[sizeof(peer_info[*count].address) - 1] = '\0';
            peer_info[*count].port = active_connections[i].port;
            peer_info[*count].connected_at = active_connections[i].connected_at;
            peer_info[*count].last_keepalive_sent = active_connections[i].last_keepalive_sent;
            peer_info[*count].last_keepalive_received = active_connections[i].last_keepalive_received;
            peer_info[*count].keepalive_failures = active_connections[i].keepalive_failures;
            (*count)++;
        }
    }
    pthread_mutex_unlock(&peer_mutex);
    
    return 0;
}

int mxd_get_unified_peers(mxd_peer_info_t* peer_info, size_t* count) {
    if (!peer_info || !count) {
        return -1;
    }
    
    if (!p2p_initialized) {
        *count = 0;
        return 0;
    }
    
    size_t max_count = *count;
    *count = 0;
    
    pthread_mutex_lock(&unified_peer_mutex);
    for (size_t i = 0; i < unified_peer_count && *count < max_count; i++) {
        if (unified_peers[i].active) {
            strncpy(peer_info[*count].address, unified_peers[i].address, 
                   sizeof(peer_info[*count].address) - 1);
            peer_info[*count].address[sizeof(peer_info[*count].address) - 1] = '\0';
            peer_info[*count].port = unified_peers[i].port;
            peer_info[*count].connected_at = 0;
            peer_info[*count].last_keepalive_sent = unified_peers[i].last_message_sent;
            peer_info[*count].last_keepalive_received = unified_peers[i].last_message_received;
            peer_info[*count].keepalive_failures = 0;
            (*count)++;
        }
    }
    pthread_mutex_unlock(&unified_peer_mutex);
    
    return 0;
}

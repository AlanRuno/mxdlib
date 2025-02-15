#include "../include/mxd_p2p.h"
#include "../include/mxd_crypto.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

// P2P network state
static struct {
    int server_socket;
    uint16_t port;
    pthread_t server_thread;
    pthread_t discovery_thread;
    volatile int running;
    mxd_peer_t *peers;
    size_t peer_count;
    pthread_mutex_t peers_mutex;
    mxd_message_handler_t message_handler;
} p2p_state = {0};

// Initialize P2P networking
int mxd_init_p2p(uint16_t port) {
    if (p2p_state.running) {
        return -1;
    }

    // Initialize state
    memset(&p2p_state, 0, sizeof(p2p_state));
    p2p_state.port = port;
    p2p_state.peers = malloc(MXD_MAX_PEERS * sizeof(mxd_peer_t));
    if (!p2p_state.peers) {
        return -1;
    }
    memset(p2p_state.peers, 0, MXD_MAX_PEERS * sizeof(mxd_peer_t));

    // Initialize mutex
    if (pthread_mutex_init(&p2p_state.peers_mutex, NULL) != 0) {
        free(p2p_state.peers);
        return -1;
    }

    // Create server socket
    p2p_state.server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (p2p_state.server_socket < 0) {
        pthread_mutex_destroy(&p2p_state.peers_mutex);
        free(p2p_state.peers);
        return -1;
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(p2p_state.server_socket, SOL_SOCKET, SO_REUSEADDR,
                   &opt, sizeof(opt)) < 0) {
        close(p2p_state.server_socket);
        pthread_mutex_destroy(&p2p_state.peers_mutex);
        free(p2p_state.peers);
        return -1;
    }

    // Set non-blocking mode
    int flags = fcntl(p2p_state.server_socket, F_GETFL, 0);
    if (flags < 0 || fcntl(p2p_state.server_socket, F_SETFL,
                          flags | O_NONBLOCK) < 0) {
        close(p2p_state.server_socket);
        pthread_mutex_destroy(&p2p_state.peers_mutex);
        free(p2p_state.peers);
        return -1;
    }

    // Bind socket
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(p2p_state.server_socket, (struct sockaddr *)&server_addr,
             sizeof(server_addr)) < 0) {
        close(p2p_state.server_socket);
        pthread_mutex_destroy(&p2p_state.peers_mutex);
        free(p2p_state.peers);
        return -1;
    }

    // Listen for connections
    if (listen(p2p_state.server_socket, SOMAXCONN) < 0) {
        close(p2p_state.server_socket);
        pthread_mutex_destroy(&p2p_state.peers_mutex);
        free(p2p_state.peers);
        return -1;
    }

    return 0;
}

// Server thread function
static void *server_thread_func(void *arg) {
    while (p2p_state.running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        // Accept connection
        int client_socket = accept(p2p_state.server_socket,
                                 (struct sockaddr *)&client_addr,
                                 &client_len);
        if (client_socket < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);  // Sleep 1ms if no connection
                continue;
            }
            break;
        }

        // Get client address
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        uint16_t client_port = ntohs(client_addr.sin_port);

        // Add peer
        pthread_mutex_lock(&p2p_state.peers_mutex);
        if (p2p_state.peer_count < MXD_MAX_PEERS) {
            mxd_peer_t *peer = &p2p_state.peers[p2p_state.peer_count];
            strncpy(peer->address, client_ip, sizeof(peer->address) - 1);
            peer->port = client_port;
            peer->state = MXD_PEER_CONNECTED;
            peer->last_seen = time(NULL);
            peer->latency = 0;
            p2p_state.peer_count++;
        }
        pthread_mutex_unlock(&p2p_state.peers_mutex);

        close(client_socket);
    }

    return NULL;
}

// Discovery thread function
static void *discovery_thread_func(void *arg) {
    while (p2p_state.running) {
        // TODO: Implement DHT-based peer discovery
        sleep(1);
    }
    return NULL;
}

// Start P2P networking
int mxd_start_p2p(void) {
    if (p2p_state.running) {
        return -1;
    }

    p2p_state.running = 1;

    // Start server thread
    if (pthread_create(&p2p_state.server_thread, NULL,
                      server_thread_func, NULL) != 0) {
        p2p_state.running = 0;
        return -1;
    }

    // Start discovery thread
    if (pthread_create(&p2p_state.discovery_thread, NULL,
                      discovery_thread_func, NULL) != 0) {
        p2p_state.running = 0;
        pthread_join(p2p_state.server_thread, NULL);
        return -1;
    }

    return 0;
}

// Stop P2P networking
int mxd_stop_p2p(void) {
    if (!p2p_state.running) {
        return -1;
    }

    p2p_state.running = 0;

    // Wait for threads to finish
    pthread_join(p2p_state.server_thread, NULL);
    pthread_join(p2p_state.discovery_thread, NULL);

    // Close server socket
    close(p2p_state.server_socket);

    // Clean up resources
    pthread_mutex_destroy(&p2p_state.peers_mutex);
    free(p2p_state.peers);
    memset(&p2p_state, 0, sizeof(p2p_state));

    return 0;
}

// Add peer to connection pool
int mxd_add_peer(const char *address, uint16_t port) {
    if (!address || !p2p_state.running) {
        return -1;
    }

    pthread_mutex_lock(&p2p_state.peers_mutex);

    // Check if peer already exists
    for (size_t i = 0; i < p2p_state.peer_count; i++) {
        if (strcmp(p2p_state.peers[i].address, address) == 0 &&
            p2p_state.peers[i].port == port) {
            pthread_mutex_unlock(&p2p_state.peers_mutex);
            return 0;  // Already exists, not an error
        }
    }

    // Add new peer
    if (p2p_state.peer_count < MXD_MAX_PEERS) {
        mxd_peer_t *peer = &p2p_state.peers[p2p_state.peer_count];
        strncpy(peer->address, address, sizeof(peer->address) - 1);
        peer->port = port;
        peer->state = MXD_PEER_CONNECTING;
        peer->last_seen = time(NULL);
        peer->latency = 0;
        p2p_state.peer_count++;
        pthread_mutex_unlock(&p2p_state.peers_mutex);
        return 0;
    }

    pthread_mutex_unlock(&p2p_state.peers_mutex);
    return -1;
}

// Remove peer from connection pool
int mxd_remove_peer(const char *address, uint16_t port) {
    if (!address || !p2p_state.running) {
        return -1;
    }

    pthread_mutex_lock(&p2p_state.peers_mutex);

    // Find and remove peer
    for (size_t i = 0; i < p2p_state.peer_count; i++) {
        if (strcmp(p2p_state.peers[i].address, address) == 0 &&
            p2p_state.peers[i].port == port) {
            // Shift remaining peers
            if (i < p2p_state.peer_count - 1) {
                memmove(&p2p_state.peers[i], &p2p_state.peers[i + 1],
                        (p2p_state.peer_count - i - 1) * sizeof(mxd_peer_t));
            }
            p2p_state.peer_count--;
            pthread_mutex_unlock(&p2p_state.peers_mutex);
            return 0;
        }
    }

    pthread_mutex_unlock(&p2p_state.peers_mutex);
    return -1;
}

// Get peer information
int mxd_get_peer(const char *address, uint16_t port, mxd_peer_t *peer) {
    if (!address || !peer || !p2p_state.running) {
        return -1;
    }

    pthread_mutex_lock(&p2p_state.peers_mutex);

    // Find peer
    for (size_t i = 0; i < p2p_state.peer_count; i++) {
        if (strcmp(p2p_state.peers[i].address, address) == 0 &&
            p2p_state.peers[i].port == port) {
            memcpy(peer, &p2p_state.peers[i], sizeof(mxd_peer_t));
            pthread_mutex_unlock(&p2p_state.peers_mutex);
            return 0;
        }
    }

    pthread_mutex_unlock(&p2p_state.peers_mutex);
    return -1;
}

// Get all connected peers
int mxd_get_peers(mxd_peer_t *peers, size_t *peer_count) {
    if (!peers || !peer_count || !p2p_state.running || *peer_count == 0) {
        return -1;
    }

    pthread_mutex_lock(&p2p_state.peers_mutex);

    // Copy connected peers
    size_t count = 0;
    for (size_t i = 0; i < p2p_state.peer_count && count < *peer_count; i++) {
        if (p2p_state.peers[i].state == MXD_PEER_CONNECTED ||
            p2p_state.peers[i].state == MXD_PEER_CONNECTING) {
            memcpy(&peers[count], &p2p_state.peers[i], sizeof(mxd_peer_t));
            count++;
        }
    }

    *peer_count = count;
    pthread_mutex_unlock(&p2p_state.peers_mutex);
    return 0;
}

// Send message to peer
int mxd_send_message(const char *address, uint16_t port,
                    mxd_message_type_t type,
                    const void *payload, size_t payload_length) {
    if (!address || !payload || payload_length > MXD_MAX_MESSAGE_SIZE ||
        !p2p_state.running) {
        return -1;
    }

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    // Set non-blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(sock);
        return -1;
    }

    // Connect to peer
    struct sockaddr_in peer_addr = {0};
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, address, &peer_addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    // Non-blocking connect
    if (connect(sock, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0) {
        if (errno != EINPROGRESS) {
            close(sock);
            return -1;
        }

        // Wait for connection
        fd_set write_fds;
        struct timeval timeout;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        if (select(sock + 1, NULL, &write_fds, NULL, &timeout) <= 0) {
            close(sock);
            return -1;
        }
    }

    // Create message header
    mxd_message_header_t header = {
        .magic = 0x4D584400,  // "MXD\0"
        .type = type,
        .length = payload_length
    };

    // Calculate checksum
    mxd_sha512(payload, payload_length, header.checksum);

    // Send header
    if (send(sock, &header, sizeof(header), 0) != sizeof(header)) {
        close(sock);
        return -1;
    }

    // Send payload
    if (send(sock, payload, payload_length, 0) != payload_length) {
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

// Broadcast message to all peers
int mxd_broadcast_message(mxd_message_type_t type,
                         const void *payload, size_t payload_length) {
    if (!payload || payload_length > MXD_MAX_MESSAGE_SIZE ||
        !p2p_state.running) {
        return -1;
    }

    pthread_mutex_lock(&p2p_state.peers_mutex);

    // Send message to all connected peers
    for (size_t i = 0; i < p2p_state.peer_count; i++) {
        if (p2p_state.peers[i].state == MXD_PEER_CONNECTED) {
            mxd_send_message(p2p_state.peers[i].address,
                           p2p_state.peers[i].port,
                           type, payload, payload_length);
        }
    }

    pthread_mutex_unlock(&p2p_state.peers_mutex);
    return 0;
}

// Set message handler callback
int mxd_set_message_handler(mxd_message_handler_t handler) {
    if (!handler || !p2p_state.running) {
        return -1;
    }

    p2p_state.message_handler = handler;
    return 0;
}

// Start DHT-based peer discovery
int mxd_start_peer_discovery(void) {
    // TODO: Implement DHT-based peer discovery
    return -1;
}

// Stop DHT-based peer discovery
int mxd_stop_peer_discovery(void) {
    // TODO: Implement DHT-based peer discovery
    return -1;
}

// Enable NAT traversal
int mxd_enable_nat_traversal(void) {
    // TODO: Implement NAT traversal
    return -1;
}

// Disable NAT traversal
int mxd_disable_nat_traversal(void) {
    // TODO: Implement NAT traversal
    return -1;
}

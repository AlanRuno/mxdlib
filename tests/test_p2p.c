#include "../include/mxd_p2p.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Test echo server state
static int echo_server_running = 0;
static pthread_t echo_server_thread;
static int echo_server_socket = -1;

// Message handler callback for testing
static int message_received = 0;
static void test_message_handler(const char *address, uint16_t port,
                                 mxd_message_type_t type, const void *payload,
                                 size_t payload_length) {
  message_received = 1;
}

// Echo server thread function
static void *echo_server_thread_func(void *arg) {
  // Create socket
  echo_server_socket = socket(AF_INET, SOCK_STREAM, 0);
  assert(echo_server_socket >= 0);

  // Set socket options
  int opt = 1;
  assert(setsockopt(echo_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt,
                    sizeof(opt)) >= 0);

  // Bind socket
  struct sockaddr_in server_addr = {0};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(12347);
  assert(bind(echo_server_socket, (struct sockaddr *)&server_addr,
              sizeof(server_addr)) >= 0);

  // Listen for connections
  assert(listen(echo_server_socket, SOMAXCONN) >= 0);

  echo_server_running = 1;

  // Accept and echo messages
  while (echo_server_running) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Accept connection
    int client_socket = accept(echo_server_socket,
                               (struct sockaddr *)&client_addr, &client_len);
    if (client_socket < 0) {
      continue;
    }

    // Read and echo data
    char buffer[1024];
    ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_read > 0) {
      send(client_socket, buffer, bytes_read, 0);
    }

    close(client_socket);
  }

  close(echo_server_socket);
  return NULL;
}

static void test_p2p_initialization(void) {
  // Create test public key
  uint8_t public_key[32] = {1}; // Test key filled with 1s
  
  // Initialize P2P with test port and public key
  assert(mxd_init_p2p(12345, public_key) == 0);

  // Start P2P networking
  assert(mxd_start_p2p() == 0);

  // Wait for network to initialize
  sleep(1);

  printf("P2P initialization test passed\n");
}

static void test_peer_management(void) {
  // Add peer
  assert(mxd_add_peer("127.0.0.1", 12346) == 0);

  // Wait for peer connection
  sleep(1);

  // Get peer information
  mxd_peer_t peer;
  assert(mxd_get_peer("127.0.0.1", 12346, &peer) == 0);
  assert(strcmp(peer.address, "127.0.0.1") == 0);
  assert(peer.port == 12346);

  // Get all peers
  mxd_peer_t peers[10];
  size_t peer_count = 10;
  assert(mxd_get_peers(peers, &peer_count) == 0);
  assert(peer_count == 1); // We should have exactly one peer

  // Remove peer
  assert(mxd_remove_peer("127.0.0.1", 12346) == 0);
  assert(mxd_get_peer("127.0.0.1", 12346, &peer) == -1);

  printf("Peer management test passed\n");
}

static void test_message_handling(void) {
  // Start echo server
  int ret = pthread_create(&echo_server_thread, NULL, echo_server_thread_func,
                        NULL);
  assert(ret == 0);

  // Wait for echo server to start
  while (!echo_server_running) {
    usleep(100000); // Sleep 100ms
  }

  // Set message handler
  assert(mxd_set_message_handler(test_message_handler) == 0);

  // Add test peer
  assert(mxd_add_peer("127.0.0.1", 12347) == 0);

  // Wait for peer connection
  sleep(1);

  // Send test message
  const char *test_message = "Hello, P2P!";
  assert(mxd_send_message("127.0.0.1", 12347, MXD_MSG_PING, test_message,
                          strlen(test_message)) == 0);

  // Broadcast test message
  assert(mxd_broadcast_message(MXD_MSG_PING, test_message,
                               strlen(test_message)) == 0);

  // Stop echo server
  echo_server_running = 0;

  // Force close server socket to unblock accept
  if (echo_server_socket >= 0) {
    close(echo_server_socket);
  }

  pthread_join(echo_server_thread, NULL);

  printf("Message handling test passed\n");
}

static void test_p2p_networking(void) {
  // Test peer discovery
  assert(mxd_start_peer_discovery() == 0);
  
  // Wait for DHT to initialize
  sleep(1);
  
  // Test NAT traversal
  assert(mxd_enable_nat_traversal() == 0);
  assert(mxd_disable_nat_traversal() == 0);
  
  // Stop peer discovery
  assert(mxd_stop_peer_discovery() == 0);
  
  // Stop P2P networking
  assert(mxd_stop_p2p() == 0);

  printf("P2P networking test passed\n");
}

int main(void) {
  printf("Starting P2P networking tests...\n");

  test_p2p_initialization();
  test_peer_management();
  test_message_handling();
  test_p2p_networking();

  printf("All P2P networking tests passed\n");
  return 0;
}

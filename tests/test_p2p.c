#include "../include/mxd_p2p.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
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
  // Create non-blocking socket
  echo_server_socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  assert(echo_server_socket >= 0);

  // Set socket options
  int opt = 1;
  assert(setsockopt(echo_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt,
                    sizeof(opt)) >= 0);
  
  // Set send/receive timeouts
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  assert(setsockopt(echo_server_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) >= 0);
  assert(setsockopt(echo_server_socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) >= 0);

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

  // Accept and echo messages with timeout
  while (echo_server_running) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Set accept timeout
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(echo_server_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // Accept connection
    int client_socket = accept(echo_server_socket,
                               (struct sockaddr *)&client_addr, &client_len);
    if (client_socket < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue; // Timeout, try again
      }
      break; // Real error, exit
    }

    // Set socket timeout
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

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

static int test_p2p_initialization(void) {
  // Create test public key
  uint8_t public_key[32] = {1}; // Test key filled with 1s
  
  // Initialize P2P with test port and public key
  assert(mxd_init_p2p(12345, public_key) == 0);

  // Start P2P networking
  assert(mxd_start_p2p() == 0);

  // Wait for network to initialize (100ms)
  usleep(100000);

  printf("P2P initialization test passed\n");
  return 0;
}

static int test_peer_management(void) {
  // Add peer
  assert(mxd_add_peer("127.0.0.1", 12347) == 0);

  // Wait for peer connection (max 5 seconds)
  int connect_retries = 50;
  while (connect_retries-- > 0) {
    mxd_peer_t peer;
    if (mxd_get_peer("127.0.0.1", 12347, &peer) == 0) {
      break;
    }
    usleep(100000); // Sleep 100ms
  }
  if (connect_retries < 0) {
    printf("Peer connection timeout\n");
    return 1;
  }

  // Get peer information
  mxd_peer_t peer;
  assert(mxd_get_peer("127.0.0.1", 12347, &peer) == 0);
  assert(strcmp(peer.address, "127.0.0.1") == 0);
  assert(peer.port == 12347);

  // Get all peers
  mxd_peer_t peers[10];
  size_t peer_count = 10;
  assert(mxd_get_peers(peers, &peer_count) == 0);
  assert(peer_count == 1); // We should have exactly one peer

  // Remove peer
  assert(mxd_remove_peer("127.0.0.1", 12347) == 0);
  assert(mxd_get_peer("127.0.0.1", 12347, &peer) == -1);

  printf("Peer management test passed\n");
  return 0;
}

static int test_message_handling(void) {
  // Start echo server
  int ret = pthread_create(&echo_server_thread, NULL, echo_server_thread_func,
                        NULL);
  assert(ret == 0);

  // Wait for echo server to start (max 1 second)
  int retries = 10;
  while (!echo_server_running && retries-- > 0) {
    usleep(100000); // Sleep 100ms
  }
  if (!echo_server_running) {
    printf("Echo server failed to start\n");
    return 1;
  }

  // Set message handler
  assert(mxd_set_message_handler(test_message_handler) == 0);

  // Add test peer
  assert(mxd_add_peer("127.0.0.1", 12347) == 0);

  // Wait for peer connection (max 5 seconds)
  int connect_retries = 50;
  while (connect_retries-- > 0) {
    mxd_peer_t peer;
    if (mxd_get_peer("127.0.0.1", 12347, &peer) == 0) {
      break;
    }
    usleep(100000); // Sleep 100ms
  }
  if (connect_retries < 0) {
    printf("Peer connection timeout\n");
    return 1;
  }

  // Send test message
  const char *test_message = "Hello, P2P!";
  assert(mxd_send_message("127.0.0.1", 12347, MXD_MSG_PING, test_message,
                          strlen(test_message)) == 0);

  // Broadcast test message
  assert(mxd_broadcast_message(MXD_MSG_PING, test_message,
                               strlen(test_message)) == 0);

  // Stop echo server with timeout
  echo_server_running = 0;

  // Force close server socket to unblock accept
  if (echo_server_socket >= 0) {
    close(echo_server_socket);
  }

  // Wait for thread to exit with timeout
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += 1; // 1 second timeout
  
  int join_result = pthread_join(echo_server_thread, NULL);
  if (join_result != 0) {
    printf("Echo server thread join failed\n");
    pthread_cancel(echo_server_thread);
  }

  printf("Message handling test passed\n");
  return 0;
}

static int test_p2p_networking(void) {
  // Test peer discovery
  assert(mxd_start_peer_discovery() == 0);
  
  // Wait for DHT to initialize (100ms)
  usleep(100000);
  
  // Test NAT traversal
  assert(mxd_enable_nat_traversal() == 0);
  assert(mxd_disable_nat_traversal() == 0);
  
  // Stop peer discovery
  assert(mxd_stop_peer_discovery() == 0);
  
  // Stop P2P networking
  assert(mxd_stop_p2p() == 0);

  printf("P2P networking test passed\n");
  return 0;
}

#include "../include/mxd_ntp.h"

int main(void) {
  printf("Starting P2P networking tests...\n");

  // Initialize NTP for timestamp synchronization
  if (mxd_init_ntp() != 0) {
    printf("Failed to initialize NTP\n");
    return 1;
  }

  // Set up signal handler for timeouts
  signal(SIGALRM, SIG_DFL);

  // Run tests with timeouts and cleanup
  alarm(10);
  int ret = test_p2p_initialization();
  alarm(0);
  if (ret != 0) {
    printf("P2P initialization test failed\n");
    mxd_stop_p2p();
    return 1;
  }
  usleep(100000); // Wait for cleanup

  alarm(10);
  ret = test_peer_management();
  alarm(0);
  if (ret != 0) {
    printf("Peer management test failed\n");
    mxd_stop_p2p();
    return 1;
  }
  usleep(100000); // Wait for cleanup

  alarm(15);
  ret = test_message_handling();
  alarm(0);
  if (ret != 0) {
    printf("Message handling test failed\n");
    mxd_stop_p2p();
    return 1;
  }
  usleep(100000); // Wait for cleanup

  alarm(10);
  ret = test_p2p_networking();
  alarm(0);
  if (ret != 0) {
    printf("P2P networking test failed\n");
    mxd_stop_p2p();
    return 1;
  }
  usleep(100000); // Wait for cleanup

  printf("All P2P networking tests passed\n");
  return 0;
}

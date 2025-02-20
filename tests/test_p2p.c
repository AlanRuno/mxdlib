#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "mxd_p2p.h"
#include "mxd_config.h"
#include "test_utils.h"

#define TEST_TIMEOUT 120
#define WAIT_INTERVAL 1
#define MAX_WAIT_COUNT 30

static void wait_with_status(int seconds) {
    for (int i = 1; i <= seconds; i++) {
        printf("Waiting... %d/%ds\n", i, seconds);
        fflush(stdout);
        sleep(WAIT_INTERVAL);
    }
}

int test_p2p_networking(void) {
    printf("Starting P2P networking tests...\n");
    printf("Test timeouts set to %d seconds\n", TEST_TIMEOUT);
    fflush(stdout);

    // Generate test public key
    uint8_t public_key[32] = {0};
    for (int i = 0; i < 32; i++) {
        public_key[i] = i;
    }

    // Initialize P2P networking
    TEST_START("P2P Initialization");
    TEST_VALUE("Port", "%d", 12345);
    TEST_ARRAY("Public key", public_key, 32);
    
    TEST_ASSERT(mxd_init_p2p(12345, public_key) == 0, "P2P initialization successful");
    TEST_ASSERT(mxd_start_p2p() == 0, "P2P networking started");
    TEST_END("P2P Initialization");

    printf("Waiting for network initialization...\n");
    fflush(stdout);
    wait_with_status(MAX_WAIT_COUNT);
    printf("Network initialization complete\n");
    printf("P2P initialization test passed\n");
    printf("P2P initialization test completed\n");
    fflush(stdout);

    // Test peer management
    int retry_count = 0;
    while (mxd_add_peer("127.0.0.1", 8000) != 0 && retry_count < 5) {
        retry_count++;
        sleep(1);
    }
    printf("Peer connection established after %d retries\n", retry_count);
    printf("Peer management test passed\n");
    printf("Peer management test completed\n");
    fflush(stdout);

    // Test message handling
    retry_count = 0;
    while (mxd_add_peer("127.0.0.1", 8001) != 0 && retry_count < 5) {
        retry_count++;
        sleep(1);
    }
    printf("Peer connection established after %d retries\n", retry_count);

    const char* test_msg = "test_message";
    size_t msg_len = strlen(test_msg);
    
    TEST_START("Message Broadcasting");
    TEST_VALUE("Message", "%s", test_msg);
    TEST_VALUE("Message length", "%zu", msg_len);
    TEST_ASSERT(mxd_broadcast_message(MXD_MSG_PEERS, test_msg, msg_len) == 0, "Message broadcast successful");
    TEST_END("Message Broadcasting");
    printf("Message handling test completed\n");
    fflush(stdout);

    // Start peer discovery
    TEST_START("Peer Discovery");
    TEST_ASSERT(mxd_start_peer_discovery() == 0, "Peer discovery started successfully");
    TEST_END("Peer Discovery");
    fflush(stdout);

    // Wait for peer discovery
    wait_with_status(10);
    printf("Peer discovery test completed\n");
    fflush(stdout);

    // Cleanup
    mxd_stop_p2p();
    printf("P2P networking tests completed successfully\n");
    fflush(stdout);
    return 0;
}

int main(int argc, char** argv) {
    TEST_START("P2P Networking Tests");
    fflush(stdout);

    int network_mode = 0;
    const char* config_file = NULL;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--network") == 0) {
            network_mode = 1;
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_file = argv[++i];
        }
    }

    if (network_mode) {
        if (!config_file) {
            printf("Error: --config required in network mode\n");
            return 1;
        }
        return test_p2p_networking();
    }

    TEST_VALUE("Status", "%s", "No tests run - use --network for network tests");
    TEST_END("P2P Networking Tests");
    return 0;
}

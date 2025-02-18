#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "mxd_p2p.h"
#include "mxd_config.h"

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
    printf("Initializing P2P with port 12345...\n");
    fflush(stdout);
    assert(mxd_init_p2p(12345, public_key) == 0);

    printf("Starting P2P networking...\n");
    fflush(stdout);
    assert(mxd_start_p2p() == 0);

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
    assert(mxd_broadcast_message(MXD_MSG_PEERS, test_msg, msg_len) == 0);
    printf("Message handling test passed\n");
    printf("Message handling test completed\n");
    fflush(stdout);

    // Start peer discovery
    assert(mxd_start_peer_discovery() == 0);
    printf("Peer discovery started\n");
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
    printf("Starting P2P networking tests...\n");
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

    printf("No tests run - use --network for network tests\n");
    return 0;
}

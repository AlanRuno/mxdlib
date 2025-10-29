#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include "mxd_p2p.h"
#include "mxd_config.h"

static volatile int running = 1;

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }
    
    uint16_t port = (uint16_t)atoi(argv[1]);
    
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    
    uint8_t public_key[32] = {0};
    for (int i = 0; i < 32; i++) {
        public_key[i] = i + 100;
    }
    
    if (mxd_init_p2p(port, public_key) != 0) {
        fprintf(stderr, "Failed to initialize P2P on port %d\n", port);
        return 1;
    }
    
    if (mxd_start_p2p() != 0) {
        fprintf(stderr, "Failed to start P2P\n");
        mxd_stop_p2p();
        return 1;
    }
    
    printf("Test node daemon started on port %d\n", port);
    fflush(stdout);
    
    while (running) {
        sleep(1);
    }
    
    printf("Test node daemon stopping\n");
    mxd_stop_p2p();
    
    return 0;
}

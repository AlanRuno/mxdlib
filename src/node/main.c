#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include "../include/mxd_config.h"
#include "../include/mxd_metrics.h"
#include "../include/mxd_dht.h"
#include "../include/blockchain/mxd_rsc.h"
#include "metrics_display.h"

static volatile int keep_running = 1;
static mxd_config_t current_config;
static mxd_node_metrics_t node_metrics;
static mxd_node_stake_t node_stake;
static pthread_mutex_t metrics_mutex = PTHREAD_MUTEX_INITIALIZER;

void handle_signal(int signum) {
    printf("\nReceived signal %d, terminating node %s...\n", 
           signum, current_config.node_id);
    fflush(stdout);
    keep_running = 0;
}

void* metrics_collector(void* arg) {
    uint64_t consecutive_errors = 0;
    uint64_t last_success_time = time(NULL);
    
    while (keep_running) {
        pthread_mutex_lock(&metrics_mutex);
        
        // Update metrics
        uint64_t current_time = time(NULL);
        uint64_t response_time = mxd_get_network_latency();
        
        if (response_time < 3000) {  // Performance requirement: latency < 3s
            mxd_update_metrics(&node_metrics, response_time);
            consecutive_errors = 0;
            last_success_time = current_time;
            
            // Record successful message
            mxd_record_message_result(&node_metrics, 1);
        } else {
            consecutive_errors++;
            if (consecutive_errors > 10) {  // Performance requirement: max 10 consecutive errors
                fprintf(stderr, "Warning: High consecutive error count: %lu\n", consecutive_errors);
            }
            // Record failed message
            mxd_record_message_result(&node_metrics, 0);
        }
        
        // Update stake info
        node_stake.metrics = node_metrics;
        node_stake.stake_amount = current_config.initial_stake;
        strncpy(node_stake.node_id, current_config.node_id, sizeof(node_stake.node_id) - 1);
        
        // Calculate TPS
        double time_diff = (double)(current_time - last_success_time);
        if (time_diff > 0) {
            double tps = node_metrics.message_success / time_diff;
            if (tps < 10.0) {  // Performance requirement: ≥10 TPS
                fprintf(stderr, "Warning: Low TPS: %.2f\n", tps);
            }
        }
        
        pthread_mutex_unlock(&metrics_mutex);
        usleep(current_config.metrics_interval * 1000);  // Convert ms to μs
    }
    return NULL;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("Usage: %s <config_file>\n", argv[0]);
        return 1;
    }

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);
    
    // Load configuration
    if (mxd_load_config(argv[1], &current_config) != 0) {
        fprintf(stderr, "Failed to load configuration\n");
        return 1;
    }
    
    // Initialize metrics
    if (mxd_init_metrics(&node_metrics) != 0) {
        fprintf(stderr, "Failed to initialize metrics\n");
        return 1;
    }
    
    // Initialize DHT node
    if (mxd_init_node(&current_config) != 0) {
        fprintf(stderr, "Failed to initialize DHT node\n");
        return 1;
    }
    
    // Start DHT service
    if (mxd_start_dht(current_config.port) != 0) {
        fprintf(stderr, "Failed to start DHT service\n");
        return 1;
    }
    
    // Start metrics collector thread
    pthread_t collector_thread;
    if (pthread_create(&collector_thread, NULL, metrics_collector, NULL) != 0) {
        fprintf(stderr, "Failed to start metrics collector\n");
        mxd_stop_dht();
        return 1;
    }
    
    printf("Node started successfully\n");
    
    // Main display loop
    while (keep_running) {
        pthread_mutex_lock(&metrics_mutex);
        
        // Update stake info from metrics
        node_stake.metrics = node_metrics;  // Copy all metrics
        node_stake.active = mxd_validate_performance(&node_metrics);
        node_stake.rank = (int)(node_metrics.performance_score * 100);
        
        display_node_metrics(&node_metrics, &node_stake);
        pthread_mutex_unlock(&metrics_mutex);
        sleep(1);
    }
    
    // Cleanup
    pthread_join(collector_thread, NULL);
    mxd_stop_dht();
    printf("Node terminated successfully\n");
    return 0;
}

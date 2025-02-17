#include "../include/mxd_metrics.h"
#include "../include/blockchain/mxd_metrics_internal.h"
#include "../include/mxd_ntp.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NUM_NODES 1000
#define NUM_UPDATES 10000

// Measure time in microseconds
static uint64_t get_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

// Test metric update performance
static void test_metric_update_performance(void) {
    printf("Testing metric update performance...\n");
    
    mxd_node_metrics_t metrics;
    mxd_init_metrics(&metrics);
    
    uint64_t start_time = get_time_us();
    
    // Perform many updates
    for (int i = 0; i < NUM_UPDATES; i++) {
        assert(mxd_update_metrics(&metrics, 100 + (i % 100)) == 0);
        assert(mxd_record_message_result(&metrics, i % 2) == 0);
    }
    
    uint64_t end_time = get_time_us();
    uint64_t total_time = end_time - start_time;
    double updates_per_second = (NUM_UPDATES * 1000000.0) / total_time;
    
    printf("Performed %d updates in %.2f ms (%.0f updates/second)\n",
           NUM_UPDATES, total_time / 1000.0, updates_per_second);
    assert(updates_per_second > 10000); // At least 10K updates/second
}

// Test scoring performance with many nodes
static void test_scoring_performance(void) {
    printf("Testing scoring performance with %d nodes...\n", NUM_NODES);
    
    mxd_node_metrics_t *metrics = malloc(NUM_NODES * sizeof(mxd_node_metrics_t));
    assert(metrics != NULL);
    
    // Initialize nodes with random data
    for (int i = 0; i < NUM_NODES; i++) {
        mxd_init_metrics(&metrics[i]);
        for (int j = 0; j < 100; j++) {
            mxd_update_metrics(&metrics[i], 100 + (j % 100));
            mxd_record_message_result(&metrics[i], j % 2);
        }
    }
    
    uint64_t start_time = get_time_us();
    
    // Calculate scores for all nodes
    double total_score = 0.0;
    for (int i = 0; i < NUM_NODES; i++) {
        double stake = 1.0 + (i % 100); // Random stake amount
        total_score += mxd_calculate_score(&metrics[i], stake);
    }
    
    uint64_t end_time = get_time_us();
    uint64_t total_time = end_time - start_time;
    double nodes_per_second = (NUM_NODES * 1000000.0) / total_time;
    
    printf("Scored %d nodes in %.2f ms (%.0f nodes/second)\n",
           NUM_NODES, total_time / 1000.0, nodes_per_second);
    assert(nodes_per_second > 1000); // At least 1K nodes/second
    
    free(metrics);
}

// Test memory usage
static void test_memory_usage(void) {
    printf("Testing memory usage...\n");
    
    // Allocate metrics for many nodes
    mxd_node_metrics_t *metrics = malloc(NUM_NODES * sizeof(mxd_node_metrics_t));
    assert(metrics != NULL);
    
    size_t total_size = NUM_NODES * sizeof(mxd_node_metrics_t);
    printf("Total memory for %d nodes: %.2f KB\n", 
           NUM_NODES, total_size / 1024.0);
    
    // Verify size per node is reasonable
    assert(sizeof(mxd_node_metrics_t) <= 128); // Max 128 bytes per node
    
    free(metrics);
}

int main(void) {
    printf("Starting node metrics performance tests...\n");
    
    // Initialize NTP
    if (mxd_init_ntp() != 0) {
        printf("Failed to initialize NTP\n");
        return 1;
    }
    
    // Run performance tests
    test_metric_update_performance();
    test_scoring_performance();
    test_memory_usage();
    
    printf("All node metrics performance tests passed!\n");
    return 0;
}

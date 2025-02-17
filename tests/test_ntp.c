#include "../include/mxd_ntp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

// Test NTP initialization
static void test_ntp_init(void) {
    printf("Testing NTP initialization...\n");
    assert(mxd_init_ntp() == 0);
    printf("NTP initialization test passed\n");
}

// Test time synchronization
static void test_time_sync(void) {
    printf("Testing time synchronization...\n");
    mxd_ntp_info_t info;
    assert(mxd_sync_time(&info) == 0);
    assert(info.timestamp > 0);
    assert(info.precision > 0);
    assert(info.delay >= 0);
    printf("Time synchronization test passed\n");
}

// Test network time retrieval
static void test_network_time(void) {
    printf("Testing network time retrieval...\n");
    uint64_t time1, time2;
    assert(mxd_get_network_time(&time1) == 0);
    assert(time1 > 0);
    
    // Sleep for 1 second
    sleep(1);
    
    assert(mxd_get_network_time(&time2) == 0);
    assert(time2 > time1);
    assert(time2 - time1 >= 1000); // At least 1 second difference
    printf("Network time retrieval test passed\n");
}

// Test error handling
static void test_error_handling(void) {
    printf("Testing error handling...\n");
    assert(mxd_sync_time(NULL) == -1);
    assert(mxd_get_network_time(NULL) == -1);
    printf("Error handling test passed\n");
}

// Network simulation test
static void test_network_conditions(void) {
    printf("Testing under various network conditions...\n");
    
    // Test with multiple consecutive syncs
    for (int i = 0; i < 5; i++) {
        mxd_ntp_info_t info;
        assert(mxd_sync_time(&info) == 0);
        assert(info.delay < 5000000); // Max 5s delay
        usleep(100000); // 100ms between syncs
    }
    
    // Test time consistency
    uint64_t times[10];
    for (int i = 0; i < 10; i++) {
        assert(mxd_get_network_time(&times[i]) == 0);
        if (i > 0) {
            assert(times[i] >= times[i-1]); // Time should never go backwards
            assert(times[i] - times[i-1] <= 1000); // Max 1s difference
        }
        usleep(50000); // 50ms between checks
    }
    
    printf("Network conditions test passed\n");
}

// Performance benchmark
static void benchmark_ntp_operations(void) {
    printf("Running NTP performance benchmarks...\n");
    
    struct timespec start, end;
    uint64_t total_sync_time = 0;
    uint64_t total_get_time = 0;
    const int iterations = 100;
    
    // Benchmark sync_time
    for (int i = 0; i < iterations; i++) {
        mxd_ntp_info_t info;
        clock_gettime(CLOCK_MONOTONIC, &start);
        mxd_sync_time(&info);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_sync_time += (end.tv_sec - start.tv_sec) * 1000000000ULL + (end.tv_nsec - start.tv_nsec);
        usleep(10000); // 10ms between syncs
    }
    
    // Benchmark get_network_time
    uint64_t timestamp;
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        mxd_get_network_time(&timestamp);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_get_time += (end.tv_sec - start.tv_sec) * 1000000000ULL + (end.tv_nsec - start.tv_nsec);
    }
    
    printf("Average sync_time operation: %lu ns\n", total_sync_time / iterations);
    printf("Average get_network_time operation: %lu ns\n", total_get_time / iterations);
    printf("Performance benchmark completed\n");
}

int main(void) {
    printf("Running NTP tests...\n");
    
    test_ntp_init();
    test_time_sync();
    test_network_time();
    test_error_handling();
    test_network_conditions();
    benchmark_ntp_operations();
    
    printf("All NTP tests passed!\n");
    return 0;
}

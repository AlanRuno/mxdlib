#include "../include/mxd_metrics.h"
#include "../include/blockchain/mxd_metrics_internal.h"
#include "../include/mxd_ntp.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Test metric initialization
static void test_init_metrics(void) {
    printf("Testing metric initialization...\n");
    
    mxd_node_metrics_t metrics;
    assert(mxd_init_metrics(&metrics) == 0);
    
    // Verify initial values
    assert(metrics.avg_response_time == 0);
    assert(metrics.min_response_time == UINT64_MAX);
    assert(metrics.max_response_time == 0);
    assert(metrics.response_count == 0);
    assert(metrics.message_success == 0);
    assert(metrics.message_total == 0);
    assert(metrics.reliability_score == 0.0);
    assert(metrics.performance_score == 0.0);
    
    printf("Metric initialization test passed\n");
}

// Test metric updates
static void test_update_metrics(void) {
    printf("Testing metric updates...\n");
    
    mxd_node_metrics_t metrics;
    mxd_init_metrics(&metrics);
    
    // Test response time updates
    assert(mxd_update_metrics(&metrics, 100) == 0);
    assert(metrics.avg_response_time == 100);
    assert(metrics.min_response_time == 100);
    assert(metrics.max_response_time == 100);
    assert(metrics.response_count == 1);
    
    assert(mxd_update_metrics(&metrics, 200) == 0);
    assert(metrics.avg_response_time == 150);
    assert(metrics.min_response_time == 100);
    assert(metrics.max_response_time == 200);
    assert(metrics.response_count == 2);
    
    // Test message result updates
    assert(mxd_record_message_result(&metrics, 1) == 0);
    assert(metrics.message_success == 1);
    assert(metrics.message_total == 1);
    
    assert(mxd_record_message_result(&metrics, 0) == 0);
    assert(metrics.message_success == 1);
    assert(metrics.message_total == 2);
    
    printf("Metric update test passed\n");
}

// Test performance scoring
static void test_performance_scoring(void) {
    printf("Testing performance scoring...\n");
    
    mxd_node_metrics_t metrics;
    mxd_init_metrics(&metrics);
    
    // Add some test data
    for (int i = 0; i < MXD_MIN_RESPONSE_COUNT + 5; i++) {
        mxd_update_metrics(&metrics, 100);
        mxd_record_message_result(&metrics, 1);
    }
    
    // Test with different stake amounts
    double score1 = mxd_calculate_score(&metrics, 10.0);
    double score2 = mxd_calculate_score(&metrics, 20.0);
    
    // Higher stake should result in higher score
    assert(score2 > score1);
    
    // Scores should be between 0 and 1
    assert(score1 >= 0.0 && score1 <= 1.0);
    assert(score2 >= 0.0 && score2 <= 1.0);
    
    printf("Performance scoring test passed\n");
}

// Test reliability validation
static void test_reliability_validation(void) {
    printf("Testing reliability validation...\n");
    
    mxd_node_metrics_t metrics;
    mxd_init_metrics(&metrics);
    
    // Should fail initial validation
    assert(mxd_validate_performance(&metrics) == 0);
    
    // Add successful responses
    for (int i = 0; i < MXD_MIN_RESPONSE_COUNT + 5; i++) {
        mxd_update_metrics(&metrics, 100);
        mxd_record_message_result(&metrics, 1);
    }
    
    // Should pass validation now
    assert(mxd_validate_performance(&metrics) == 1);
    
    // Add some failures
    for (int i = 0; i < 20; i++) {
        mxd_record_message_result(&metrics, 0);
    }
    
    // Should fail validation due to low success rate
    assert(mxd_validate_performance(&metrics) == 0);
    
    printf("Reliability validation test passed\n");
}

// Test metrics formatting
static void test_metrics_formatting(void) {
    printf("Testing metrics formatting...\n");
    
    mxd_node_metrics_t metrics;
    mxd_init_metrics(&metrics);
    
    // Add some test data
    mxd_update_metrics(&metrics, 100);
    mxd_update_metrics(&metrics, 200);
    mxd_record_message_result(&metrics, 1);
    mxd_record_message_result(&metrics, 1);
    
    char buffer[256];
    assert(mxd_format_metrics(&metrics, buffer, sizeof(buffer)) > 0);
    assert(strlen(buffer) > 0);
    
    printf("Metrics formatting test passed\n");
}

int main(void) {
    printf("Starting node metrics tests...\n");
    
    // Initialize NTP for timestamp synchronization
    if (mxd_init_ntp() != 0) {
        printf("Failed to initialize NTP\n");
        return 1;
    }
    
    // Run tests
    test_init_metrics();
    test_update_metrics();
    test_performance_scoring();
    test_reliability_validation();
    test_metrics_formatting();
    
    printf("All node metrics tests passed!\n");
    return 0;
}

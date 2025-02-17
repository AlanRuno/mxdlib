#ifndef MXD_METRICS_H
#define MXD_METRICS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Node performance metrics
typedef struct {
    uint64_t avg_response_time;    // Average response time in milliseconds
    uint64_t min_response_time;    // Minimum response time observed
    uint64_t max_response_time;    // Maximum response time observed
    uint32_t response_count;       // Number of responses recorded
    uint32_t message_success;      // Successful message count
    uint32_t message_total;        // Total message count
    double reliability_score;      // 0.0 to 1.0 reliability rating
    double performance_score;      // Combined performance metric
    uint64_t last_update;         // NTP synchronized timestamp
} mxd_node_metrics_t;

// Initialize node metrics
int mxd_init_metrics(mxd_node_metrics_t *metrics);

// Update node metrics with new response time
int mxd_update_metrics(mxd_node_metrics_t *metrics, uint64_t response_time);

// Record message success/failure
int mxd_record_message_result(mxd_node_metrics_t *metrics, int success);

// Calculate node performance score
double mxd_calculate_score(const mxd_node_metrics_t *metrics, double stake);

// Get node reliability score
double mxd_get_reliability(const mxd_node_metrics_t *metrics);

// Check if node meets minimum performance requirements
int mxd_validate_performance(const mxd_node_metrics_t *metrics);

// Get formatted metrics string for logging
int mxd_format_metrics(const mxd_node_metrics_t *metrics, char *buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif // MXD_METRICS_H

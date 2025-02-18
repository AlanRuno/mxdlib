#ifndef MXD_METRICS_TYPES_H
#define MXD_METRICS_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

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

// Node stake information
typedef struct {
    mxd_node_metrics_t metrics;    // Node performance metrics
    double stake_amount;           // Amount of stake held by node
    uint64_t stake_time;          // Time when stake was locked
} mxd_node_stake_t;

#ifdef __cplusplus
}
#endif

#endif // MXD_METRICS_TYPES_H

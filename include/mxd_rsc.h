#ifndef MXD_RSC_H
#define MXD_RSC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "mxd_blockchain.h"
#include "mxd_blockchain_db.h"

// Node performance metrics
typedef struct {
    uint64_t avg_response_time;    // Average response time in milliseconds
    uint64_t min_response_time;    // Minimum response time observed
    uint64_t max_response_time;    // Maximum response time observed
    uint32_t response_count;       // Number of responses recorded
    double tip_share;              // Node's share of distributed tips
    uint64_t last_update;          // Last update timestamp (NTP synchronized)
} mxd_node_metrics_t;

// Node stake information
typedef struct {
    char node_id[64];              // Unique node identifier
    double stake_amount;           // Amount of stake held
    uint8_t public_key[256];       // Node's public key
    mxd_node_metrics_t metrics;    // Node performance metrics
    uint32_t rank;                 // Current node rank
    uint8_t active;                // Node activity status
    uint8_t in_rapid_table;        // Whether node is in the Rapid Table
    uint32_t rapid_table_position; // Position in the Rapid Table (0 = highest)
} mxd_node_stake_t;

// Rapid Table structure
typedef struct {
    mxd_node_stake_t **nodes;      // Array of pointers to nodes in the table
    size_t count;                  // Number of nodes in the table
    size_t capacity;               // Allocated capacity for nodes
    uint64_t last_update;          // Last update timestamp
} mxd_rapid_table_t;

// Validation chain status
typedef enum {
    MXD_VALIDATION_PENDING = 0,    // Block is pending validation
    MXD_VALIDATION_IN_PROGRESS,    // Block is being validated
    MXD_VALIDATION_COMPLETE,       // Block has completed validation chain
    MXD_VALIDATION_REJECTED,       // Block was rejected during validation
    MXD_VALIDATION_EXPIRED         // Validation chain expired (5+ blocks)
} mxd_validation_status_t;

// Validation chain context
typedef struct {
    uint32_t height;               // Block height
    uint8_t block_hash[64];        // Block hash
    uint8_t proposer_id[20];       // Proposer's public key hash
    mxd_validation_status_t status; // Current validation status
    uint32_t signature_count;      // Number of signatures collected
    uint32_t required_signatures;  // Required signatures for quorum (50% of Rapid Table)
    uint64_t start_time;           // Validation start timestamp
    uint64_t expiry_time;          // Validation expiry timestamp
} mxd_validation_context_t;

// Validate if a node meets Rapid Stake requirements
int mxd_validate_node_stake(const mxd_node_stake_t *node, double total_stake);

// Initialize node metrics
int mxd_init_node_metrics(mxd_node_metrics_t *metrics);

// Update node response metrics with NTP-synchronized timestamp
int mxd_update_node_metrics(mxd_node_stake_t *node, uint64_t response_time, uint64_t timestamp);

// Calculate node ranking based on stake, speed, and reliability
int mxd_calculate_node_rank(const mxd_node_stake_t *node, double total_stake);

// Distribute voluntary tips based on node performance
int mxd_distribute_tips(mxd_node_stake_t *nodes, size_t node_count, double total_tip);

// Update rapid table entries and recalculate rankings
int mxd_update_rapid_table(mxd_node_stake_t *nodes, size_t node_count, double total_stake);

// Get node performance statistics
int mxd_get_node_stats(const mxd_node_stake_t *node, mxd_node_metrics_t *stats);

// Check if node meets minimum performance requirements
int mxd_validate_node_performance(const mxd_node_stake_t *node, uint64_t current_time);

// Initialize Rapid Table
int mxd_init_rapid_table(mxd_rapid_table_t *table, size_t capacity);

// Add node to Rapid Table
int mxd_add_to_rapid_table(mxd_rapid_table_t *table, mxd_node_stake_t *node);

// Remove node from Rapid Table
int mxd_remove_from_rapid_table(mxd_rapid_table_t *table, const char *node_id);

// Get node from Rapid Table by ID
mxd_node_stake_t *mxd_get_node_from_rapid_table(const mxd_rapid_table_t *table, const char *node_id);

// Free Rapid Table resources
void mxd_free_rapid_table(mxd_rapid_table_t *table);

// Initialize validation context for a block
int mxd_init_validation_context(mxd_validation_context_t *context, const mxd_block_t *block, 
                               const mxd_rapid_table_t *table);

// Add validator signature to block
int mxd_add_validator_signature_to_block(mxd_block_t *block, const uint8_t validator_id[20], 
                                        uint64_t timestamp, const uint8_t signature[128], 
                                        uint32_t chain_position);

// Verify validation chain integrity
int mxd_verify_validation_chain_integrity(const mxd_block_t *block);

// Check if block has reached validation quorum (≥50% of Rapid Table)
int mxd_block_has_validation_quorum(const mxd_block_t *block, const mxd_rapid_table_t *table);

// Check if block has minimum signatures for relay (X=3)
int mxd_block_has_min_relay_signatures(const mxd_block_t *block);

// Resolve fork between competing blocks using validation chain
int mxd_resolve_fork_by_validation(const mxd_block_t *block1, const mxd_block_t *block2, 
                                  const mxd_rapid_table_t *table);

// Calculate cumulative latency score for fork resolution
double mxd_calculate_validation_latency_score(const mxd_block_t *block, const mxd_rapid_table_t *table);

// Check if validator has signed conflicting blocks (for blacklisting)
int mxd_validator_signed_conflicting_blocks(const uint8_t validator_id[20], uint32_t height, 
                                           const uint8_t block_hash[64]);

// Blacklist validator for signing conflicting blocks
int mxd_blacklist_validator(const uint8_t validator_id[20], uint32_t duration);

// Check if validator is blacklisted
int mxd_is_validator_blacklisted(const uint8_t validator_id[20]);

// Get next validator in validation chain
int mxd_get_next_validator(const mxd_block_t *block, const mxd_rapid_table_t *table, 
                          uint8_t next_validator_id[20]);

// Process validation chain for a block
int mxd_process_validation_chain(mxd_block_t *block, mxd_validation_context_t *context, 
                                const mxd_rapid_table_t *table);

#ifdef __cplusplus
}
#endif

#endif // MXD_RSC_H

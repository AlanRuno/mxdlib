#include "../../include/mxd_rsc.h"
#include "../../include/mxd_ntp.h"
#include "../../include/mxd_blockchain_db.h"
#include "../../include/mxd_logging.h"
#include "../../include/mxd_utxo.h"
#include "../../include/mxd_crypto.h"
#include "../../include/mxd_p2p.h"
#include "../../include/mxd_endian.h"
#include "../../include/mxd_rocksdb_globals.h"
#include "../../include/mxd_config.h"
#include "../metrics/mxd_prometheus.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <pthread.h>
#include <rocksdb/c.h>

// Performance thresholds
#define MXD_MAX_RESPONSE_TIME 5000     // Maximum acceptable response time (ms)
#define MXD_MIN_RESPONSE_COUNT 10      // Minimum responses needed for ranking
#define MXD_INACTIVE_THRESHOLD 300000  // Node considered inactive after 5 minutes
#define MXD_RELIABILITY_WEIGHT 0.3     // Weight for reliability in ranking
#define MXD_SPEED_WEIGHT 0.4           // Weight for speed in ranking
#define MXD_STAKE_WEIGHT 0.3           // Weight for stake in ranking

// Validation chain thresholds
#define MXD_MIN_RELAY_SIGNATURES 3     // Minimum signatures required for relay (X=3)
#define MXD_VALIDATION_EXPIRY 5        // Validation signatures expire after 5 blocks
#define MXD_BLACKLIST_DURATION_DEFAULT 1000    // Default blacklist duration (in blocks) - Per Phase 4 spec: ban for 1000 blocks
#define MXD_MAX_TIMESTAMP_DRIFT_MS 60000ULL  // Maximum timestamp drift allowed (in milliseconds)

// Helper function to get blacklist duration from config or use default
static uint32_t get_blacklist_duration(void) {
    mxd_config_t *config = mxd_get_config();
    if (config && config->consensus.blacklist_duration_blocks > 0) {
        return config->consensus.blacklist_duration_blocks;
    }
    return MXD_BLACKLIST_DURATION_DEFAULT;
}

#include "../../include/mxd_rocksdb_globals.h"

// Initialize node metrics
int mxd_init_node_metrics(mxd_node_metrics_t *metrics) {
    if (!metrics) {
        return -1;
    }

    metrics->avg_response_time = 0;
    metrics->min_response_time = UINT64_MAX;
    metrics->max_response_time = 0;
    metrics->response_count = 0;
    metrics->tip_share = 0;
    metrics->last_update = 0;

    return 0;
}

// Validate if a node meets Rapid Stake requirements
int mxd_validate_node_stake(const mxd_node_stake_t *node, mxd_amount_t total_stake) {
    if (!node || total_stake == 0) {
        return -1;
    }

    // Check minimum stake requirement (1% of total stake)
    return (node->stake_amount >= total_stake / 100) ? 0 : -1;
}

// Update node response metrics with NTP-synchronized timestamp
int mxd_update_node_metrics(mxd_node_stake_t *node, uint64_t response_time, uint64_t timestamp) {
    if (!node || response_time > MXD_MAX_RESPONSE_TIME) {
        return -1;
    }

    mxd_node_metrics_t *metrics = &node->metrics;

    // Update response time statistics
    metrics->response_count++;
    double old_avg = metrics->avg_response_time;
    metrics->avg_response_time = old_avg + (response_time - old_avg) / metrics->response_count;
    metrics->min_response_time = response_time < metrics->min_response_time ? 
                                response_time : metrics->min_response_time;
    metrics->max_response_time = response_time > metrics->max_response_time ? 
                                response_time : metrics->max_response_time;
    metrics->last_update = timestamp;

    return 0;
}

// Calculate reliability score (0.0 to 1.0)
static double calculate_reliability(const mxd_node_metrics_t *metrics) {
    if (metrics->response_count < MXD_MIN_RESPONSE_COUNT) {
        return 0.0;
    }

    // Calculate consistency score based on response time variance
    double variance_score = 1.0 - (metrics->max_response_time - metrics->min_response_time) / 
                           (double)MXD_MAX_RESPONSE_TIME;
    if (variance_score < 0.0) variance_score = 0.0;

    return variance_score;
}

// Calculate node ranking based on stake, speed, and reliability
int mxd_calculate_node_rank(const mxd_node_stake_t *node, mxd_amount_t total_stake) {
    if (!node || total_stake == 0) {
        return -1;
    }

    const mxd_node_metrics_t *metrics = &node->metrics;
    
    // Node must have minimum responses and be active
    if (metrics->response_count < MXD_MIN_RESPONSE_COUNT || !node->active) {
        return -1;
    }

    // Calculate component scores (0.0 to 1.0)
    double speed_score = 1.0 - (metrics->avg_response_time / (double)MXD_MAX_RESPONSE_TIME);
    if (speed_score < 0.0) speed_score = 0.0;

    double stake_score = (double)node->stake_amount / (double)total_stake;
    double reliability_score = calculate_reliability(metrics);

    // Calculate weighted score
    double total_score = (speed_score * MXD_SPEED_WEIGHT) +
                        (stake_score * MXD_STAKE_WEIGHT) +
                        (reliability_score * MXD_RELIABILITY_WEIGHT);

    // Convert to integer rank (0-1000)
    return (int)(total_score * 1000.0);
}

// Compare function for node ranking
static int compare_nodes(const void *a, const void *b) {
    const mxd_node_stake_t *node_a = (const mxd_node_stake_t *)a;
    const mxd_node_stake_t *node_b = (const mxd_node_stake_t *)b;

    // Inactive nodes are ranked last
    if (node_a->active != node_b->active) {
        return node_a->active ? -1 : 1;
    }

    // Sort by rank (higher is better)
    if (node_a->rank != node_b->rank) {
        return (node_a->rank < node_b->rank) ? 1 : -1;
    }

    return 0;
}

// Compare function for node pointers (for qsort on pointer arrays)
static int compare_node_ptrs(const void *a, const void *b) {
    const mxd_node_stake_t *node_a = *(const mxd_node_stake_t * const *)a;
    const mxd_node_stake_t *node_b = *(const mxd_node_stake_t * const *)b;
    return compare_nodes(node_a, node_b);
}

// Distribute voluntary tips based on node performance
int mxd_distribute_tips(mxd_node_stake_t *nodes, size_t node_count, mxd_amount_t total_tip) {
    if (!nodes || node_count == 0 || total_tip == 0) {
        return -1;
    }

    // Count active nodes with positive rank
    size_t active_count = 0;
    for (size_t i = 0; i < node_count; i++) {
        if (nodes[i].active && nodes[i].rank > 0) {
            active_count++;
        }
    }

    if (active_count == 0) {
        // If no nodes have positive rank, distribute to all active nodes equally
        // This handles the case where nodes are active but rank calculation failed
        for (size_t i = 0; i < node_count; i++) {
            if (nodes[i].active) {
                active_count++;
            }
        }
        
        if (active_count == 0) {
            return -1;
        }
        
        // Distribute using 50% geometric decay pattern to all active nodes
        mxd_amount_t remaining = total_tip;
        size_t distributed_count = 0;
        for (size_t i = 0; i < node_count; i++) {
            if (nodes[i].active) {
                distributed_count++;
                if (distributed_count == active_count || remaining <= 1) {
                    // Last active node gets remaining amount
                    nodes[i].metrics.tip_share = remaining;
                    remaining = 0;
                } else {
                    // Each node gets 50% of remaining (integer division)
                    nodes[i].metrics.tip_share = remaining / 2;
                    remaining -= nodes[i].metrics.tip_share;
                }
            } else {
                nodes[i].metrics.tip_share = 0;
            }
        }
        return 0;
    }

    // Sort nodes by rank (highest to lowest)
    qsort(nodes, node_count, sizeof(mxd_node_stake_t), compare_nodes);

    // Distribute tips using 50% geometric decay pattern from whitepaper
    mxd_amount_t remaining = total_tip;
    size_t distributed_count = 0;
    for (size_t i = 0; i < node_count; i++) {
        if (nodes[i].active && nodes[i].rank > 0) {
            distributed_count++;
            if (distributed_count == active_count || remaining <= 1) {
                // Last active node gets remaining amount
                nodes[i].metrics.tip_share = remaining;
                remaining = 0;
            } else {
                // Each node gets 50% of remaining (integer division)
                nodes[i].metrics.tip_share = remaining / 2;
                remaining -= nodes[i].metrics.tip_share;
            }
        } else {
            nodes[i].metrics.tip_share = 0;
        }
    }

    return 0;
}

// Update rapid table entries and recalculate rankings
// CRITICAL FIX: Rapid table updates should be tied to block signing events
// This function should only be called when a block reaches quorum (not arbitrarily)
// The blockchain-based state requirement means rapid table modifications must occur
// at block signing events, not at arbitrary times.
int mxd_update_rapid_table(mxd_node_stake_t *nodes, size_t node_count, mxd_amount_t total_stake) {
    if (!nodes || node_count == 0 || total_stake == 0) {
        return -1;
    }

    uint64_t current_time = mxd_now_ms();

    // Update node activity status and calculate ranks
    for (size_t i = 0; i < node_count; i++) {
        // Check if node is active based on last update time
        nodes[i].active = (current_time - nodes[i].metrics.last_update) < MXD_INACTIVE_THRESHOLD;
        
        // Calculate new rank
        nodes[i].rank = mxd_calculate_node_rank(&nodes[i], total_stake);
    }

    // Sort nodes by rank
    qsort(nodes, node_count, sizeof(mxd_node_stake_t), compare_nodes);

    return 0;
}

int mxd_update_rapid_table_rankings(mxd_rapid_table_t *table) {
    if (!table || !table->nodes || table->count == 0) {
        return -1;
    }
    
    size_t total_count = 0;
    size_t pruned_count = 0;
    mxd_amount_t total_stake = 0;
    if (mxd_get_utxo_stats(&total_count, &pruned_count, &total_stake) != 0 || total_stake == 0) {
        MXD_LOG_WARN("rsc", "Could not get UTXO stats for rapid table update");
        return -1;
    }
    
    mxd_node_stake_t *flat_nodes = malloc(table->count * sizeof(mxd_node_stake_t));
    if (!flat_nodes) {
        return -1;
    }
    
    for (size_t i = 0; i < table->count; i++) {
        if (table->nodes[i]) {
            memcpy(&flat_nodes[i], table->nodes[i], sizeof(mxd_node_stake_t));
        } else {
            memset(&flat_nodes[i], 0, sizeof(mxd_node_stake_t));
        }
    }
    
    int result = mxd_update_rapid_table(flat_nodes, table->count, total_stake);
    
    if (result == 0) {
        for (size_t i = 0; i < table->count; i++) {
            if (table->nodes[i]) {
                memcpy(table->nodes[i], &flat_nodes[i], sizeof(mxd_node_stake_t));
            }
        }
        MXD_LOG_DEBUG("rsc", "Updated rapid table rankings for %zu nodes", table->count);
    }
    
    free(flat_nodes);
    return result;
}

// Get node performance statistics
int mxd_get_node_stats(const mxd_node_stake_t *node, mxd_node_metrics_t *stats) {
    if (!node || !stats) {
        return -1;
    }

    *stats = node->metrics;
    return 0;
}

// Check if node meets minimum performance requirements
int mxd_validate_node_performance(const mxd_node_stake_t *node, uint64_t current_time) {
    if (!node) {
        return -1;
    }

    // Check if node is active
    if (!node->active || 
        (current_time - node->metrics.last_update) >= MXD_INACTIVE_THRESHOLD) {
        return -1;
    }

    // Check minimum response count
    if (node->metrics.response_count < MXD_MIN_RESPONSE_COUNT) {
        return -1;
    }

    // Check average response time
    if (node->metrics.avg_response_time >= MXD_MAX_RESPONSE_TIME) {
        return -1;
    }

    return 0;
}

// Initialize Rapid Table
int mxd_init_rapid_table(mxd_rapid_table_t *table, size_t capacity) {
    if (!table || capacity == 0) {
        return -1;
    }
    
    table->nodes = malloc(capacity * sizeof(mxd_node_stake_t *));
    if (!table->nodes) {
        return -1;
    }
    
    memset(table->nodes, 0, capacity * sizeof(mxd_node_stake_t *));
    table->count = 0;
    table->capacity = capacity;
    
    table->last_update = mxd_now_ms();
    
    return 0;
}

int mxd_add_to_rapid_table(mxd_rapid_table_t *table, mxd_node_stake_t *node, const char *local_node_id) {
    if (!table || !node || !table->nodes) {
        return -1;
    }
    
    // Check if we're in genesis mode (network height is 0)
    uint32_t blockchain_height = 0;
    int is_genesis = (mxd_get_blockchain_height(&blockchain_height) != 0 || blockchain_height == 0);
    
    if (!is_genesis && local_node_id && strcmp(node->node_id, local_node_id) == 0) {
        MXD_LOG_DEBUG("rsc", "Skipping self-node %s from rapid table (non-genesis mode)", node->node_id);
        return 0; // Not an error, just skip
    }
    
    if (is_genesis && local_node_id && strcmp(node->node_id, local_node_id) == 0) {
        MXD_LOG_INFO("rsc", "Adding self-node %s to rapid table (genesis mode)", node->node_id);
    }
    
    // Check if node is already in table
    for (size_t i = 0; i < table->count; i++) {
        if (table->nodes[i] && strcmp(table->nodes[i]->node_id, node->node_id) == 0) {
            return 0; // Node already in table
        }
    }
    
    // Check if table is full
    if (table->count >= table->capacity) {
        return -1;
    }
    
    table->nodes[table->count] = node;
    node->in_rapid_table = 1;
    node->rapid_table_position = table->count;
    table->count++;
    
    table->last_update = mxd_now_ms();
    
    return 0;
}

int mxd_remove_from_rapid_table(mxd_rapid_table_t *table, const char *node_id) {
    if (!table || !node_id || !table->nodes) {
        return -1;
    }
    
    size_t index = 0;
    int found = 0;
    for (size_t i = 0; i < table->count; i++) {
        if (table->nodes[i] && strcmp(table->nodes[i]->node_id, node_id) == 0) {
            index = i;
            found = 1;
            break;
        }
    }
    
    if (!found) {
        return -1; // Node not in table
    }
    
    table->nodes[index]->in_rapid_table = 0;
    table->nodes[index]->rapid_table_position = 0;
    
    for (size_t i = index; i < table->count - 1; i++) {
        table->nodes[i] = table->nodes[i + 1];
        if (table->nodes[i]) {
            table->nodes[i]->rapid_table_position = i;
        }
    }
    
    table->nodes[table->count - 1] = NULL;
    table->count--;
    
    table->last_update = mxd_now_ms();
    
    return 0;
}

// Get node from Rapid Table by ID
mxd_node_stake_t *mxd_get_node_from_rapid_table(const mxd_rapid_table_t *table, const char *node_id) {
    if (!table || !node_id || !table->nodes) {
        return NULL;
    }
    
    for (size_t i = 0; i < table->count; i++) {
        if (table->nodes[i] && strcmp(table->nodes[i]->node_id, node_id) == 0) {
            return table->nodes[i];
        }
    }
    
    return NULL;
}

void mxd_free_rapid_table(mxd_rapid_table_t *table) {
    if (!table) {
        return;
    }
    
    if (table->nodes) {
        free(table->nodes);
        table->nodes = NULL;
    }
    
    table->count = 0;
    table->capacity = 0;
}

// Initialize validation context for a block
int mxd_init_validation_context(mxd_validation_context_t *context, const mxd_block_t *block, 
                               const mxd_rapid_table_t *table) {
    if (!context || !block || !table) {
        return -1;
    }
    
    // Initialize context
    memset(context, 0, sizeof(mxd_validation_context_t));
    context->height = block->height;
    memcpy(context->block_hash, block->block_hash, 64);
    memcpy(context->proposer_id, block->proposer_id, 20);
    context->status = MXD_VALIDATION_PENDING;
    context->signature_count = block->validation_count;
    
    // Calculate required signatures (50% of Rapid Table)
    context->required_signatures = (table->count + 1) / 2;
    
    uint64_t current_time = mxd_now_ms();
    context->start_time = current_time;
    
    context->expiry_time = current_time + (5 * 60 * 1000);
    
    return 0;
}

int mxd_add_validator_signature_to_block(mxd_block_t *block, const uint8_t validator_id[20], 
                                        uint64_t timestamp, uint8_t algo_id, const uint8_t *signature,
                                        uint16_t signature_length, uint32_t chain_position) {
    if (!block || !validator_id || !signature || signature_length == 0 || signature_length > MXD_SIGNATURE_MAX) {
        return -1;
    }
    
    // Validate algo_id
    if (algo_id != MXD_SIGALG_ED25519 && algo_id != MXD_SIGALG_DILITHIUM5) {
        MXD_LOG_ERROR("rsc", "Invalid algo_id %u in validator signature", algo_id);
        return -1;
    }
    
    // Validate signature length matches algorithm
    size_t expected_sig_len = mxd_sig_signature_len(algo_id);
    if (signature_length != expected_sig_len) {
        MXD_LOG_ERROR("rsc", "Signature length %u doesn't match algo_id %u (expected %zu)", 
                      signature_length, algo_id, expected_sig_len);
        return -1;
    }
    
    uint64_t current_time_ms = mxd_now_ms();
    
    if (llabs((int64_t)timestamp - (int64_t)current_time_ms) > (int64_t)MXD_MAX_TIMESTAMP_DRIFT_MS) {
        return -1;
    }
    
    for (uint32_t i = 0; i < block->validation_count; i++) {
        if (memcmp(block->validation_chain[i].validator_id, validator_id, 20) == 0) {
            return -1;
        }
    }
    
    // BLOCKER FIX: Verify signature content before adding to block
    // Signature must be over "block_hash + previous_validator_id + timestamp"
    uint8_t msg[64 + 20 + 8];
    memcpy(msg, block->block_hash, 64);
    if (block->validation_count == 0) {
        memset(msg + 64, 0, 20);
    } else {
        memcpy(msg + 64, block->validation_chain[block->validation_count - 1].validator_id, 20);
    }
    // CRITICAL FIX: Use big-endian encoding for timestamp (consistent with rest of codebase)
    uint64_t ts_be = mxd_htonll(timestamp);
    memcpy(msg + 64 + 20, &ts_be, 8);
    
    // Get validator's public key
    uint8_t pubbuf[4096];
    size_t publen = 0;
    if (mxd_get_validator_public_key(validator_id, pubbuf, sizeof(pubbuf), &publen) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to get validator public key for signature verification");
        return -1;
    }
    
    // Verify signature
    if (mxd_sig_verify(algo_id, signature, signature_length, msg, sizeof(msg), pubbuf) != 0) {
        MXD_LOG_ERROR("rsc", "Signature verification failed for validator");
        return -1;
    }
    
    if (!block->validation_chain) {
        block->validation_capacity = 10;
        block->validation_chain = malloc(block->validation_capacity * sizeof(mxd_validator_signature_t));
        if (!block->validation_chain) {
            return -1;
        }
    } else if (block->validation_count >= block->validation_capacity) {
        size_t new_capacity = block->validation_capacity * 2;
        mxd_validator_signature_t *new_chain = realloc(block->validation_chain, 
                                                     new_capacity * sizeof(mxd_validator_signature_t));
        if (!new_chain) {
            return -1;
        }
        block->validation_chain = new_chain;
        block->validation_capacity = new_capacity;
    }
    
    mxd_validator_signature_t *sig = &block->validation_chain[block->validation_count];
    memcpy(sig->validator_id, validator_id, 20);
    sig->timestamp = timestamp;
    sig->algo_id = algo_id;
    sig->signature_length = signature_length;
    memcpy(sig->signature, signature, sig->signature_length);
    sig->chain_position = chain_position;
    
    block->validation_count++;
    
    mxd_store_signature(block->height, validator_id, signature, signature_length);
    
    return 0;
}

int mxd_verify_validation_chain_integrity(const mxd_block_t *block) {
    if (!block || !block->validation_chain || block->validation_count == 0) {
        return -1;
    }
    
    for (uint32_t i = 0; i < block->validation_count; i++) {
        if (block->validation_chain[i].chain_position != i) {
            return -1; // Chain positions not sequential
        }
    }
    
    for (uint32_t i = 1; i < block->validation_count; i++) {
        if (block->validation_chain[i].timestamp < block->validation_chain[i-1].timestamp) {
            return -1; // Timestamps not monotonically increasing
        }
    }
    
    return 0;
}

// Check if block has reached validation quorum (≥50% of Rapid Table)
int mxd_block_has_validation_quorum(const mxd_block_t *block, const mxd_rapid_table_t *table) {
    if (!block || !table) {
        return -1;
    }
    
    // Calculate required signatures (50% of Rapid Table)
    uint32_t required_signatures = (table->count + 1) / 2;
    
    // Check if block has enough signatures
    return (block->validation_count >= required_signatures) ? 1 : 0;
}

// Check if block has minimum signatures for relay (X=3)
int mxd_block_has_min_relay_signatures(const mxd_block_t *block) {
    if (!block) {
        return -1;
    }
    
    // Check if block has minimum required signatures for relay
    return (block->validation_count >= MXD_MIN_RELAY_SIGNATURES) ? 1 : 0;
}

int mxd_resolve_fork_by_validation(const mxd_block_t *block1, const mxd_block_t *block2, 
                                  const mxd_rapid_table_t *table) {
    if (!block1 || !block2 || !table) {
        return -1;
    }
    
    // Check if blocks are at the same height
    if (block1->height != block2->height) {
        return (block1->height > block2->height) ? 1 : 2;
    }
    
    if (block1->validation_count != block2->validation_count) {
        return (block1->validation_count > block2->validation_count) ? 1 : 2;
    }
    
    double score1 = mxd_calculate_validation_latency_score(block1, table);
    double score2 = mxd_calculate_validation_latency_score(block2, table);
    
    if (fabs(score1 - score2) > 0.0001) { // Avoid floating point equality comparison
        return (score1 > score2) ? 1 : 2;
    }
    
    int cmp = memcmp(block1->block_hash, block2->block_hash, 64);
    return (cmp < 0) ? 1 : 2;
}

// Calculate cumulative latency score for fork resolution
double mxd_calculate_validation_latency_score(const mxd_block_t *block, const mxd_rapid_table_t *table) {
    if (!block || !block->validation_chain || block->validation_count == 0 || !table) {
        return 0.0;
    }
    
    // Calculate cumulative latency score using formula: Σ (1 / latency_i)
    double score = 0.0;
    
    for (uint32_t i = 0; i < block->validation_count; i++) {
        const uint8_t *validator_id = block->validation_chain[i].validator_id;
        
        for (size_t j = 0; j < table->count; j++) {
            if (table->nodes[j] && memcmp(table->nodes[j]->node_address, validator_id, 20) == 0) {
                uint64_t latency = table->nodes[j]->metrics.avg_response_time;
                if (latency < 1) latency = 1; // Avoid division by zero
                
                score += 1.0 / (double)latency;
                break;
            }
        }
    }
    
    return score;
}

// Check if validator has signed conflicting blocks (for blacklisting)
int mxd_validator_signed_conflicting_blocks(const uint8_t validator_id[20], uint32_t height, 
                                           const uint8_t block_hash[64]) {
    if (!validator_id || !block_hash) {
        return -1;
    }
    
    mxd_validator_signature_t *signatures = NULL;
    uint32_t *heights = NULL;
    size_t signature_count = 0;
    
    if (mxd_get_signatures_by_validator(validator_id, &signatures, &heights, &signature_count) != 0) {
        return -1;
    }
    
    if (!signatures || !heights || signature_count == 0) {
        return 0;
    }
    
    int conflict_found = 0;
    for (size_t i = 0; i < signature_count; i++) {
        if (heights[i] == height) {
            mxd_block_t block;
            memset(&block, 0, sizeof(mxd_block_t));
            
            if (mxd_retrieve_block_by_height(height, &block) == 0) {
                if (memcmp(block.block_hash, block_hash, 64) != 0) {
                    conflict_found = 1;
                    MXD_LOG_WARN("rsc", "Double-signing detected: validator signed conflicting blocks at height %u", height);
                    mxd_metrics_increment("validator_double_sign_detected_total");
                    
                    uint32_t blacklist_duration = get_blacklist_duration();
                    if (mxd_blacklist_validator(validator_id, blacklist_duration) == 0) {
                        MXD_LOG_INFO("rsc", "Validator automatically blacklisted for %u blocks due to double-signing", blacklist_duration);
                    }
                }
                
                if (block.validation_chain) {
                    free(block.validation_chain);
                }
            }
            
            if (conflict_found) {
                break;
            }
        }
    }
    
    free(signatures);
    free(heights);
    
    return conflict_found;
}

int mxd_blacklist_validator(const uint8_t validator_id[20], uint32_t duration) {
    if (!validator_id) {
        return -1;
    }
    
    uint32_t current_height = 0;
    if (mxd_get_blockchain_height(&current_height) != 0) {
        return -1;
    }
    
    uint32_t expiry_height = current_height + (duration > 0 ? duration : get_blacklist_duration());
    
    uint8_t key[10 + 20];
    memcpy(key, "blacklist:", 10);
    memcpy(key + 10, validator_id, 20);
    
    char value[10];
    snprintf(value, sizeof(value), "%u", expiry_height);
    
    if (!mxd_get_rocksdb_db()) {
        MXD_LOG_ERROR("rsc", "Blockchain DB not initialized");
        return -1;
    }
    
    char *err = NULL;
    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), (char *)key, sizeof(key), 
               value, strlen(value), &err);
    
    if (err) {
        MXD_LOG_ERROR("rsc", "Failed to blacklist validator: %s", err);
        free(err);
        return -1;
    }
    
    MXD_LOG_INFO("rsc", "Validator blacklisted until height %u (duration: %u blocks)", expiry_height, duration);
    mxd_metrics_increment("validator_blacklisted_total");
    return 0;
}

// Check if validator is blacklisted
int mxd_is_validator_blacklisted(const uint8_t validator_id[20]) {
    if (!validator_id) {
        return -1;
    }
    
    uint32_t current_height = 0;
    if (mxd_get_blockchain_height(&current_height) != 0) {
        return -1;
    }
    
    uint8_t key[10 + 20];
    memcpy(key, "blacklist:", 10);
    memcpy(key + 10, validator_id, 20);
    
    if (!mxd_get_rocksdb_db()) {
        MXD_LOG_ERROR("rsc", "Blockchain DB not initialized");
        return -1;
    }
    
    char *err = NULL;
    char *value = NULL;
    size_t value_len = 0;
    
    value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(), (char *)key, sizeof(key), &value_len, &err);
    
    if (err) {
        MXD_LOG_ERROR("rsc", "Failed to check blacklist status: %s", err);
        free(err);
        return -1;
    }
    
    if (value && value_len > 0) {
        uint32_t expiry_height = atoi(value);
        free(value);
        
        if (expiry_height > current_height) {
            return 1; // Validator is blacklisted
        }
    }
    
    return 0; // Not blacklisted
}

int mxd_get_next_validator(const mxd_block_t *block, const mxd_rapid_table_t *table, 
                          uint8_t next_validator_id[20]) {
    if (!block || !table || !next_validator_id) {
        return -1;
    }
    
    if (block->validation_count == 0) {
        if (table->count == 0) {
            return -1; // No validators in Rapid Table
        }
        
        memcpy(next_validator_id, table->nodes[0]->node_address, 20);
        return 0;
    }
    
    uint32_t last_position = 0;
    int found = 0;
    
    for (size_t i = 0; i < table->count; i++) {
        if (memcmp(table->nodes[i]->node_address, 
                  block->validation_chain[block->validation_count - 1].validator_id, 20) == 0) {
            last_position = i;
            found = 1;
            break;
        }
    }
    
    if (!found) {
        return -1; // Last validator not in Rapid Table
    }
    
    uint32_t next_position = (last_position + 1) % table->count;
    
    // Check if we've gone full circle
    if (next_position == 0 && block->validation_count > 0) {
        return -1; // All validators have signed
    }
    
    memcpy(next_validator_id, table->nodes[next_position]->node_address, 20);
    
    return 0;
}

int mxd_process_validation_chain(mxd_block_t *block, mxd_validation_context_t *context, 
                                const mxd_rapid_table_t *table) {
    if (!block || !context || !table) {
        return -1;
    }
    
    // Check if validation is already complete
    if (context->status == MXD_VALIDATION_COMPLETE) {
        return 0;
    }
    
    // Check if validation has expired
    uint64_t current_time = mxd_now_ms();
    
    if (current_time > context->expiry_time) {
        context->status = MXD_VALIDATION_EXPIRED;
        return -1;
    }
    
    // Update signature count
    context->signature_count = block->validation_count;
    
    // Check if block has reached quorum
    if (mxd_block_has_validation_quorum(block, table)) {
        context->status = MXD_VALIDATION_COMPLETE;
        
        if (block->total_supply == 0) {
            size_t total_count = 0;
            size_t pruned_count = 0;
            mxd_amount_t total_value = 0;
            if (mxd_get_utxo_stats(&total_count, &pruned_count, &total_value) == 0) {
                block->total_supply = total_value;
            }
        }
        
        // Distribute tips to validators in the validation chain
        if (block->validation_count > 0) {
            mxd_node_stake_t *validators = malloc(block->validation_count * sizeof(mxd_node_stake_t));
            if (validators) {
                // Initialize validators from validation chain
                for (uint32_t i = 0; i < block->validation_count; i++) {
                    memset(&validators[i], 0, sizeof(mxd_node_stake_t));
                    memcpy(validators[i].node_address, block->validation_chain[i].validator_id, 20);
                    validators[i].active = 1;
                }
                
                // Calculate tip distribution using 50% pattern
                mxd_amount_t total_tip = mxd_calculate_total_tip_from_frozen_set(block);
                
                if (total_tip > 0) {
                    mxd_distribute_tips(validators, block->validation_count, total_tip);
                    
                    mxd_transaction_t tip_tx;
                    if (mxd_create_transaction(&tip_tx) == 0) {
                        tip_tx.is_coinbase = 1;
                        
                        for (uint32_t i = 0; i < block->validation_count; i++) {
                            if (validators[i].metrics.tip_share > 0) {
                                if (mxd_add_tx_output(&tip_tx, validators[i].node_address, 
                                                     validators[i].metrics.tip_share) != 0) {
                                    break;
                                }
                            }
                        }
                        
                        // Calculate transaction hash
                        mxd_calculate_tx_hash(&tip_tx, tip_tx.tx_hash);
                        
                        mxd_create_utxos_from_tx(&tip_tx, tip_tx.tx_hash);
                        
                        // Free transaction resources
                        mxd_free_transaction(&tip_tx);
                    }
                }
                
                free(validators);
            }
        }
        
        mxd_store_block(block);
        
        return 0;
    }
    
    if (mxd_verify_validation_chain_integrity(block) != 0) {
        context->status = MXD_VALIDATION_REJECTED;
        return -1;
    }
    
    uint8_t next_validator_id[20];
    if (mxd_get_next_validator(block, table, next_validator_id) != 0) {
        if (context->signature_count >= context->required_signatures) {
            context->status = MXD_VALIDATION_COMPLETE;
            
            if (block->total_supply == 0) {
                size_t total_count = 0;
                size_t pruned_count = 0;
                mxd_amount_t total_value = 0;
                if (mxd_get_utxo_stats(&total_count, &pruned_count, &total_value) == 0) {
                    block->total_supply = total_value;
                }
            }
            
            mxd_store_block(block);
            
            return 0;
        } else {
            context->status = MXD_VALIDATION_REJECTED;
            return -1;
        }
    }
    
    // Update status to in progress
    context->status = MXD_VALIDATION_IN_PROGRESS;
    
    return 0;
}
static struct {
    uint8_t id[20];
    uint8_t algo_id;
    uint8_t pub[4096];
    size_t len;
} mxd_pubkey_registry[1024];

static size_t mxd_pubkey_registry_count;
static pthread_mutex_t mxd_pubkey_registry_mutex = PTHREAD_MUTEX_INITIALIZER;

int mxd_test_register_validator_pubkey(const uint8_t *validator_id, const uint8_t *pub, size_t pub_len) {
    uint8_t algo_id = MXD_SIGALG_ED25519;
    if (pub_len == 2592) {
        algo_id = MXD_SIGALG_DILITHIUM5;
    } else if (pub_len == 32) {
        algo_id = MXD_SIGALG_ED25519;
    }
    
    if (!validator_id || !pub || pub_len == 0 || pub_len > sizeof(mxd_pubkey_registry[0].pub)) return -1;
    
    pthread_mutex_lock(&mxd_pubkey_registry_mutex);
    
    if (mxd_pubkey_registry_count >= 1024) {
        pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
        return -1;
    }
    
    memcpy(mxd_pubkey_registry[mxd_pubkey_registry_count].id, validator_id, 20);
    mxd_pubkey_registry[mxd_pubkey_registry_count].algo_id = algo_id;
    memcpy(mxd_pubkey_registry[mxd_pubkey_registry_count].pub, pub, pub_len);
    mxd_pubkey_registry[mxd_pubkey_registry_count].len = pub_len;
    mxd_pubkey_registry_count++;
    
    pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
    
    if (mxd_store_validator_metadata(validator_id, algo_id, pub, pub_len) != 0) {
        MXD_LOG_WARN("rsc", "Failed to persist validator metadata to RocksDB");
    }
    
    return 0;
}

void mxd_test_clear_validator_pubkeys(void) {
    pthread_mutex_lock(&mxd_pubkey_registry_mutex);
    mxd_pubkey_registry_count = 0;
    pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
}

int mxd_get_validator_public_key(const uint8_t *validator_id, uint8_t *out_key, size_t out_capacity, size_t *out_len) {
    if (!validator_id || !out_key || !out_len) return -1;
    
    pthread_mutex_lock(&mxd_pubkey_registry_mutex);
    
    for (size_t i = 0; i < mxd_pubkey_registry_count; i++) {
        if (memcmp(mxd_pubkey_registry[i].id, validator_id, 20) == 0) {
            if (out_capacity < mxd_pubkey_registry[i].len) {
                pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
                return -1;
            }
            memcpy(out_key, mxd_pubkey_registry[i].pub, mxd_pubkey_registry[i].len);
            *out_len = mxd_pubkey_registry[i].len;
            pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
    return -1;
}

int mxd_get_validator_algo_id(const uint8_t *validator_id, uint8_t *out_algo_id) {
    if (!validator_id || !out_algo_id) return -1;
    
    pthread_mutex_lock(&mxd_pubkey_registry_mutex);
    
    for (size_t i = 0; i < mxd_pubkey_registry_count; i++) {
        if (memcmp(mxd_pubkey_registry[i].id, validator_id, 20) == 0) {
            *out_algo_id = mxd_pubkey_registry[i].algo_id;
            pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&mxd_pubkey_registry_mutex);
    return -1;
}

int mxd_should_add_to_rapid_table(const mxd_node_stake_t *node, mxd_amount_t total_supply, int is_genesis) {
    if (!node) {
        return 0;
    }
    
    if (is_genesis || total_supply == 0) {
        return 1;
    }
    
    // Check if stake is at least 1% of total supply
    if (node->stake_amount < total_supply / 100) {
        return 0;
    }
    
    if (!node->active) {
        return 0;
    }
    
    if (node->metrics.response_count < MXD_MIN_RESPONSE_COUNT) {
        return 0;
    }
    
    if (node->metrics.avg_response_time >= MXD_MAX_RESPONSE_TIME) {
        return 0;
    }
    
    return 1;
}

// MINOR FIX: Document time unit consistency - MXD_NODE_EXPIRY_TIME is in seconds (1 week = 604800 seconds)
#define MXD_NODE_EXPIRY_TIME 604800

int mxd_apply_membership_deltas(mxd_rapid_table_t *table, const mxd_block_t *block, 
                                const char *local_node_id) {
    if (!table || !block) {
        return -1;
    }
    
    if (!block->rapid_membership_entries || block->rapid_membership_count == 0) {
        return 0; // No deltas to apply
    }
    
    for (uint32_t i = 0; i < block->rapid_membership_count; i++) {
        const mxd_rapid_membership_entry_t *entry = &block->rapid_membership_entries[i];
        
        if (local_node_id) {
            char node_id_str[41];
            // Convert address bytes to hex string for comparison
            for (int j = 0; j < 20; j++) {
                snprintf(node_id_str + (j * 2), 3, "%02x", entry->node_address[j]);
            }
            node_id_str[40] = '\0';
            
            if (strcmp(node_id_str, local_node_id) == 0) {
                continue;
            }
        }
        
        // Check if node already exists in table
        int found = 0;
        for (size_t j = 0; j < table->count; j++) {
            // Compare node_address fields directly (both are 20-byte binary)
            if (table->nodes[j] && memcmp(table->nodes[j]->node_address, entry->node_address, 20) == 0) {
                // Update last activity timestamp
                table->nodes[j]->metrics.last_update = entry->timestamp;
                found = 1;
                break;
            }
        }
        
        if (!found && table->count < table->capacity) {
            if (!table->nodes[table->count]) {
                table->nodes[table->count] = malloc(sizeof(mxd_node_stake_t));
                if (!table->nodes[table->count]) {
                    continue;
                }
            }
            
            // Initialize new node
            memset(table->nodes[table->count], 0, sizeof(mxd_node_stake_t));
            memcpy(table->nodes[table->count]->node_id, entry->node_address, 20);
            table->nodes[table->count]->active = 1;
            table->nodes[table->count]->metrics.last_update = entry->timestamp;
            mxd_init_node_metrics(&table->nodes[table->count]->metrics);
            
            table->count++;
        }
    }
    
    return 0;
}

int mxd_remove_expired_nodes(mxd_rapid_table_t *table, uint64_t current_time) {
    if (!table) {
        return -1;
    }
    
    size_t write_idx = 0;
    for (size_t read_idx = 0; read_idx < table->count; read_idx++) {
        if (table->nodes[read_idx]) {
            uint64_t last_update = table->nodes[read_idx]->metrics.last_update;
            
            // Check if node has expired (1 week of inactivity)
            if (current_time > last_update && (current_time - last_update) > MXD_NODE_EXPIRY_TIME) {
                free(table->nodes[read_idx]);
                table->nodes[read_idx] = NULL;
            } else {
                if (write_idx != read_idx) {
                    table->nodes[write_idx] = table->nodes[read_idx];
                    table->nodes[read_idx] = NULL;
                }
                write_idx++;
            }
        }
    }
    
    table->count = write_idx;
    return 0;
}

int mxd_rebuild_rapid_table_from_blockchain(mxd_rapid_table_t *table, uint32_t from_height, 
                                            uint32_t to_height, const char *local_node_id) {
    if (!table) {
        return -1;
    }
    
    for (size_t i = 0; i < table->count; i++) {
        if (table->nodes[i]) {
            free(table->nodes[i]);
            table->nodes[i] = NULL;
        }
    }
    table->count = 0;
    
    for (uint32_t height = from_height; height <= to_height; height++) {
        mxd_block_t block;
        memset(&block, 0, sizeof(mxd_block_t));
        
        if (mxd_retrieve_block_by_height(height, &block) != 0) {
            continue;
        }
        
        mxd_apply_membership_deltas(table, &block, local_node_id);
        
        mxd_free_validation_chain(&block);
    }
    
    uint64_t current_time;
    if (mxd_get_network_time(&current_time) == 0) {
        mxd_remove_expired_nodes(table, current_time);
    }
    
    // Update rapid table rankings after rebuilding from blockchain
    mxd_update_rapid_table_rankings(table);
    
    return 0;
}

typedef struct {
    uint8_t node_address[20];
    uint8_t algo_id;
    uint8_t public_key[MXD_PUBKEY_MAX_LEN];
    uint16_t public_key_length;
    uint8_t signature[MXD_SIGNATURE_MAX];
    uint16_t signature_length;
    int received;
} mxd_genesis_signature_t;

static mxd_genesis_member_t *pending_genesis_members = NULL;
static size_t pending_genesis_count = 0;
static size_t pending_genesis_capacity = 0;
static uint8_t local_genesis_address[20] = {0};
static uint8_t local_genesis_algo_id = MXD_SIGALG_ED25519;
static uint8_t local_genesis_pubkey[MXD_PUBKEY_MAX_LEN] = {0};
static uint8_t local_genesis_privkey[MXD_PRIVKEY_MAX_LEN] = {0};
static int genesis_coordination_initialized = 0;
static mxd_genesis_signature_t collected_signatures[10];
static size_t collected_signature_count = 0;
static uint8_t pending_genesis_digest[64] = {0};
static int genesis_sign_request_sent = 0;
static int genesis_locked = 0;
static pthread_mutex_t genesis_mutex = PTHREAD_MUTEX_INITIALIZER;

// Genesis sync phase tracking
#define MXD_GENESIS_SYNC_TIMEOUT_MS 10000  // 10 seconds to wait for sync confirmations
#define MXD_GENESIS_SYNC_MIN_CONFIRMATIONS 3  // Minimum nodes that must agree on member list

typedef struct {
    uint8_t node_address[20];
    uint8_t member_list_hash[64];  // SHA-512 hash of sorted member addresses
    size_t member_count;
    uint64_t timestamp;
} mxd_genesis_sync_t;

static mxd_genesis_sync_t genesis_sync_confirmations[20];
static size_t genesis_sync_count = 0;
static uint64_t genesis_sync_started_time = 0;
static int genesis_sync_phase_complete = 0;
static uint8_t local_member_list_hash[64] = {0};

// Forward declaration for compare_addresses (defined later in file)
static int compare_addresses(const void *a, const void *b);

// Calculate hash of sorted member list for sync comparison
static int calculate_member_list_hash(uint8_t *hash_out) {
    if (!hash_out || pending_genesis_count == 0) {
        return -1;
    }
    
    // Create sorted copy of member addresses
    uint8_t sorted_addresses[20][20];
    for (size_t i = 0; i < pending_genesis_count && i < 20; i++) {
        memcpy(sorted_addresses[i], pending_genesis_members[i].node_address, 20);
    }
    
    // Sort addresses
    size_t count = pending_genesis_count < 20 ? pending_genesis_count : 20;
    qsort(sorted_addresses, count, 20, compare_addresses);
    
    // Hash the sorted addresses
    return mxd_sha512((uint8_t*)sorted_addresses, count * 20, hash_out);
}

// Broadcast genesis sync message with current member list hash
int mxd_broadcast_genesis_sync(void) {
    if (!genesis_coordination_initialized || pending_genesis_count < 3) {
        return -1;
    }
    
    pthread_mutex_lock(&genesis_mutex);
    
    // Calculate current member list hash
    if (calculate_member_list_hash(local_member_list_hash) != 0) {
        pthread_mutex_unlock(&genesis_mutex);
        return -1;
    }
    
    size_t count = pending_genesis_count;
    pthread_mutex_unlock(&genesis_mutex);
    
    // Build sync message: [node_address(20)] [member_count(4)] [member_list_hash(64)] [timestamp(8)]
    uint8_t message[20 + 4 + 64 + 8];
    size_t offset = 0;
    
    memcpy(message + offset, local_genesis_address, 20);
    offset += 20;
    
    uint32_t count_net = htonl((uint32_t)count);
    memcpy(message + offset, &count_net, 4);
    offset += 4;
    
    memcpy(message + offset, local_member_list_hash, 64);
    offset += 64;
    
    uint64_t timestamp = mxd_now_ms();
    uint64_t timestamp_net = mxd_htonll(timestamp);
    memcpy(message + offset, &timestamp_net, 8);
    offset += 8;
    
    MXD_LOG_INFO("rsc", "Broadcasting genesis sync: member_count=%zu", count);
    
    return mxd_broadcast_message(MXD_MSG_GENESIS_SYNC, message, offset);
}

// Handle incoming genesis sync message
int mxd_handle_genesis_sync(const uint8_t *node_address, size_t member_count, 
                            const uint8_t *member_list_hash, uint64_t timestamp) {
    if (!genesis_coordination_initialized || !node_address || !member_list_hash) {
        return -1;
    }
    
    pthread_mutex_lock(&genesis_mutex);
    
    // Check if we already have a sync from this node
    for (size_t i = 0; i < genesis_sync_count; i++) {
        if (memcmp(genesis_sync_confirmations[i].node_address, node_address, 20) == 0) {
            // Update existing entry if newer
            if (timestamp > genesis_sync_confirmations[i].timestamp) {
                genesis_sync_confirmations[i].member_count = member_count;
                memcpy(genesis_sync_confirmations[i].member_list_hash, member_list_hash, 64);
                genesis_sync_confirmations[i].timestamp = timestamp;
            }
            pthread_mutex_unlock(&genesis_mutex);
            return 0;
        }
    }
    
    // Add new sync confirmation
    if (genesis_sync_count < 20) {
        mxd_genesis_sync_t *sync = &genesis_sync_confirmations[genesis_sync_count];
        memcpy(sync->node_address, node_address, 20);
        sync->member_count = member_count;
        memcpy(sync->member_list_hash, member_list_hash, 64);
        sync->timestamp = timestamp;
        genesis_sync_count++;
        
        char addr_hex[41] = {0};
        for (int i = 0; i < 20; i++) {
            snprintf(addr_hex + (i * 2), 3, "%02x", node_address[i]);
        }
        MXD_LOG_INFO("rsc", "Received genesis sync from %s: member_count=%zu (total syncs: %zu)", 
                     addr_hex, member_count, genesis_sync_count);
    }
    
    pthread_mutex_unlock(&genesis_mutex);
    return 0;
}

// Check if sync phase is complete (enough nodes agree on member list)
static int check_genesis_sync_complete(void) {
    if (genesis_sync_phase_complete) {
        return 1;
    }
    
    // Calculate our current member list hash
    uint8_t our_hash[64];
    if (calculate_member_list_hash(our_hash) != 0) {
        return 0;
    }
    
    // Count how many nodes agree with our member list
    int matching_count = 1;  // Count ourselves
    
    for (size_t i = 0; i < genesis_sync_count; i++) {
        if (memcmp(genesis_sync_confirmations[i].member_list_hash, our_hash, 64) == 0 &&
            genesis_sync_confirmations[i].member_count == pending_genesis_count) {
            matching_count++;
        }
    }
    
    if (matching_count >= MXD_GENESIS_SYNC_MIN_CONFIRMATIONS) {
        MXD_LOG_INFO("rsc", "Genesis sync complete: %d nodes agree on member list (%zu members)", 
                     matching_count, pending_genesis_count);
        genesis_sync_phase_complete = 1;
        return 1;
    }
    
    return 0;
}

int mxd_init_genesis_coordination(const uint8_t *local_address, const uint8_t *local_pubkey, const uint8_t *local_privkey, uint8_t algo_id) {
    if (!local_address || !local_pubkey || !local_privkey) {
        return -1;
    }
    
    // Validate algo_id
    if (algo_id != MXD_SIGALG_ED25519 && algo_id != MXD_SIGALG_DILITHIUM5) {
        MXD_LOG_ERROR("rsc", "Invalid algo_id %u for genesis coordination", algo_id);
        return -1;
    }
    
    // Reset genesis_locked to allow new members to be added
    genesis_locked = 0;
    
    local_genesis_algo_id = algo_id;
    
    size_t pubkey_len = mxd_sig_pubkey_len(local_genesis_algo_id);
    size_t privkey_len = mxd_sig_privkey_len(local_genesis_algo_id);
    
    memcpy(local_genesis_address, local_address, 20);
    memcpy(local_genesis_pubkey, local_pubkey, pubkey_len);
    memcpy(local_genesis_privkey, local_privkey, privkey_len);
    
    pending_genesis_capacity = 10;
    pending_genesis_members = calloc(pending_genesis_capacity, sizeof(mxd_genesis_member_t));
    if (!pending_genesis_members) {
        return -1;
    }
    
    genesis_coordination_initialized = 1;
    
    // Automatically add local node to pending genesis members
    // This ensures the local node is counted as a genesis validator
    mxd_genesis_member_t *local_member = &pending_genesis_members[0];
    memcpy(local_member->node_address, local_address, 20);
    local_member->algo_id = algo_id;
    memcpy(local_member->public_key, local_pubkey, pubkey_len);
    local_member->timestamp = mxd_now_ms();
    // Sign the announce payload for consistency
    uint8_t announce_payload[20 + MXD_PUBKEY_MAX_LEN + 8];
    uint64_t timestamp_net = mxd_htonll(local_member->timestamp);
    memcpy(announce_payload, local_address, 20);
    memcpy(announce_payload + 20, local_pubkey, pubkey_len);
    memcpy(announce_payload + 20 + pubkey_len, &timestamp_net, 8);
    size_t announce_payload_len = 20 + pubkey_len + 8;
    size_t sig_len = sizeof(local_member->signature);
    if (mxd_sig_sign(algo_id, local_member->signature, &sig_len, announce_payload, announce_payload_len, local_privkey) == 0) {
        local_member->signature_length = (uint16_t)sig_len;
        pending_genesis_count = 1;
        
        // Register local node's public key for validation
        if (mxd_test_register_validator_pubkey(local_address, local_pubkey, pubkey_len) != 0) {
            MXD_LOG_WARN("rsc", "Failed to register local validator pubkey");
        }
        
        MXD_LOG_INFO("rsc", "Local node automatically added to pending genesis members");
    } else {
        MXD_LOG_WARN("rsc", "Failed to sign local genesis announce, local node not added to pending members");
    }
    
    MXD_LOG_INFO("rsc", "Genesis coordination initialized with %s", mxd_sig_alg_name(local_genesis_algo_id));
    return 0;
}

void mxd_cleanup_genesis_coordination(void) {
    if (pending_genesis_members) {
        free(pending_genesis_members);
        pending_genesis_members = NULL;
    }
    pending_genesis_count = 0;
    pending_genesis_capacity = 0;
    genesis_coordination_initialized = 0;
}

int mxd_broadcast_genesis_announce(void) {
    if (!genesis_coordination_initialized) {
        return -1;
    }
    
    size_t pubkey_len = mxd_sig_pubkey_len(local_genesis_algo_id);
    
    uint64_t current_time_ms = mxd_now_ms();
    uint64_t current_time_net = mxd_htonll(current_time_ms);
    
    uint8_t announce_payload[20 + MXD_PUBKEY_MAX_LEN + 8];
    memcpy(announce_payload, local_genesis_address, 20);
    memcpy(announce_payload + 20, local_genesis_pubkey, pubkey_len);
    memcpy(announce_payload + 20 + pubkey_len, &current_time_net, 8);
    
    size_t announce_payload_len = 20 + pubkey_len + 8;
    
    uint8_t signature[MXD_SIG_MAX_LEN];
    size_t signature_len = sizeof(signature);
    if (mxd_sig_sign(local_genesis_algo_id, signature, &signature_len, announce_payload, announce_payload_len, local_genesis_privkey) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to sign genesis announce");
        return -1;
    }
    
    MXD_LOG_INFO("rsc", "Generated genesis announce signature: algo=%s, sig_len=%zu, timestamp_ms=%lu", 
                 mxd_sig_alg_name(local_genesis_algo_id), signature_len, current_time_ms);
    
    uint8_t message[1 + 20 + 2 + MXD_PUBKEY_MAX_LEN + 8 + 2 + MXD_SIG_MAX_LEN];
    size_t offset = 0;
    
    message[offset] = local_genesis_algo_id;
    offset += 1;
    
    memcpy(message + offset, local_genesis_address, 20);
    offset += 20;
    
    uint16_t pubkey_len_net = htons((uint16_t)pubkey_len);
    memcpy(message + offset, &pubkey_len_net, 2);
    offset += 2;
    
    memcpy(message + offset, local_genesis_pubkey, pubkey_len);
    offset += pubkey_len;
    
    memcpy(message + offset, &current_time_net, 8);
    offset += 8;
    
    uint16_t sig_len_net = htons((uint16_t)signature_len);
    memcpy(message + offset, &sig_len_net, 2);
    offset += 2;
    
    memcpy(message + offset, signature, signature_len);
    offset += signature_len;
    
    MXD_LOG_INFO("rsc", "Constructed genesis announce message: total_size=%zu (algo=1, addr=20, pubkey_len=2, pubkey=%zu, time=8, sig_len=2, sig=%zu)", 
                offset, pubkey_len, signature_len);
    
    if (mxd_broadcast_message(MXD_MSG_GENESIS_ANNOUNCE, message, offset) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to broadcast genesis announce");
        return -1;
    }
    
    MXD_LOG_INFO("rsc", "Broadcast genesis announce: message_size=%zu", offset);
    return 0;
}

int mxd_handle_genesis_announce(uint8_t algo_id, const uint8_t *node_address, const uint8_t *public_key, 
                                 size_t pubkey_len, uint64_t timestamp, const uint8_t *signature, uint16_t signature_length) {
    if (!genesis_coordination_initialized || !node_address || !public_key || !signature) {
        MXD_LOG_WARN("rsc", "Genesis announce validation failed: initialized=%d, node_address=%p, public_key=%p, signature=%p",
                    genesis_coordination_initialized, (void*)node_address, (void*)public_key, (void*)signature);
        return -1;
    }
    
    size_t expected_pubkey_len = mxd_sig_pubkey_len(algo_id);
    if (expected_pubkey_len == 0 || pubkey_len != expected_pubkey_len) {
        MXD_LOG_WARN("rsc", "Invalid pubkey length %zu for algo %u (expected %zu)", 
                     pubkey_len, algo_id, expected_pubkey_len);
        return -1;
    }
    
    char addr_hex[41] = {0};
    for (int i = 0; i < 20; i++) {
        snprintf(addr_hex + (i * 2), 3, "%02x", node_address[i]);
    }
    MXD_LOG_INFO("rsc", "Processing genesis announce from address: %s, algo=%s, timestamp=%lu, sig_len=%u", 
                 addr_hex, mxd_sig_alg_name(algo_id), timestamp, signature_length);
    
    uint8_t derived_address[20];
    if (mxd_derive_address(algo_id, public_key, pubkey_len, derived_address) != 0) {
        MXD_LOG_WARN("rsc", "Failed to derive address from public key");
        return -1;
    }
    
    char derived_hex[41] = {0};
    for (int i = 0; i < 20; i++) {
        snprintf(derived_hex + (i * 2), 3, "%02x", derived_address[i]);
    }
    
    if (memcmp(node_address, derived_address, 20) != 0) {
        MXD_LOG_WARN("rsc", "Node address mismatch: announced=%s, derived=%s", addr_hex, derived_hex);
        return -1;
    }
    
    uint64_t current_time_ms = mxd_now_ms();
    
    int64_t drift_ms = llabs((int64_t)timestamp - (int64_t)current_time_ms);
    if (drift_ms > (int64_t)MXD_MAX_TIMESTAMP_DRIFT_MS) {
        MXD_LOG_WARN("rsc", "Genesis announce timestamp drift too large: drift=%ld ms (max=%llu ms)", 
                     drift_ms, MXD_MAX_TIMESTAMP_DRIFT_MS);
        return -1;
    }
    MXD_LOG_INFO("rsc", "Timestamp validation passed: drift=%ld ms", drift_ms);
    
    uint64_t timestamp_net = mxd_htonll(timestamp);
    uint8_t announce_payload[20 + MXD_PUBKEY_MAX_LEN + 8];
    memcpy(announce_payload, node_address, 20);
    memcpy(announce_payload + 20, public_key, pubkey_len);
    memcpy(announce_payload + 20 + pubkey_len, &timestamp_net, 8);
    
    size_t announce_payload_len = 20 + pubkey_len + 8;
    
    MXD_LOG_INFO("rsc", "Verifying signature: payload_size=%zu, sig_len=%u", announce_payload_len, signature_length);
    if (mxd_sig_verify(algo_id, signature, signature_length, announce_payload, announce_payload_len, public_key) != 0) {
        MXD_LOG_WARN("rsc", "Invalid genesis announce signature from %s", addr_hex);
        return -1;
    }
    MXD_LOG_INFO("rsc", "Signature verification passed for %s", addr_hex);
    
    // Protect genesis globals with mutex
    pthread_mutex_lock(&genesis_mutex);
    
    // Check if genesis coordination is locked (no new members allowed)
    if (genesis_locked) {
        MXD_LOG_DEBUG("rsc", "Genesis coordination locked, ignoring new member announce from %s", addr_hex);
        pthread_mutex_unlock(&genesis_mutex);
        return 0;
    }
    
    for (size_t i = 0; i < pending_genesis_count; i++) {
        if (memcmp(pending_genesis_members[i].node_address, node_address, 20) == 0) {
            MXD_LOG_DEBUG("rsc", "Genesis member already registered");
            pthread_mutex_unlock(&genesis_mutex);
            return 0;
        }
    }
    
    if (pending_genesis_count >= pending_genesis_capacity) {
        size_t new_capacity = pending_genesis_capacity * 2;
        mxd_genesis_member_t *new_members = realloc(pending_genesis_members, new_capacity * sizeof(mxd_genesis_member_t));
        if (!new_members) {
            pthread_mutex_unlock(&genesis_mutex);
            return -1;
        }
        pending_genesis_members = new_members;
        pending_genesis_capacity = new_capacity;
    }
    
    mxd_genesis_member_t *member = &pending_genesis_members[pending_genesis_count];
    memcpy(member->node_address, node_address, 20);
    member->algo_id = algo_id;
    memcpy(member->public_key, public_key, pubkey_len);
    member->timestamp = timestamp;
    memcpy(member->signature, signature, signature_length);
    member->signature_length = signature_length;
    pending_genesis_count++;
    
    size_t count = pending_genesis_count;
    pthread_mutex_unlock(&genesis_mutex);
    
    if (mxd_test_register_validator_pubkey(node_address, public_key, pubkey_len) != 0) {
        MXD_LOG_WARN("rsc", "Failed to register validator pubkey for genesis member");
    }
    
    MXD_LOG_INFO("rsc", "Registered genesis member (%zu/%d)", count, 3);
    return 0;
}

int mxd_get_pending_genesis_count(void) {
    pthread_mutex_lock(&genesis_mutex);
    int count = (int)pending_genesis_count;
    pthread_mutex_unlock(&genesis_mutex);
    return count;
}

int mxd_is_genesis_locked(void) {
    pthread_mutex_lock(&genesis_mutex);
    int locked = genesis_locked;
    pthread_mutex_unlock(&genesis_mutex);
    return locked;
}

void mxd_set_genesis_locked(int locked) {
    pthread_mutex_lock(&genesis_mutex);
    genesis_locked = locked;
    pthread_mutex_unlock(&genesis_mutex);
}

int mxd_sync_pending_genesis_to_rapid_table(mxd_rapid_table_t *table, const char *local_node_id) {
    if (!genesis_coordination_initialized || !table) {
        return -1;
    }
    
    if (genesis_locked) {
        MXD_LOG_DEBUG("rsc", "Genesis coordination locked, skipping sync to rapid table");
        return 0;
    }
    
    for (size_t i = 0; i < pending_genesis_count; i++) {
        mxd_genesis_member_t *member = &pending_genesis_members[i];
        
        // Convert node address to hex string for node_id
        char node_id_hex[41] = {0};
        for (int j = 0; j < 20; j++) {
            snprintf(node_id_hex + (j * 2), 3, "%02x", member->node_address[j]);
        }
        
        // Check if already in rapid table
        int found = 0;
        for (size_t j = 0; j < table->count; j++) {
            if (table->nodes[j] && strcmp(table->nodes[j]->node_id, node_id_hex) == 0) {
                found = 1;
                break;
            }
        }
        
        if (!found) {
            mxd_node_stake_t *node = malloc(sizeof(mxd_node_stake_t));
            if (!node) {
                continue;
            }
            
            memset(node, 0, sizeof(mxd_node_stake_t));
            strncpy(node->node_id, node_id_hex, sizeof(node->node_id) - 1);
            memcpy(node->node_address, member->node_address, 20);
            node->stake_amount = 0.0;
            node->active = 1;
            node->in_rapid_table = 1;
            
            // Initialize metrics
            mxd_init_node_metrics(&node->metrics);
            
            if (mxd_add_to_rapid_table(table, node, local_node_id) == 0) {
                MXD_LOG_INFO("rsc", "Added pre-genesis member %s to rapid table", node_id_hex);
            } else {
                free(node);
            }
        }
    }
    
    return 0;
}

static int compare_addresses(const void *a, const void *b) {
    return memcmp(a, b, 20);
}

int mxd_send_genesis_sign_request(const uint8_t *target_address, const uint8_t *membership_digest, 
                                   const uint8_t *proposer_id, uint32_t height,
                                   const mxd_genesis_member_t *members, size_t member_count) {
    if (!members || member_count == 0 || member_count > 10) {
        MXD_LOG_ERROR("rsc", "Invalid member list for genesis sign request");
        return -1;
    }
    
    size_t max_message_size = 20 + 64 + 20 + 4 + 1 + (member_count * (20 + 1 + 2 + MXD_PUBKEY_MAX_LEN));
    uint8_t *message = malloc(max_message_size);
    if (!message) {
        MXD_LOG_ERROR("rsc", "Failed to allocate memory for genesis sign request");
        return -1;
    }
    
    size_t offset = 0;
    
    memcpy(message + offset, target_address, 20);
    offset += 20;
    memcpy(message + offset, membership_digest, 64);
    offset += 64;
    memcpy(message + offset, proposer_id, 20);
    offset += 20;
    memcpy(message + offset, &height, 4);
    offset += 4;
    
    uint8_t count = (uint8_t)member_count;
    memcpy(message + offset, &count, 1);
    offset += 1;
    
    for (size_t i = 0; i < member_count; i++) {
        const mxd_genesis_member_t *m = &members[i];
        
        memcpy(message + offset, m->node_address, 20);
        offset += 20;
        
        memcpy(message + offset, &m->algo_id, 1);
        offset += 1;
        
        size_t pubkey_len = mxd_sig_pubkey_len(m->algo_id);
        uint16_t pubkey_len_net = htons((uint16_t)pubkey_len);
        memcpy(message + offset, &pubkey_len_net, 2);
        offset += 2;
        
        memcpy(message + offset, m->public_key, pubkey_len);
        offset += pubkey_len;
    }
    
    MXD_LOG_INFO("rsc", "Sending genesis sign request with %zu members, message size=%zu", member_count, offset);
    
    int result = mxd_broadcast_message(MXD_MSG_GENESIS_SIGN_REQUEST, message, offset);
    free(message);
    
    if (result != 0) {
        MXD_LOG_ERROR("rsc", "Failed to send genesis sign request");
        return -1;
    }
    
    return 0;
}

int mxd_handle_genesis_sign_request(const uint8_t *target_address, const uint8_t *membership_digest,
                                     const uint8_t *proposer_id, uint32_t height,
                                     const mxd_genesis_member_t *members, size_t member_count) {
    if (!genesis_coordination_initialized) {
        MXD_LOG_INFO("rsc", "Genesis sign request rejected: coordination not initialized");
        return -1;
    }
    
    // Log target address vs local address for debugging
    char target_hex[41], local_hex[41];
    for (int i = 0; i < 20; i++) {
        sprintf(target_hex + i*2, "%02x", target_address[i]);
        sprintf(local_hex + i*2, "%02x", local_genesis_address[i]);
    }
    MXD_LOG_INFO("rsc", "Genesis sign request: target=%s, local=%s", target_hex, local_hex);
    
    if (memcmp(target_address, local_genesis_address, 20) != 0) {
        MXD_LOG_INFO("rsc", "Genesis sign request not for this node (address mismatch)");
        return 0;
    }
    
    if (height != 0) {
        MXD_LOG_WARN("rsc", "Genesis sign request for non-zero height");
        return -1;
    }
    
    static int already_signed_genesis = 0;
    if (already_signed_genesis) {
        MXD_LOG_WARN("rsc", "Already signed genesis block");
        return -1;
    }
    
    // Accept sign requests if:
    // 1. Member count is at least 3 (minimum for genesis)
    // 2. This node is included in the member list
    // We trust the proposer's member list to ensure consistency across the network
    if (member_count < 3) {
        MXD_LOG_WARN("rsc", "Genesis sign request has insufficient members: %zu (need at least 3)", member_count);
        return -1;
    }
    
    // Verify this node is included in the member list
    int self_included = 0;
    for (size_t i = 0; i < member_count; i++) {
        if (memcmp(members[i].node_address, local_genesis_address, 20) == 0) {
            // Verify our public key matches
            size_t pubkey_len = mxd_sig_pubkey_len(local_genesis_algo_id);
            if (members[i].algo_id != local_genesis_algo_id) {
                MXD_LOG_WARN("rsc", "Genesis sign request has wrong algo_id for this node");
                return -1;
            }
            if (memcmp(members[i].public_key, local_genesis_pubkey, pubkey_len) != 0) {
                MXD_LOG_WARN("rsc", "Genesis sign request has wrong public_key for this node");
                return -1;
            }
            self_included = 1;
            break;
        }
    }
    
    if (!self_included) {
        MXD_LOG_DEBUG("rsc", "Genesis sign request does not include this node - ignoring");
        return 0;
    }
    
    MXD_LOG_INFO("rsc", "Accepting genesis sign request with %zu members (trusting proposer's list)", member_count);
    
    MXD_LOG_INFO("rsc", "Genesis sign request member list validated (%zu members)", member_count);
    
    genesis_locked = 1;
    MXD_LOG_INFO("rsc", "Genesis coordination locked - no new members will be accepted");
    
    uint8_t signature[MXD_SIGNATURE_MAX];
    size_t signature_len = sizeof(signature);
    if (mxd_sig_sign(local_genesis_algo_id, signature, &signature_len, membership_digest, 64, local_genesis_privkey) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to sign membership digest");
        return -1;
    }
    
    already_signed_genesis = 1;
    
    // Response format: signer_address (20) + proposer_id (20) + membership_digest (64) + sig_len (2) + signature
    uint8_t response[20 + 20 + 64 + 2 + 4096];
    size_t offset = 0;
    memcpy(response + offset, local_genesis_address, 20);
    offset += 20;
    memcpy(response + offset, proposer_id, 20);  // Include proposer_id so proposer can verify this response is for them
    offset += 20;
    memcpy(response + offset, membership_digest, 64);
    offset += 64;
    uint16_t sig_len = (uint16_t)signature_len;
    memcpy(response + offset, &sig_len, 2);
    offset += 2;
    memcpy(response + offset, signature, signature_len);
    offset += signature_len;
    
    if (mxd_broadcast_message(MXD_MSG_GENESIS_SIGN_RESPONSE, response, offset) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to send genesis sign response");
        return -1;
    }
    
    MXD_LOG_INFO("rsc", "Sent genesis signature response for proposer");
    return 0;
}

int mxd_handle_genesis_sign_response(const uint8_t *signer_address, const uint8_t *proposer_id,
                                      const uint8_t *membership_digest,
                                      const uint8_t *signature, uint16_t signature_length) {
    if (!genesis_coordination_initialized) {
        return -1;
    }
    
    if (!genesis_sign_request_sent) {
        MXD_LOG_DEBUG("rsc", "Ignoring genesis sign response (not active proposer)");
        return 0;
    }
    
    // Verify this response is for our sign request (not another proposer's)
    if (memcmp(proposer_id, local_genesis_address, 20) != 0) {
        MXD_LOG_DEBUG("rsc", "Ignoring genesis sign response for different proposer");
        return 0;
    }
    
    if (memcmp(membership_digest, pending_genesis_digest, 64) != 0) {
        MXD_LOG_WARN("rsc", "Genesis sign response digest mismatch");
        return -1;
    }
    
    for (size_t i = 0; i < collected_signature_count; i++) {
        if (memcmp(collected_signatures[i].node_address, signer_address, 20) == 0) {
            MXD_LOG_DEBUG("rsc", "Already have signature from this node");
            return 0;
        }
    }
    
    uint8_t signer_pubkey[MXD_PUBKEY_MAX_LEN];
    size_t pubkey_len = sizeof(signer_pubkey);
    if (mxd_get_validator_public_key(signer_address, signer_pubkey, sizeof(signer_pubkey), &pubkey_len) != 0) {
        MXD_LOG_WARN("rsc", "Failed to get public key for signer");
        return -1;
    }
    
    uint8_t signer_algo_id;
    if (mxd_get_validator_algo_id(signer_address, &signer_algo_id) != 0) {
        MXD_LOG_WARN("rsc", "Failed to get algorithm ID for signer");
        return -1;
    }
    
    if (mxd_sig_verify(signer_algo_id, signature, signature_length, membership_digest, 64, signer_pubkey) != 0) {
        MXD_LOG_WARN("rsc", "Invalid genesis signature");
        return -1;
    }
    
    if (collected_signature_count >= 10) {
        MXD_LOG_WARN("rsc", "Too many collected signatures");
        return -1;
    }
    
    mxd_genesis_signature_t *sig = &collected_signatures[collected_signature_count];
    memcpy(sig->node_address, signer_address, 20);
    sig->algo_id = signer_algo_id;
    memcpy(sig->public_key, signer_pubkey, pubkey_len);
    sig->public_key_length = (uint16_t)pubkey_len;
    memcpy(sig->signature, signature, signature_length);
    sig->signature_length = signature_length;
    sig->received = 1;
    collected_signature_count++;
    
    MXD_LOG_INFO("rsc", "Collected genesis signature (%zu/3)", collected_signature_count);
    return 0;
}

// Track when we first had 3+ genesis members for timeout-based proposer fallback
static uint64_t genesis_quorum_reached_time = 0;
#define MXD_GENESIS_PROPOSER_TIMEOUT_MS 30000  // 30 seconds timeout for proposer fallback

int mxd_try_coordinate_genesis_block(void) {
    if (!genesis_coordination_initialized) {
        return -1;
    }
    
    uint32_t blockchain_height = 0;
    if (mxd_get_blockchain_height(&blockchain_height) == 0 && blockchain_height > 0) {
        return 0;
    }
    
    if (pending_genesis_count < 3) {
        genesis_quorum_reached_time = 0;  // Reset timeout tracking
        return 0;
    }
    
    // Track when we first reached quorum
    uint64_t current_time = mxd_now_ms();
    if (genesis_quorum_reached_time == 0) {
        genesis_quorum_reached_time = current_time;
        genesis_sync_started_time = current_time;
        genesis_locked = 1;  // Lock member list immediately when quorum is reached
        MXD_LOG_INFO("rsc", "Genesis quorum reached with %zu members, locking member list and starting sync phase", pending_genesis_count);
    }
    
    // Sync phase: broadcast our member list hash and wait for confirmations
    if (!genesis_sync_phase_complete) {
        // Periodically broadcast sync message (every 2 seconds)
        static uint64_t last_sync_broadcast = 0;
        if (current_time - last_sync_broadcast > 2000) {
            mxd_broadcast_genesis_sync();
            last_sync_broadcast = current_time;
        }
        
        // Check if sync is complete
        if (!check_genesis_sync_complete()) {
            // Check for sync timeout
            if (current_time - genesis_sync_started_time > MXD_GENESIS_SYNC_TIMEOUT_MS) {
                MXD_LOG_WARN("rsc", "Genesis sync timeout after %llu ms, proceeding with %zu sync confirmations",
                            (unsigned long long)(current_time - genesis_sync_started_time), genesis_sync_count);
                genesis_sync_phase_complete = 1;
            } else {
                return 0;  // Still waiting for sync
            }
        }
        MXD_LOG_INFO("rsc", "Genesis sync phase complete, proceeding to sign request phase");
    }
    
    uint8_t addresses[10][20];
    size_t addr_count = 0;
    
    for (size_t i = 0; i < pending_genesis_count && addr_count < 10; i++) {
        memcpy(addresses[addr_count], pending_genesis_members[i].node_address, 20);
        addr_count++;
    }
    
    qsort(addresses, addr_count, 20, compare_addresses);
    
    // Check if this node is the designated proposer (lexicographically smallest address)
    int is_designated_proposer = (memcmp(local_genesis_address, addresses[0], 20) == 0);
    
    // Allow fallback proposer if timeout exceeded and we're in the top 3
    int is_fallback_proposer = 0;
    if (!is_designated_proposer && (current_time - genesis_quorum_reached_time) > MXD_GENESIS_PROPOSER_TIMEOUT_MS) {
        for (size_t i = 1; i < addr_count && i < 3; i++) {
            if (memcmp(local_genesis_address, addresses[i], 20) == 0) {
                is_fallback_proposer = 1;
                MXD_LOG_INFO("rsc", "Designated proposer timeout, this node becoming fallback proposer (position %zu)", i);
                break;
            }
        }
    }
    
    if (!is_designated_proposer && !is_fallback_proposer) {
        return 0;
    }
    
    if (!genesis_sign_request_sent) {
        MXD_LOG_INFO("rsc", "This node is the designated proposer for genesis block");
        
        mxd_block_t genesis_block;
        uint8_t prev_hash[64] = {0};
        
        if (mxd_init_block(&genesis_block, prev_hash) != 0) {
            MXD_LOG_ERROR("rsc", "Failed to initialize genesis block");
            return -1;
        }
        
        genesis_block.height = 0;
        genesis_block.total_supply = 0; // Genesis has no supply yet
        memcpy(genesis_block.proposer_id, local_genesis_address, 20);
        
        if (mxd_freeze_transaction_set(&genesis_block) != 0) {
            MXD_LOG_ERROR("rsc", "Failed to freeze genesis block transaction set");
            mxd_free_validation_chain(&genesis_block);
            return -1;
        }
        
        if (mxd_calculate_membership_digest(&genesis_block, pending_genesis_digest) != 0) {
            MXD_LOG_ERROR("rsc", "Failed to calculate membership digest");
            mxd_free_validation_chain(&genesis_block);
            return -1;
        }
        
        mxd_free_validation_chain(&genesis_block);
        
        uint8_t self_signature[MXD_SIGNATURE_MAX];
        size_t self_sig_len = sizeof(self_signature);
        if (mxd_sig_sign(local_genesis_algo_id, self_signature, &self_sig_len, pending_genesis_digest, 64, local_genesis_privkey) != 0) {
            MXD_LOG_ERROR("rsc", "Failed to sign own membership");
            return -1;
        }
        
        mxd_genesis_signature_t *self_sig = &collected_signatures[collected_signature_count];
        memcpy(self_sig->node_address, local_genesis_address, 20);
        self_sig->algo_id = local_genesis_algo_id;
        size_t local_pubkey_len = mxd_sig_pubkey_len(local_genesis_algo_id);
        memcpy(self_sig->public_key, local_genesis_pubkey, local_pubkey_len);
        self_sig->public_key_length = (uint16_t)local_pubkey_len;
        memcpy(self_sig->signature, self_signature, self_sig_len);
        self_sig->signature_length = (uint16_t)self_sig_len;
        self_sig->received = 1;
        collected_signature_count++;
        
        for (size_t i = 0; i < pending_genesis_count && i < 3; i++) {
            if (memcmp(pending_genesis_members[i].node_address, local_genesis_address, 20) != 0) {
                mxd_send_genesis_sign_request(pending_genesis_members[i].node_address, 
                                              pending_genesis_digest, local_genesis_address, 0,
                                              pending_genesis_members, pending_genesis_count);
            }
        }
        
        genesis_sign_request_sent = 1;
        MXD_LOG_INFO("rsc", "Sent genesis sign requests to peers");
        return 0;
    }
    
    if (collected_signature_count < 3) {
        return 0;
    }
    
    static int genesis_creation_attempted = 0;
    if (genesis_creation_attempted) {
        return 0;
    }
    genesis_creation_attempted = 1;
    
    MXD_LOG_INFO("rsc", "Have %zu signatures, creating genesis block", collected_signature_count);
    
    mxd_block_t genesis_block;
    uint8_t prev_hash[64] = {0};
    
    if (mxd_init_block(&genesis_block, prev_hash) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to initialize genesis block");
        genesis_creation_attempted = 0;
        return -1;
    }
    
    genesis_block.height = 0;
    genesis_block.total_supply = 0; // Genesis has no supply yet
    memcpy(genesis_block.proposer_id, local_genesis_address, 20);
    
    if (mxd_freeze_transaction_set(&genesis_block) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to freeze genesis block transaction set");
        genesis_creation_attempted = 0;
        return -1;
    }
    
    if (mxd_get_network_time(&current_time) != 0) {
        current_time = mxd_now_ms(); // Use NTP-synchronized time in milliseconds
    }
    
    for (size_t i = 0; i < collected_signature_count && i < 3; i++) {
        mxd_genesis_signature_t *sig = &collected_signatures[i];
        
        if (mxd_append_membership_entry(&genesis_block, sig->node_address, 
                                        sig->algo_id, sig->public_key, sig->public_key_length,
                                        sig->signature, sig->signature_length, current_time) != 0) {
            MXD_LOG_WARN("rsc", "Failed to append membership entry for signature %zu", i);
            continue;
        }
    }
    
    if (!mxd_block_has_membership_quorum(&genesis_block, 0)) {
        MXD_LOG_ERROR("rsc", "Genesis block does not have quorum (%u/3 validators)",
                     genesis_block.rapid_membership_count);
        genesis_creation_attempted = 0;
        return -1;
    }
    
    if (mxd_calculate_block_hash(&genesis_block, genesis_block.block_hash) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to calculate genesis block hash");
        genesis_creation_attempted = 0;
        return -1;
    }
    
    if (mxd_store_block(&genesis_block) != 0) {
        MXD_LOG_ERROR("rsc", "Failed to store genesis block");
        genesis_creation_attempted = 0;
        return -1;
    }
    
    MXD_LOG_INFO("rsc", "Genesis block created successfully with %u validators",
                 genesis_block.rapid_membership_count);
    
    mxd_free_validation_chain(&genesis_block);
    
    return 1;
}

int mxd_rebuild_rapid_table_after_genesis(mxd_rapid_table_t *table, const char *local_node_id) {
    if (!table) {
        return -1;
    }
    
    uint32_t blockchain_height = 0;
    if (mxd_get_blockchain_height(&blockchain_height) != 0 || blockchain_height == 0) {
        return -1;
    }
    
    MXD_LOG_INFO("rsc", "Rebuilding rapid table from genesis block");
    return mxd_rebuild_rapid_table_from_blockchain(table, 0, blockchain_height, local_node_id);
}

int mxd_try_create_genesis_block(mxd_rapid_table_t *table, const uint8_t *node_address,
                                  const uint8_t *private_key, const uint8_t *public_key) {
    return mxd_try_coordinate_genesis_block();
}

#ifndef MXD_BLOCKCHAIN_SYNC_H
#define MXD_BLOCKCHAIN_SYNC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mxd_blockchain.h"
#include "mxd_blockchain_db.h"
#include "mxd_rsc.h"

int mxd_sync_blockchain(void);

int mxd_get_block_by_height(uint32_t height, mxd_block_t *block);

int mxd_sync_validation_chain(const uint8_t block_hash[64], uint32_t height);

int mxd_request_validation_chain_from_peers(const uint8_t block_hash[64]);

int mxd_process_incoming_validation_chain(const uint8_t block_hash[64],
                                         const mxd_validator_signature_t *signatures,
                                         uint32_t signature_count);

int mxd_verify_and_add_validation_signature(mxd_block_t *block,
                                           const uint8_t validator_id[20],
                                           uint8_t algo_id,
                                           const uint8_t *signature,
                                           uint16_t signature_length,
                                           uint64_t timestamp);

int mxd_check_block_relay_status(const uint8_t block_hash[64]);

int mxd_sync_rapid_table(mxd_rapid_table_t *table, const char *local_node_id);

int mxd_handle_validation_chain_conflict(const uint8_t block_hash1[64],
                                        const uint8_t block_hash2[64]);

int mxd_prune_expired_validation_chains(uint32_t current_height);

// Pull-based sync fallback - actively request missing blocks from peers
// Call this periodically to catch blocks that failed to broadcast
int mxd_pull_missing_blocks(void);

// Apply block transactions to UTXO state (deserializes and processes each tx)
// If supply_delta is non-NULL, outputs the net supply change (outputs - inputs)
int mxd_apply_block_transactions(const mxd_block_t *block, int64_t *supply_delta);

// Parallel sync configuration
#define MXD_SYNC_WORKERS_DEFAULT  4   // Default worker threads
#define MXD_SYNC_WORKERS_MAX      8   // Maximum worker threads
#define MXD_SYNC_CHUNK_SIZE       50  // Blocks per sub-range
#define MXD_SYNC_TIMEOUT_MS       15000 // Per-range timeout (ms)
#define MXD_SYNC_MAX_RETRIES      3   // Retries per range before fallback

#ifdef __cplusplus
}
#endif

#endif // MXD_BLOCKCHAIN_SYNC_H

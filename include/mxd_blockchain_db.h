#ifndef MXD_BLOCKCHAIN_DB_H
#define MXD_BLOCKCHAIN_DB_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mxd_blockchain.h"
#include <stdint.h>

// Initialize blockchain database
int mxd_init_blockchain_db(const char *db_path);

// Close blockchain database
int mxd_close_blockchain_db(void);

// Store block in database with validation chain
int mxd_store_block(const mxd_block_t *block);

// Retrieve block by height
int mxd_retrieve_block_by_height(uint32_t height, mxd_block_t *block);

// Retrieve block by hash
int mxd_retrieve_block_by_hash(const uint8_t hash[64], mxd_block_t *block);

// Get current blockchain height
int mxd_get_blockchain_height(uint32_t *height);

// Store signature for block height (for replay protection)
int mxd_store_signature(uint32_t height, const uint8_t validator_id[20], const uint8_t signature[128]);

// Check if signature exists for block height (replay protection)
int mxd_signature_exists(uint32_t height, const uint8_t validator_id[20], const uint8_t signature[128]);

// Prune expired signatures (older than 5 blocks)
int mxd_prune_expired_signatures(uint32_t current_height);

// Get validation chain signatures for a block height
int mxd_get_signatures_by_height(uint32_t height, mxd_validator_signature_t **signatures, size_t *signature_count);

// Get validation chain signatures by validator ID
int mxd_get_signatures_by_validator(const uint8_t validator_id[20], mxd_validator_signature_t **signatures, 
                                   uint32_t **heights, size_t *signature_count);

// Calculate cumulative latency score for a block
double mxd_calculate_block_latency_score(const mxd_block_t *block);

// Flush blockchain database to disk (for checkpointing)
int mxd_flush_blockchain_db(void);

// Compact blockchain database (optimize storage)
int mxd_compact_blockchain_db(void);

#ifdef __cplusplus
}
#endif

#endif // MXD_BLOCKCHAIN_DB_H

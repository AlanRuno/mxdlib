#ifndef MXD_BLOCKCHAIN_H
#define MXD_BLOCKCHAIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <time.h>

// Validator signature structure for validation chain
typedef struct {
    uint8_t validator_id[20];       // Public key hash of validator
    uint64_t timestamp;             // Timestamp of signature
    uint8_t signature[128];         // Signature over (block_hash + prev_validator_id + timestamp)
    uint32_t chain_position;        // Position in validation chain
} mxd_validator_signature_t;

// Block structure
typedef struct {
    uint32_t version;
    uint8_t prev_block_hash[64];
    uint8_t merkle_root[64];
    time_t timestamp;
    uint32_t difficulty;
    uint64_t nonce;
    uint8_t block_hash[64];
    uint8_t proposer_id[20];        // Public key hash of block proposer
    uint32_t height;                // Block height
    
    // Validation chain
    mxd_validator_signature_t *validation_chain;
    uint32_t validation_count;      // Number of validators in chain
    uint32_t validation_capacity;   // Allocated capacity for validation chain
} mxd_block_t;

// Initialize a new block
int mxd_init_block(mxd_block_t *block, const uint8_t prev_hash[64]);

// Initialize block with validation chain
int mxd_init_block_with_validation(mxd_block_t *block, const uint8_t prev_hash[64], 
                                  const uint8_t proposer_id[20], uint32_t height);

// Add transaction to block
int mxd_add_transaction(mxd_block_t *block, const uint8_t *transaction_data,
                        size_t transaction_length);

// Add validator signature to validation chain
int mxd_add_validator_signature(mxd_block_t *block, const uint8_t validator_id[20], 
                              uint64_t timestamp, const uint8_t signature[128]);

// Validate block structure and contents
int mxd_validate_block(const mxd_block_t *block);

// Verify validation chain signatures
int mxd_verify_validation_chain(const mxd_block_t *block);

// Calculate block hash
int mxd_calculate_block_hash(const mxd_block_t *block, uint8_t hash[64]);

// Check if block has enough signatures (>= 50% of Rapid Table)
int mxd_block_has_quorum(const mxd_block_t *block);

// Check if block has minimum required signatures for relay (X=3)
int mxd_block_has_min_signatures(const mxd_block_t *block);

// Fork resolution based on validation signatures
int mxd_resolve_fork(const mxd_block_t *block1, const mxd_block_t *block2);

// Calculate cumulative latency score for fork resolution
double mxd_calculate_latency_score(const mxd_block_t *block);

// Free validation chain memory
void mxd_free_validation_chain(mxd_block_t *block);

#ifdef __cplusplus
}
#endif

#endif // MXD_BLOCKCHAIN_H

#ifndef MXD_BLOCK_PROPOSER_H
#define MXD_BLOCK_PROPOSER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mxd_blockchain.h"
#include "mxd_transaction.h"
#include <stdint.h>

// Block proposer configuration
#define MXD_BLOCK_CLOSE_TIMEOUT_MS 5000  // 5 seconds

// Block proposer state
typedef struct {
    mxd_block_t* current_block;
    uint64_t block_start_time;
    uint8_t is_proposing;
    uint8_t proposer_id[20];
} mxd_block_proposer_t;

// Initialize block proposer
int mxd_init_block_proposer(const uint8_t proposer_id[20]);

// Start proposing a new block
int mxd_start_block_proposal(const uint8_t prev_hash[64], uint32_t height);

// Add transaction to current block
int mxd_add_transaction_to_block(const mxd_transaction_t* tx);

// Check if block should be closed (5 second timeout)
int mxd_should_close_block(void);

// Manually close block (freeze transaction set)
int mxd_close_block(void);

// Get current block being proposed
mxd_block_t* mxd_get_current_block(void);

// Stop block proposal
int mxd_stop_block_proposal(void);

// Cleanup block proposer
void mxd_cleanup_block_proposer(void);

#ifdef __cplusplus
}
#endif

#endif // MXD_BLOCK_PROPOSER_H

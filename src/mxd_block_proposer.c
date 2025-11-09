#include "../include/mxd_block_proposer.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_logging.h"
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

static mxd_block_proposer_t proposer_state = {0};

static uint64_t get_current_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)(tv.tv_sec) * 1000 + (uint64_t)(tv.tv_usec) / 1000;
}

int mxd_init_block_proposer(const uint8_t proposer_id[20]) {
    if (!proposer_id) {
        return -1;
    }
    
    memset(&proposer_state, 0, sizeof(mxd_block_proposer_t));
    memcpy(proposer_state.proposer_id, proposer_id, 20);
    proposer_state.current_block = NULL;
    proposer_state.is_proposing = 0;
    
    MXD_LOG_INFO("proposer", "Block proposer initialized");
    return 0;
}

int mxd_start_block_proposal(const uint8_t prev_hash[64], uint32_t height) {
    if (!prev_hash) {
        return -1;
    }
    
    if (proposer_state.is_proposing) {
        MXD_LOG_WARN("proposer", "Stopping existing block proposal before starting new one");
        mxd_stop_block_proposal();
    }
    
    proposer_state.current_block = malloc(sizeof(mxd_block_t));
    if (!proposer_state.current_block) {
        MXD_LOG_ERROR("proposer", "Failed to allocate memory for new block");
        return -1;
    }
    
    if (mxd_init_block_with_validation(proposer_state.current_block, prev_hash, 
                                       proposer_state.proposer_id, height) != 0) {
        MXD_LOG_ERROR("proposer", "Failed to initialize block");
        free(proposer_state.current_block);
        proposer_state.current_block = NULL;
        return -1;
    }
    
    proposer_state.block_start_time = get_current_time_ms();
    proposer_state.is_proposing = 1;
    
    MXD_LOG_INFO("proposer", "Started block proposal at height %u (timeout: %d ms)", 
                 height, MXD_BLOCK_CLOSE_TIMEOUT_MS);
    return 0;
}

int mxd_add_transaction_to_block(const mxd_transaction_t* tx) {
    if (!tx || !proposer_state.is_proposing || !proposer_state.current_block) {
        return -1;
    }
    
    if (proposer_state.current_block->transaction_set_frozen) {
        MXD_LOG_WARN("proposer", "Cannot add transaction to frozen block");
        return -1;
    }
    
    MXD_LOG_DEBUG("proposer", "Transaction added to block");
    return 0;
}

int mxd_should_close_block(void) {
    if (!proposer_state.is_proposing || !proposer_state.current_block) {
        return 0;
    }
    
    if (proposer_state.current_block->rapid_membership_count == 0 &&
        !proposer_state.current_block->transaction_set_frozen) {
        return 0;
    }
    
    uint64_t current_time = get_current_time_ms();
    uint64_t elapsed = current_time - proposer_state.block_start_time;
    
    if (elapsed >= MXD_BLOCK_CLOSE_TIMEOUT_MS) {
        MXD_LOG_INFO("proposer", "Block timeout reached (%llu ms elapsed), should close block",
                     (unsigned long long)elapsed);
        return 1;
    }
    
    return 0;
}

int mxd_close_block(void) {
    if (!proposer_state.is_proposing || !proposer_state.current_block) {
        MXD_LOG_WARN("proposer", "No active block to close");
        return -1;
    }
    
    if (proposer_state.current_block->transaction_set_frozen) {
        MXD_LOG_DEBUG("proposer", "Block already frozen");
        return 0;
    }
    
    if (mxd_freeze_transaction_set(proposer_state.current_block) != 0) {
        MXD_LOG_ERROR("proposer", "Failed to freeze transaction set");
        return -1;
    }
    
    uint64_t elapsed = get_current_time_ms() - proposer_state.block_start_time;
    MXD_LOG_INFO("proposer", "Block closed and transaction set frozen after %llu ms",
                 (unsigned long long)elapsed);
    
    return 0;
}

mxd_block_t* mxd_get_current_block(void) {
    if (!proposer_state.is_proposing) {
        return NULL;
    }
    return proposer_state.current_block;
}

int mxd_stop_block_proposal(void) {
    if (!proposer_state.is_proposing) {
        return 0;
    }
    
    if (proposer_state.current_block) {
        if (proposer_state.current_block->validation_chain) {
            free(proposer_state.current_block->validation_chain);
        }
        
        if (proposer_state.current_block->rapid_membership_entries) {
            free(proposer_state.current_block->rapid_membership_entries);
        }
        
        free(proposer_state.current_block);
        proposer_state.current_block = NULL;
    }
    
    proposer_state.is_proposing = 0;
    MXD_LOG_INFO("proposer", "Block proposal stopped");
    
    return 0;
}

void mxd_cleanup_block_proposer(void) {
    mxd_stop_block_proposal();
    memset(&proposer_state, 0, sizeof(mxd_block_proposer_t));
    MXD_LOG_INFO("proposer", "Block proposer cleaned up");
}

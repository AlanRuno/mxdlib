#include "../include/mxd_block_proposer.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_serialize.h"
#include "../include/mxd_transaction.h"
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

// Helper function to serialize a transaction for block storage
// Returns allocated buffer that must be freed by caller, or NULL on error
static uint8_t* serialize_transaction_for_block(const mxd_transaction_t* tx, size_t* out_len) {
    if (!tx || !out_len) return NULL;
    
    // Calculate total size needed
    size_t size = 0;
    size += 4;  // version (u32)
    size += 4;  // input_count (u32)
    size += 4;  // output_count (u32)
    size += 8;  // voluntary_tip (u64)
    size += 8;  // timestamp (u64)
    size += 1;  // is_coinbase (u8)
    size += 64; // tx_hash
    
    // Calculate input sizes
    for (uint32_t i = 0; i < tx->input_count; i++) {
        size += 64;  // prev_tx_hash
        size += 4;   // output_index (u32)
        size += 1;   // algo_id (u8)
        size += 2;   // public_key_length (u16)
        size += tx->inputs[i].public_key_length;
        size += 2;   // signature_length (u16)
        size += tx->inputs[i].signature_length;
    }
    
    // Calculate output sizes
    for (uint32_t i = 0; i < tx->output_count; i++) {
        size += 20;  // recipient_addr
        size += 8;   // amount (u64)
    }
    
    uint8_t* buffer = malloc(size);
    if (!buffer) return NULL;
    
    uint8_t* ptr = buffer;
    
    // Serialize header fields
    mxd_write_u32_be(&ptr, tx->version);
    mxd_write_u32_be(&ptr, tx->input_count);
    mxd_write_u32_be(&ptr, tx->output_count);
    mxd_write_u64_be(&ptr, tx->voluntary_tip);
    mxd_write_u64_be(&ptr, tx->timestamp);
    mxd_write_u8(&ptr, tx->is_coinbase);
    mxd_write_bytes(&ptr, tx->tx_hash, 64);
    
    // Serialize inputs (including signatures for block storage)
    for (uint32_t i = 0; i < tx->input_count; i++) {
        mxd_write_bytes(&ptr, tx->inputs[i].prev_tx_hash, 64);
        mxd_write_u32_be(&ptr, tx->inputs[i].output_index);
        mxd_write_u8(&ptr, tx->inputs[i].algo_id);
        mxd_write_u16_be(&ptr, tx->inputs[i].public_key_length);
        mxd_write_bytes(&ptr, tx->inputs[i].public_key, tx->inputs[i].public_key_length);
        mxd_write_u16_be(&ptr, tx->inputs[i].signature_length);
        if (tx->inputs[i].signature_length > 0 && tx->inputs[i].signature) {
            mxd_write_bytes(&ptr, tx->inputs[i].signature, tx->inputs[i].signature_length);
        }
    }
    
    // Serialize outputs
    for (uint32_t i = 0; i < tx->output_count; i++) {
        mxd_write_bytes(&ptr, tx->outputs[i].recipient_addr, 20);
        mxd_write_u64_be(&ptr, tx->outputs[i].amount);
    }
    
    *out_len = size;
    return buffer;
}

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
    
    // Serialize the transaction for block storage
    size_t tx_data_len = 0;
    uint8_t* tx_data = serialize_transaction_for_block(tx, &tx_data_len);
    if (!tx_data) {
        MXD_LOG_ERROR("proposer", "Failed to serialize transaction for block");
        return -1;
    }
    
    // Add the serialized transaction to the block
    int result = mxd_add_transaction(proposer_state.current_block, tx_data, tx_data_len);
    free(tx_data);
    
    if (result != 0) {
        MXD_LOG_ERROR("proposer", "Failed to add transaction to block");
        return -1;
    }
    
    MXD_LOG_DEBUG("proposer", "Transaction added to block");
    return 0;
}

int mxd_should_close_block(void) {
    if (!proposer_state.is_proposing || !proposer_state.current_block) {
        return 0;
    }

    // Block should close if:
    // 1. Already frozen (ready for validation)
    // 2. Has transactions and timeout reached
    // 3. Has membership entries and timeout reached
    if (proposer_state.current_block->transaction_set_frozen) {
        return 0;  // Already closed
    }

    uint64_t current_time = get_current_time_ms();
    uint64_t elapsed = current_time - proposer_state.block_start_time;

    // Log block status periodically (every 5 seconds)
    static uint64_t last_status_log = 0;
    if (current_time - last_status_log >= 5000) {
        MXD_LOG_INFO("proposer", "Block status: height=%u, tx_count=%u, membership_count=%u, elapsed=%llu ms",
                     proposer_state.current_block->height,
                     proposer_state.current_block->transaction_count,
                     proposer_state.current_block->rapid_membership_count,
                     (unsigned long long)elapsed);
        last_status_log = current_time;
    }

    // For empty blocks (no transactions), use a longer timeout to allow chain progress
    // This ensures the blockchain can advance even without transaction activity
    int is_empty = (proposer_state.current_block->transaction_count == 0 &&
                    proposer_state.current_block->rapid_membership_count == 0);

    uint64_t close_timeout = is_empty ? (MXD_BLOCK_CLOSE_TIMEOUT_MS * 2) : MXD_BLOCK_CLOSE_TIMEOUT_MS;

    if (elapsed >= close_timeout) {
        MXD_LOG_INFO("proposer", "Block timeout reached (%llu ms elapsed, timeout=%llu ms, %u txs, empty=%d), closing block",
                     (unsigned long long)elapsed, (unsigned long long)close_timeout,
                     proposer_state.current_block->transaction_count, is_empty);
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

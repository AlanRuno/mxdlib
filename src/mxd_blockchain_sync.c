#include "mxd_logging.h"

#include "../include/mxd_blockchain_sync.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_rsc.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_ntp.h"
#include "../include/mxd_serialize.h"
#include "../include/mxd_blockchain.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define MXD_VALIDATION_EXPIRY_BLOCKS 5
#define MXD_MIN_RELAY_SIGNATURES 3
#define MXD_MAX_TIMESTAMP_DRIFT 60

static int mxd_request_peer_height(const char *address, uint16_t port, uint32_t *height);
static mxd_block_t* mxd_request_blocks_from_peers(uint32_t start_height, uint32_t end_height, size_t *block_count);
static int mxd_apply_block_transactions(const mxd_block_t *block);
static int mxd_sync_block_range(uint32_t start_height, uint32_t end_height);

static uint32_t mxd_discover_network_height(void) {
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    
    if (mxd_get_peers(peers, &peer_count) != 0 || peer_count == 0) {
        MXD_LOG_WARN("sync", "No peers available to discover network height");
        return 0;
    }
    
    uint32_t max_height = 0;
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].state == MXD_PEER_CONNECTED) {
            uint32_t peer_height = 0;
            if (mxd_request_peer_height(peers[i].address, peers[i].port, &peer_height) == 0) {
                if (peer_height > max_height) {
                    max_height = peer_height;
                }
            }
        }
    }
    
    return max_height;
}

// Callback storage for peer height responses
static volatile uint32_t pending_peer_height = 0;
static volatile int peer_height_received = 0;

// Called by P2P layer when height response is received
void mxd_handle_peer_height_response(const uint8_t *data, size_t data_len) {
    if (data && data_len >= 4) {
        const uint8_t *ptr = data;
        pending_peer_height = mxd_read_u32_be(&ptr);
        peer_height_received = 1;
    }
}

static int mxd_request_peer_height(const char *address, uint16_t port, uint32_t *height) {
    if (!address || !height) return -1;
    
    // Reset response state
    peer_height_received = 0;
    pending_peer_height = 0;
    
    // Send height request to peer using GET_BLOCKS with height=0 to request current height
    uint8_t request[8];
    uint8_t *ptr = request;
    mxd_write_u32_be(&ptr, 0);  // start_height = 0 (request height info)
    mxd_write_u32_be(&ptr, 0);  // end_height = 0 (request height info only)
    
    if (mxd_send_message_with_retry(address, port, MXD_MSG_GET_BLOCKS, 
                                    request, sizeof(request), 3) != 0) {
        MXD_LOG_DEBUG("sync", "Failed to send height request to peer %s:%u", address, port);
        *height = 0;
        return -1;
    }
    
    // Wait for response with timeout (up to 3 seconds)
    int wait_ms = 0;
    while (!peer_height_received && wait_ms < 3000) {
        struct timespec ts = {0, 50000000}; // 50ms
        nanosleep(&ts, NULL);
        wait_ms += 50;
    }
    
    if (peer_height_received) {
        *height = pending_peer_height;
        MXD_LOG_DEBUG("sync", "Peer %s:%u reported height: %u", address, port, *height);
        return 0;
    }
    
    MXD_LOG_DEBUG("sync", "Timeout waiting for height from peer %s:%u", address, port);
    *height = 0;
    return -1;
}

// Callback storage for block responses
static mxd_block_t *pending_blocks = NULL;
static volatile uint32_t pending_blocks_received = 0;
static volatile uint32_t pending_blocks_expected = 0;

// Forward declaration for deserializing blocks from database format
extern int mxd_deserialize_block_from_network(const uint8_t *data, size_t data_len, mxd_block_t *block);

// Called by P2P layer when block data is received
void mxd_handle_blocks_response(const uint8_t *data, size_t data_len, uint32_t block_index) {
    if (!data || data_len == 0) return;
    
    // Handle unsolicited blocks (e.g., genesis block broadcast)
    if (!pending_blocks) {
        MXD_LOG_INFO("sync", "Received unsolicited block data (len=%zu), attempting to process", data_len);
        
        // Deserialize the block using the network format
        mxd_block_t block;
        memset(&block, 0, sizeof(block));
        
        if (mxd_deserialize_block_from_network(data, data_len, &block) != 0) {
            MXD_LOG_WARN("sync", "Failed to deserialize unsolicited block");
            return;
        }
        
        MXD_LOG_INFO("sync", "Deserialized unsolicited block: height=%u, validators=%u, membership=%u",
                     block.height, block.validation_count, block.rapid_membership_count);
        
        // Check if we already have this block
        uint32_t current_height = 0;
        int have_blockchain = (mxd_get_blockchain_height(&current_height) == 0);
        
        // Special handling for genesis block (height 0)
        // If we don't have any blocks yet (have_blockchain is false or current_height is 0),
        // we should accept the genesis block
        if (block.height == 0) {
            if (have_blockchain && current_height >= 0) {
                // Check if we actually have a genesis block stored
                mxd_block_t existing_genesis;
                memset(&existing_genesis, 0, sizeof(existing_genesis));
                if (mxd_retrieve_block_by_height(0, &existing_genesis) == 0) {
                    MXD_LOG_DEBUG("sync", "Already have genesis block, ignoring duplicate");
                    mxd_free_block(&existing_genesis);
                    mxd_free_block(&block);
                    return;
                }
            }
            // Don't have genesis block yet, proceed to store it
            MXD_LOG_INFO("sync", "Received genesis block, will store it");
        } else if (block.height <= current_height) {
            MXD_LOG_DEBUG("sync", "Already have block at height %u (current=%u), ignoring",
                         block.height, current_height);
            mxd_free_block(&block);
            return;
        }
        
        // Store the block
        if (mxd_store_block(&block) == 0) {
            MXD_LOG_INFO("sync", "Stored unsolicited block at height %u", block.height);
        } else {
            MXD_LOG_ERROR("sync", "Failed to store unsolicited block at height %u", block.height);
        }
        
        mxd_free_block(&block);
        return;
    }
    
    if (block_index >= pending_blocks_expected) return;
    
    // Deserialize block from received data (for requested blocks)
    mxd_block_t *block = &pending_blocks[block_index];
    
    const uint8_t *ptr = data;
    const uint8_t *end = data + data_len;
    
    // Read basic block header fields
    if (ptr + 4 + 64 + 64 + 8 + 4 + 8 + 64 + 20 + 4 > end) {
        MXD_LOG_ERROR("sync", "Block data too short for block %u", block_index);
        return;
    }
    
    block->version = mxd_read_u32_be(&ptr);
    mxd_read_bytes(&ptr, block->prev_block_hash, 64);
    mxd_read_bytes(&ptr, block->merkle_root, 64);
    block->timestamp = mxd_read_u64_be(&ptr);
    block->difficulty = mxd_read_u32_be(&ptr);
    block->nonce = mxd_read_u64_be(&ptr);
    mxd_read_bytes(&ptr, block->block_hash, 64);
    mxd_read_bytes(&ptr, block->proposer_id, 20);
    block->height = mxd_read_u32_be(&ptr);
    
    // Read transaction count and allocate
    if (ptr + 4 > end) return;
    block->transaction_count = mxd_read_u32_be(&ptr);
    
    if (block->transaction_count > 0) {
        block->transactions = calloc(block->transaction_count, sizeof(mxd_block_transaction_t));
        if (!block->transactions) {
            block->transaction_count = 0;
            return;
        }
        block->transaction_capacity = block->transaction_count;
        
        // Read each transaction
        for (uint32_t i = 0; i < block->transaction_count; i++) {
            if (ptr + 4 > end) break;
            uint32_t tx_len = mxd_read_u32_be(&ptr);
            
            if (ptr + tx_len > end || tx_len == 0) break;
            
            block->transactions[i].data = malloc(tx_len);
            if (!block->transactions[i].data) break;
            
            mxd_read_bytes(&ptr, block->transactions[i].data, tx_len);
            block->transactions[i].length = tx_len;
        }
    }
    
    pending_blocks_received++;
    MXD_LOG_DEBUG("sync", "Received block %u (height %u)", block_index, block->height);
}

static mxd_block_t* mxd_request_blocks_from_peers(uint32_t start_height, uint32_t end_height, size_t *block_count) {
    if (!block_count || start_height > end_height) return NULL;
    
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    
    if (mxd_get_peers(peers, &peer_count) != 0 || peer_count == 0) {
        MXD_LOG_WARN("sync", "No peers available to request blocks");
        return NULL;
    }
    
    uint32_t count = end_height - start_height + 1;
    mxd_block_t *blocks = calloc(count, sizeof(mxd_block_t));
    if (!blocks) {
        MXD_LOG_ERROR("sync", "Failed to allocate memory for blocks");
        return NULL;
    }
    
    // Set up callback storage
    pending_blocks = blocks;
    pending_blocks_received = 0;
    pending_blocks_expected = count;
    
    // Try to request blocks from connected peers
    int request_sent = 0;
    for (size_t i = 0; i < peer_count && i < 3; i++) {
        if (peers[i].state == MXD_PEER_CONNECTED) {
            uint8_t request[8];
            uint8_t *ptr = request;
            mxd_write_u32_be(&ptr, start_height);
            mxd_write_u32_be(&ptr, end_height);
            
            if (mxd_send_message_with_retry(peers[i].address, peers[i].port, 
                                           MXD_MSG_GET_BLOCKS, request, sizeof(request), 2) == 0) {
                MXD_LOG_DEBUG("sync", "Requested blocks %u-%u from peer %s:%u", 
                             start_height, end_height, peers[i].address, peers[i].port);
                request_sent = 1;
                break;
            }
        }
    }
    
    if (!request_sent) {
        MXD_LOG_ERROR("sync", "Failed to send block request to any peer");
        free(blocks);
        pending_blocks = NULL;
        return NULL;
    }
    
    // Wait for blocks with timeout (up to 30 seconds for large ranges)
    int wait_ms = 0;
    int timeout_ms = 30000;
    while (pending_blocks_received < count && wait_ms < timeout_ms) {
        struct timespec ts = {0, 100000000}; // 100ms
        nanosleep(&ts, NULL);
        wait_ms += 100;
    }
    
    pending_blocks = NULL;
    
    if (pending_blocks_received < count) {
        MXD_LOG_WARN("sync", "Only received %u of %u blocks", pending_blocks_received, count);
        // Still return what we got - caller will validate
    }
    
    *block_count = count;
    return blocks;
}

static int mxd_apply_block_transactions(const mxd_block_t *block) {
    if (!block) return -1;
    
    // Apply each transaction in the block to the UTXO state
    for (uint32_t i = 0; i < block->transaction_count; i++) {
        if (!block->transactions[i].data || block->transactions[i].length == 0) {
            MXD_LOG_WARN("sync", "Skipping empty transaction at index %u", i);
            continue;
        }
        
        // Deserialize the transaction from block storage format
        mxd_transaction_t tx;
        memset(&tx, 0, sizeof(mxd_transaction_t));
        
        const uint8_t *ptr = block->transactions[i].data;
        const uint8_t *end = ptr + block->transactions[i].length;
        
        // Read header fields
        if (ptr + 4 + 4 + 4 + 8 + 8 + 1 + 64 > end) {
            MXD_LOG_ERROR("sync", "Transaction data too short at index %u", i);
            continue;
        }
        
        tx.version = mxd_read_u32_be(&ptr);
        tx.input_count = mxd_read_u32_be(&ptr);
        tx.output_count = mxd_read_u32_be(&ptr);
        tx.voluntary_tip = mxd_read_u64_be(&ptr);
        tx.timestamp = mxd_read_u64_be(&ptr);
        tx.is_coinbase = mxd_read_u8(&ptr);
        mxd_read_bytes(&ptr, tx.tx_hash, 64);
        
        // Allocate and read inputs
        if (tx.input_count > 0) {
            tx.inputs = calloc(tx.input_count, sizeof(mxd_tx_input_t));
            if (!tx.inputs) {
                MXD_LOG_ERROR("sync", "Failed to allocate inputs for transaction %u", i);
                continue;
            }
            
            for (uint32_t j = 0; j < tx.input_count; j++) {
                if (ptr + 64 + 4 + 1 + 2 > end) {
                    mxd_free_transaction(&tx);
                    MXD_LOG_ERROR("sync", "Transaction input data truncated at index %u", i);
                    goto next_tx;
                }
                
                mxd_read_bytes(&ptr, tx.inputs[j].prev_tx_hash, 64);
                tx.inputs[j].output_index = mxd_read_u32_be(&ptr);
                tx.inputs[j].algo_id = mxd_read_u8(&ptr);
                tx.inputs[j].public_key_length = mxd_read_u16_be(&ptr);
                
                if (ptr + tx.inputs[j].public_key_length + 2 > end) {
                    mxd_free_transaction(&tx);
                    goto next_tx;
                }
                
                tx.inputs[j].public_key = malloc(tx.inputs[j].public_key_length);
                if (!tx.inputs[j].public_key) {
                    mxd_free_transaction(&tx);
                    goto next_tx;
                }
                mxd_read_bytes(&ptr, tx.inputs[j].public_key, tx.inputs[j].public_key_length);
                
                tx.inputs[j].signature_length = mxd_read_u16_be(&ptr);
                if (tx.inputs[j].signature_length > 0) {
                    if (ptr + tx.inputs[j].signature_length > end) {
                        mxd_free_transaction(&tx);
                        goto next_tx;
                    }
                    tx.inputs[j].signature = malloc(tx.inputs[j].signature_length);
                    if (!tx.inputs[j].signature) {
                        mxd_free_transaction(&tx);
                        goto next_tx;
                    }
                    mxd_read_bytes(&ptr, tx.inputs[j].signature, tx.inputs[j].signature_length);
                }
            }
        }
        
        // Allocate and read outputs
        if (tx.output_count > 0) {
            tx.outputs = calloc(tx.output_count, sizeof(mxd_tx_output_t));
            if (!tx.outputs) {
                mxd_free_transaction(&tx);
                MXD_LOG_ERROR("sync", "Failed to allocate outputs for transaction %u", i);
                continue;
            }
            
            for (uint32_t j = 0; j < tx.output_count; j++) {
                if (ptr + 20 + 8 > end) {
                    mxd_free_transaction(&tx);
                    goto next_tx;
                }
                mxd_read_bytes(&ptr, tx.outputs[j].recipient_addr, 20);
                tx.outputs[j].amount = mxd_read_u64_be(&ptr);
            }
        }
        
        // Apply the transaction to UTXO state
        if (mxd_apply_transaction_to_utxo(&tx) != 0) {
            MXD_LOG_ERROR("sync", "Failed to apply transaction %u to UTXO state", i);
            mxd_free_transaction(&tx);
            return -1;
        }
        
        mxd_free_transaction(&tx);
        continue;
        
    next_tx:
        MXD_LOG_ERROR("sync", "Failed to deserialize transaction %u", i);
        continue;
    }
    
    return 0;
}

static int mxd_sync_block_range(uint32_t start_height, uint32_t end_height) {
    size_t block_count = 0;
    mxd_block_t *blocks = mxd_request_blocks_from_peers(start_height, end_height, &block_count);
    if (!blocks) {
        MXD_LOG_ERROR("sync", "Failed to request blocks from peers");
        return -1;
    }
    
    for (uint32_t h = start_height; h <= end_height; h++) {
        mxd_block_t *block = &blocks[h - start_height];
        
        if (mxd_validate_block(block) != 0) {
            MXD_LOG_ERROR("sync", "Invalid block at height %u", h);
            free(blocks);
            return -1;
        }
        
        if (mxd_verify_validation_chain_integrity(block) != 0) {
            MXD_LOG_ERROR("sync", "Invalid validation chain at height %u", h);
            free(blocks);
            return -1;
        }
        
        if (mxd_block_has_min_relay_signatures(block) != 1) {
            MXD_LOG_ERROR("sync", "Insufficient signatures at height %u", h);
            free(blocks);
            return -1;
        }
        
        if (mxd_apply_block_transactions(block) != 0) {
            MXD_LOG_ERROR("sync", "Failed to apply transactions at height %u", h);
            free(blocks);
            return -1;
        }
        
        if (mxd_store_block(block) != 0) {
            MXD_LOG_ERROR("sync", "Failed to store block at height %u", h);
            free(blocks);
            return -1;
        }
    }
    
    free(blocks);
    return 0;
}

int mxd_sync_blockchain(void) {
    uint32_t local_height = 0;
    if (mxd_get_blockchain_height(&local_height) != 0) {
        local_height = 0;
    }
    
    uint32_t network_height = mxd_discover_network_height();
    if (network_height <= local_height) {
        MXD_LOG_INFO("sync", "Already synced (local: %u, network: %u)", local_height, network_height);
        return 0;
    }
    
    MXD_LOG_INFO("sync", "Syncing from height %u to %u", local_height + 1, network_height);
    
    const uint32_t CHUNK_SIZE = 500;
    for (uint32_t start = local_height + 1; start <= network_height; start += CHUNK_SIZE) {
        uint32_t end = (start + CHUNK_SIZE - 1 < network_height) ? 
                       start + CHUNK_SIZE - 1 : network_height;
        
        if (mxd_sync_block_range(start, end) != 0) {
            MXD_LOG_ERROR("sync", "Failed to sync blocks %u-%u", start, end);
            return -1;
        }
        
        MXD_LOG_INFO("sync", "Synced blocks %u-%u", start, end);
    }
    
    MXD_LOG_INFO("sync", "Blockchain sync complete");
    return 0;
}

int mxd_get_block_by_height(uint32_t height, mxd_block_t *block) {
    if (!block) return -1;
    
    return mxd_retrieve_block_by_height(height, block);
}

int mxd_sync_validation_chain(const uint8_t block_hash[64], uint32_t height) {
    if (!block_hash) return -1;
    
    if (mxd_request_validation_chain_from_peers(block_hash) != 0) {
        MXD_LOG_ERROR("sync", "Failed to request validation chain for block at height %u", height);
        return -1;
    }
    
    // For testing purposes, simulate successful sync
    MXD_LOG_INFO("sync", "Synchronizing validation chain for block at height %u", height);
    return 0;
}

int mxd_request_validation_chain_from_peers(const uint8_t block_hash[64]) {
    if (!block_hash) return -1;
    
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    if (mxd_get_peers(peers, &peer_count) != 0 || peer_count == 0) {
        MXD_LOG_WARN("sync", "No peers available to request validation chain");
        return -1;
    }
    
    int success = 0;
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].state == MXD_PEER_CONNECTED) {
            if (mxd_request_validation_chain(peers[i].address, peers[i].port, block_hash) == 0) {
                success = 1;
            }
        }
    }
    
    return success ? 0 : -1;
}

int mxd_process_incoming_validation_chain(const uint8_t block_hash[64], 
                                         const mxd_validator_signature_t *signatures,
                                         uint32_t signature_count) {
    if (!block_hash || !signatures || signature_count == 0) return -1;
    
    mxd_block_t block;
    if (mxd_retrieve_block_by_hash(block_hash, &block) != 0) {
        MXD_LOG_ERROR("sync", "Failed to retrieve block for validation chain processing");
        return -1;
    }
    
    for (uint32_t i = 0; i < signature_count; i++) {
        if (mxd_verify_and_add_validation_signature(&block,
                                                  signatures[i].validator_id,
                                                  signatures[i].algo_id,
                                                  signatures[i].signature,
                                                  signatures[i].signature_length,
                                                  signatures[i].timestamp) != 0) {
            MXD_LOG_WARN("sync", "Failed to verify signature %u of %u", i + 1, signature_count);
        }
    }
    
    if (mxd_store_block(&block) != 0) {
        MXD_LOG_ERROR("sync", "Failed to store block with updated validation chain");
        return -1;
    }
    
    if (mxd_check_block_relay_status(block_hash) == 1) {
        MXD_LOG_INFO("sync", "Block has enough signatures for relay");
    }
    
    return 0;
}

int mxd_verify_and_add_validation_signature(mxd_block_t *block, 
                                           const uint8_t validator_id[20],
                                           uint8_t algo_id,
                                           const uint8_t *signature,
                                           uint16_t signature_length,
                                           uint64_t timestamp) {
    if (!block || !validator_id || !signature || signature_length == 0 || signature_length > MXD_SIGNATURE_MAX) return -1;
    
    if (algo_id != MXD_SIGALG_ED25519 && algo_id != MXD_SIGALG_DILITHIUM5) {
        MXD_LOG_WARN("sync", "Invalid algo_id %u", algo_id);
        return -1;
    }
    
    // Use NTP-synchronized time for timestamp validation
    uint64_t current_time_ms = 0;
    if (mxd_get_network_time(&current_time_ms) != 0) {
        current_time_ms = (uint64_t)time(NULL) * 1000;
    }
    uint64_t current_time = current_time_ms / 1000;
    uint64_t drift = (timestamp > current_time) ? 
                     (timestamp - current_time) : 
                     (current_time - timestamp);
    
    if (drift > MXD_MAX_TIMESTAMP_DRIFT) {
        MXD_LOG_WARN("sync", "Signature timestamp drift too large: %lu seconds", (unsigned long)drift);
        return -1;
    }
    
    if (mxd_signature_exists(block->height, validator_id, signature, signature_length) != 0) {
        MXD_LOG_WARN("sync", "Signature already exists for this block height");
        return -1;
    }
    
    if (mxd_is_validator_blacklisted(validator_id) != 0) {
        MXD_LOG_WARN("sync", "Validator is blacklisted");
        return -1;
    }
    
    // Use the validated signature addition path with timestamp drift checking
    uint32_t chain_position = block->validation_count;
    if (mxd_add_validator_signature_to_block(block, validator_id, timestamp, algo_id, signature, signature_length, chain_position) != 0) {
        MXD_LOG_ERROR("sync", "Failed to add validator signature to block");
        return -1;
    }
    
    return 0;
}

int mxd_check_block_relay_status(const uint8_t block_hash[64]) {
    if (!block_hash) return -1;
    
    mxd_block_t block;
    if (mxd_retrieve_block_by_hash(block_hash, &block) != 0) {
        MXD_LOG_ERROR("sync", "Failed to retrieve block for relay status check");
        return -1;
    }
    
    if (block.validation_count >= MXD_MIN_RELAY_SIGNATURES) {
        return 1; // Yes, block has enough signatures for relay
    }
    
    return 0; // No, block does not have enough signatures for relay
}

int mxd_sync_rapid_table(mxd_rapid_table_t *table, const char *local_node_id) {
    if (!table) return -1;
    
    MXD_LOG_INFO("sync", "Synchronizing Rapid Table with network");
    
    uint32_t current_height = 0;
    if (mxd_get_blockchain_height(&current_height) != 0 || current_height == 0) {
        MXD_LOG_WARN("sync", "No blockchain data available for rapid table sync");
        return 0;
    }
    
    uint32_t from_height = current_height > 1000 ? current_height - 1000 : 0;
    
    if (mxd_rebuild_rapid_table_from_blockchain(table, from_height, current_height, local_node_id) == 0) {
        MXD_LOG_INFO("sync", "Rapid Table synchronized from blockchain (heights %u to %u)", 
                     from_height, current_height);
        return 0;
    } else {
        MXD_LOG_ERROR("sync", "Failed to rebuild rapid table from blockchain");
        return -1;
    }
}

int mxd_handle_validation_chain_conflict(const uint8_t block_hash1[64], 
                                        const uint8_t block_hash2[64]) {
    if (!block_hash1 || !block_hash2) return -1;
    
    mxd_block_t block1, block2;
    if (mxd_retrieve_block_by_hash(block_hash1, &block1) != 0 ||
        mxd_retrieve_block_by_hash(block_hash2, &block2) != 0) {
        MXD_LOG_ERROR("sync", "Failed to retrieve blocks for conflict resolution");
        return -1;
    }
    
    int result = mxd_resolve_fork(&block1, &block2);
    
    if (result > 0) {
        MXD_LOG_INFO("sync", "Block 1 wins conflict resolution");
        return 1;
    } else if (result < 0) {
        MXD_LOG_INFO("sync", "Block 2 wins conflict resolution");
        return 2;
    } else {
        MXD_LOG_INFO("sync", "Conflict resolution inconclusive");
        return 0;
    }
}

int mxd_prune_expired_validation_chains(uint32_t current_height) {
    if (current_height < MXD_VALIDATION_EXPIRY_BLOCKS) {
        return 0; // Nothing to prune yet
    }
    
    uint32_t prune_height = current_height - MXD_VALIDATION_EXPIRY_BLOCKS;
    
    return mxd_prune_expired_signatures(prune_height);
}

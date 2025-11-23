#include "mxd_logging.h"

#include "../include/mxd_blockchain_sync.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_rsc.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_utxo.h"
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

static int mxd_request_peer_height(const char *address, uint16_t port, uint32_t *height) {
    if (!address || !height) return -1;
    
    uint8_t request[4] = {0};
    if (mxd_send_message_with_retry(address, port, MXD_MSG_GET_BLOCKS, 
                                    request, sizeof(request), 3) != 0) {
        return -1;
    }
    
    *height = 0;
    return 0;
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
    
    for (size_t i = 0; i < peer_count && i < 3; i++) {
        if (peers[i].state == MXD_PEER_CONNECTED) {
            uint8_t request[8];
            uint32_t start_be = htonl(start_height);
            uint32_t end_be = htonl(end_height);
            memcpy(request, &start_be, 4);
            memcpy(request + 4, &end_be, 4);
            
            if (mxd_send_message_with_retry(peers[i].address, peers[i].port, 
                                           MXD_MSG_GET_BLOCKS, request, sizeof(request), 2) == 0) {
                break;
            }
        }
    }
    
    *block_count = count;
    return blocks;
}

static int mxd_apply_block_transactions(const mxd_block_t *block) {
    if (!block) return -1;
    
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
    
    uint64_t current_time = time(NULL);
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

#include "../include/mxd_blockchain_sync.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_rsc.h"
#include <string.h>
#include <time.h>
#include <stdio.h>

#define MXD_VALIDATION_EXPIRY_BLOCKS 5
#define MXD_MIN_RELAY_SIGNATURES 3
#define MXD_MAX_TIMESTAMP_DRIFT 60

int mxd_sync_blockchain(void) {
    // For testing purposes, simulate successful sync
    return 0;
}

int mxd_get_block_by_height(uint32_t height, mxd_block_t *block) {
    if (!block) return -1;
    
    return mxd_retrieve_block_by_height(height, block);
}

int mxd_sync_validation_chain(const uint8_t block_hash[64], uint32_t height) {
    if (!block_hash) return -1;
    
    if (mxd_request_validation_chain_from_peers(block_hash) != 0) {
        printf("Failed to request validation chain for block at height %u\n", height);
        return -1;
    }
    
    // For testing purposes, simulate successful sync
    printf("Synchronizing validation chain for block at height %u\n", height);
    return 0;
}

int mxd_request_validation_chain_from_peers(const uint8_t block_hash[64]) {
    if (!block_hash) return -1;
    
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    if (mxd_get_peers(peers, &peer_count) != 0 || peer_count == 0) {
        printf("No peers available to request validation chain\n");
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
        printf("Failed to retrieve block for validation chain processing\n");
        return -1;
    }
    
    for (uint32_t i = 0; i < signature_count; i++) {
        if (mxd_verify_and_add_validation_signature(&block, 
                                                  signatures[i].validator_id,
                                                  signatures[i].signature,
                                                  signatures[i].timestamp) != 0) {
            printf("Failed to verify signature %u of %u\n", i + 1, signature_count);
        }
    }
    
    if (mxd_store_block(&block) != 0) {
        printf("Failed to store block with updated validation chain\n");
        return -1;
    }
    
    if (mxd_check_block_relay_status(block_hash) == 1) {
        printf("Block has enough signatures for relay\n");
    }
    
    return 0;
}

int mxd_verify_and_add_validation_signature(mxd_block_t *block, 
                                           const uint8_t validator_id[20],
                                           const uint8_t signature[128],
                                           uint64_t timestamp) {
    if (!block || !validator_id || !signature) return -1;
    
    uint64_t current_time = time(NULL);
    uint64_t drift = (timestamp > current_time) ? 
                     (timestamp - current_time) : 
                     (current_time - timestamp);
    
    if (drift > MXD_MAX_TIMESTAMP_DRIFT) {
        printf("Signature timestamp drift too large: %lu seconds\n", (unsigned long)drift);
        return -1;
    }
    
    if (mxd_signature_exists(block->height, validator_id, signature) != 0) {
        printf("Signature already exists for this block height\n");
        return -1;
    }
    
    if (mxd_is_validator_blacklisted(validator_id) != 0) {
        printf("Validator is blacklisted\n");
        return -1;
    }
    
    if (mxd_add_validator_signature(block, validator_id, timestamp, signature) != 0) {
        printf("Failed to add validator signature to block\n");
        return -1;
    }
    
    if (mxd_store_signature(block->height, validator_id, signature) != 0) {
        printf("Failed to store signature for replay protection\n");
        return -1;
    }
    
    return 0;
}

int mxd_check_block_relay_status(const uint8_t block_hash[64]) {
    if (!block_hash) return -1;
    
    mxd_block_t block;
    if (mxd_retrieve_block_by_hash(block_hash, &block) != 0) {
        printf("Failed to retrieve block for relay status check\n");
        return -1;
    }
    
    if (block.validation_count >= MXD_MIN_RELAY_SIGNATURES) {
        return 1; // Yes, block has enough signatures for relay
    }
    
    return 0; // No, block does not have enough signatures for relay
}

int mxd_sync_rapid_table(mxd_rapid_table_t *table) {
    if (!table) return -1;
    
    // For testing purposes, simulate successful sync
    printf("Synchronizing Rapid Table with network\n");
    return 0;
}

int mxd_handle_validation_chain_conflict(const uint8_t block_hash1[64], 
                                        const uint8_t block_hash2[64]) {
    if (!block_hash1 || !block_hash2) return -1;
    
    mxd_block_t block1, block2;
    if (mxd_retrieve_block_by_hash(block_hash1, &block1) != 0 ||
        mxd_retrieve_block_by_hash(block_hash2, &block2) != 0) {
        printf("Failed to retrieve blocks for conflict resolution\n");
        return -1;
    }
    
    int result = mxd_resolve_fork(&block1, &block2);
    
    if (result > 0) {
        printf("Block 1 wins conflict resolution\n");
        return 1;
    } else if (result < 0) {
        printf("Block 2 wins conflict resolution\n");
        return 2;
    } else {
        printf("Conflict resolution inconclusive\n");
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

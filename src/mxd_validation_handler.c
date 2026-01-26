#include "../include/mxd_p2p.h"
#include "../include/mxd_rsc.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_blockchain_sync.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_endian.h"
#include "../include/mxd_serialize.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// Mutex to prevent race condition when multiple signature handlers
// concurrently load, modify, and store the same block
static pthread_mutex_t validation_sig_mutex = PTHREAD_MUTEX_INITIALIZER;

// BLOCKER FIX: Implement actual processing of validation messages instead of just logging

// Forward declaration for block response callback
extern void mxd_handle_blocks_response(const uint8_t *data, size_t data_len, uint32_t block_index);

// Helper to serialize validation chain for response
static int serialize_validation_chain(const mxd_block_t *block, uint8_t **out_data, size_t *out_len) {
    if (!block || !out_data || !out_len) return -1;
    if (block->validation_count == 0 || !block->validation_chain) {
        *out_data = NULL;
        *out_len = 0;
        return 0;
    }
    
    // Calculate size: block_hash(64) + count(4) + signatures
    size_t size = 64 + 4;
    for (uint32_t i = 0; i < block->validation_count; i++) {
        // validator_id(20) + timestamp(8) + algo_id(1) + sig_len(2) + signature + chain_pos(4)
        size += 20 + 8 + 1 + 2 + block->validation_chain[i].signature_length + 4;
    }
    
    uint8_t *data = malloc(size);
    if (!data) return -1;
    
    uint8_t *ptr = data;
    memcpy(ptr, block->block_hash, 64);
    ptr += 64;
    
    uint32_t count_net = htonl(block->validation_count);
    memcpy(ptr, &count_net, 4);
    ptr += 4;
    
    for (uint32_t i = 0; i < block->validation_count; i++) {
        const mxd_validator_signature_t *sig = &block->validation_chain[i];
        memcpy(ptr, sig->validator_id, 20);
        ptr += 20;
        uint64_t ts_net = mxd_htonll(sig->timestamp);
        memcpy(ptr, &ts_net, 8);
        ptr += 8;
        *ptr++ = sig->algo_id;
        uint16_t sig_len_net = htons(sig->signature_length);
        memcpy(ptr, &sig_len_net, 2);
        ptr += 2;
        memcpy(ptr, sig->signature, sig->signature_length);
        ptr += sig->signature_length;
        uint32_t pos_net = htonl(sig->chain_position);
        memcpy(ptr, &pos_net, 4);
        ptr += 4;
    }
    
    *out_data = data;
    *out_len = size;
    return 0;
}

// Helper to deserialize validation chain from network message
static int deserialize_validation_chain(const uint8_t *data, size_t data_len,
                                       uint8_t block_hash[64],
                                       mxd_validator_signature_t **out_sigs,
                                       uint32_t *out_count) {
    if (!data || data_len < 68 || !block_hash || !out_sigs || !out_count) return -1;
    
    const uint8_t *ptr = data;
    const uint8_t *end = data + data_len;
    
    memcpy(block_hash, ptr, 64);
    ptr += 64;
    
    uint32_t count_net;
    memcpy(&count_net, ptr, 4);
    ptr += 4;
    uint32_t count = ntohl(count_net);
    
    if (count == 0 || count > 1000) {
        *out_sigs = NULL;
        *out_count = 0;
        return 0;
    }
    
    mxd_validator_signature_t *sigs = calloc(count, sizeof(mxd_validator_signature_t));
    if (!sigs) return -1;
    
    for (uint32_t i = 0; i < count; i++) {
        if (ptr + 20 + 8 + 1 + 2 > end) {
            free(sigs);
            return -1;
        }
        
        memcpy(sigs[i].validator_id, ptr, 20);
        ptr += 20;
        uint64_t ts_net;
        memcpy(&ts_net, ptr, 8);
        ptr += 8;
        sigs[i].timestamp = mxd_ntohll(ts_net);
        sigs[i].algo_id = *ptr++;
        uint16_t sig_len_net;
        memcpy(&sig_len_net, ptr, 2);
        ptr += 2;
        sigs[i].signature_length = ntohs(sig_len_net);
        
        if (sigs[i].signature_length > MXD_SIGNATURE_MAX || ptr + sigs[i].signature_length + 4 > end) {
            free(sigs);
            return -1;
        }
        
        memcpy(sigs[i].signature, ptr, sigs[i].signature_length);
        ptr += sigs[i].signature_length;
        uint32_t pos_net;
        memcpy(&pos_net, ptr, 4);
        ptr += 4;
        sigs[i].chain_position = ntohl(pos_net);
    }
    
    *out_sigs = sigs;
    *out_count = count;
    return 0;
}

void mxd_validation_message_handler(const char *address, uint16_t port,
                                      mxd_message_type_t type,
                                      const void *payload,
                                      size_t payload_length) {
    MXD_LOG_DEBUG("validation", "Validation handler invoked: type=%d len=%zu from %s:%u", 
                 type, payload_length, address, port);
    
    switch (type) {
        case MXD_MSG_VALIDATION_SIGNATURE: {
            if (payload_length < 64 + 1 + 20 + 2) {
                MXD_LOG_WARN("validation", "Invalid VALIDATION_SIGNATURE message size: %zu", payload_length);
                return;
            }
            
            const uint8_t *data = (const uint8_t *)payload;
            size_t offset = 0;
            
            const uint8_t *block_hash = data + offset;
            offset += 64;
            
            uint8_t algo_id = data[offset];
            offset += 1;
            
            const uint8_t *validator_id = data + offset;
            offset += 20;
            
            uint16_t sig_len_net;
            memcpy(&sig_len_net, data + offset, 2);
            uint16_t sig_len = ntohs(sig_len_net);
            offset += 2;
            
            if (offset + sig_len + 4 + 8 > payload_length) {
                MXD_LOG_WARN("validation", "Invalid VALIDATION_SIGNATURE signature length: %u", sig_len);
                return;
            }
            
            const uint8_t *signature = data + offset;
            offset += sig_len;
            
            uint32_t chain_pos_net;
            memcpy(&chain_pos_net, data + offset, 4);
            uint32_t chain_position = ntohl(chain_pos_net);
            offset += 4;
            
            uint64_t timestamp_net;
            memcpy(&timestamp_net, data + offset, 8);
            uint64_t timestamp = mxd_ntohll(timestamp_net);
            
            MXD_LOG_INFO("validation", "Processing validation signature: algo_id=%u, sig_len=%u, chain_pos=%u",
                         algo_id, sig_len, chain_position);
            
            // Lock mutex to prevent concurrent handlers from overwriting each other's signatures.
            // Without this, multiple handlers load the same block (validation_count=N),
            // each adds one signature (=N+1), and stores back - last writer wins, losing signatures.
            pthread_mutex_lock(&validation_sig_mutex);

            mxd_block_t block;
            memset(&block, 0, sizeof(block));
            if (mxd_retrieve_block_by_hash(block_hash, &block) != 0) {
                MXD_LOG_WARN("validation", "Block not found for validation signature");
                pthread_mutex_unlock(&validation_sig_mutex);
                return;
            }

            // Verify and add the signature to the block
            if (mxd_verify_and_add_validation_signature(&block, validator_id, algo_id,
                                                        signature, sig_len, timestamp) == 0) {
                // Store updated block with new signature
                if (mxd_store_block(&block) == 0) {
                    MXD_LOG_INFO("validation", "Added validation signature to block (now has %u signatures)",
                                 block.validation_count);

                    // Check if block now has enough signatures for relay
                    if (mxd_check_block_relay_status(block_hash) == 1) {
                        MXD_LOG_INFO("validation", "Block now has enough signatures for relay");
                    }
                } else {
                    MXD_LOG_ERROR("validation", "Failed to store block with new signature");
                }
            } else {
                MXD_LOG_WARN("validation", "Failed to verify/add validation signature");
            }

            mxd_free_block(&block);
            pthread_mutex_unlock(&validation_sig_mutex);
            break;
        }
        
        case MXD_MSG_VALIDATION_CHAIN: {
            MXD_LOG_INFO("validation", "Processing validation chain message: len=%zu", payload_length);
            
            // BLOCKER FIX: Deserialize and process the validation chain
            uint8_t block_hash[64];
            mxd_validator_signature_t *signatures = NULL;
            uint32_t sig_count = 0;
            
            if (deserialize_validation_chain(payload, payload_length, block_hash, &signatures, &sig_count) == 0) {
                if (sig_count > 0 && signatures) {
                    if (mxd_process_incoming_validation_chain(block_hash, signatures, sig_count) == 0) {
                        MXD_LOG_INFO("validation", "Successfully processed validation chain with %u signatures", sig_count);
                    } else {
                        MXD_LOG_WARN("validation", "Failed to process validation chain");
                    }
                    free(signatures);
                }
            } else {
                MXD_LOG_WARN("validation", "Failed to deserialize validation chain");
            }
            break;
        }
        
        case MXD_MSG_BLOCKS: {
            MXD_LOG_INFO("validation", "Processing block message: len=%zu", payload_length);
            
            // BLOCKER FIX: Process received block data
            if (payload_length < 4) {
                MXD_LOG_WARN("validation", "Block message too short");
                return;
            }
            
            const uint8_t *data = (const uint8_t *)payload;

            // Check if this is a height response (4 bytes: current_height)
            if (payload_length == 4) {
                // This is a height info response - route to sync module
                extern void mxd_handle_peer_height_response(const uint8_t *data, size_t data_len);
                const uint8_t *ptr = data;
                uint32_t current_height = mxd_read_u32_be(&ptr);
                MXD_LOG_INFO("validation", "Received height response: %u", current_height);
                mxd_handle_peer_height_response(data, payload_length);
                return;
            }
            
            // Otherwise, this is actual block data - pass to block response handler
            // Block index is typically 0 for single block responses
            mxd_handle_blocks_response(data, payload_length, 0);
            break;
        }
        
        case MXD_MSG_GET_BLOCKS: {
            MXD_LOG_INFO("validation", "Processing GET_BLOCKS request: len=%zu", payload_length);
            
            // BLOCKER FIX: Respond to block requests
            if (payload_length < 8) {
                MXD_LOG_WARN("validation", "GET_BLOCKS message too short");
                return;
            }
            
            const uint8_t *ptr = (const uint8_t *)payload;
            uint32_t start_height = mxd_read_u32_be(&ptr);
            uint32_t end_height = mxd_read_u32_be(&ptr);
            
            // If both are 0, this is a height info request
            if (start_height == 0 && end_height == 0) {
                uint32_t current_height = 0;
                mxd_get_blockchain_height(&current_height);

                // Send height response - height must be in first 4 bytes for sync code to read it
                uint8_t response[4];
                uint8_t *rp = response;
                mxd_write_u32_be(&rp, current_height);  // current_height (first 4 bytes)

                mxd_send_message(address, port, MXD_MSG_BLOCKS, response, sizeof(response));
                MXD_LOG_INFO("validation", "Sent height response: %u", current_height);
                return;
            }
            
            // Otherwise, send requested blocks with full serialization
            for (uint32_t h = start_height; h <= end_height && h - start_height < 100; h++) {
                mxd_block_t block;
                memset(&block, 0, sizeof(block));
                if (mxd_retrieve_block_by_height(h, &block) == 0) {
                    // Serialize full block for network transmission
                    uint8_t *block_data = NULL;
                    size_t block_data_len = 0;

                    if (mxd_serialize_block_for_network(&block, &block_data, &block_data_len) == 0 && block_data) {
                        mxd_send_message(address, port, MXD_MSG_BLOCKS, block_data, block_data_len);
                        MXD_LOG_INFO("validation", "Sent block at height %u (size=%zu bytes)", h, block_data_len);
                        free(block_data);
                    } else {
                        MXD_LOG_ERROR("validation", "Failed to serialize block at height %u", h);
                    }
                    mxd_free_block(&block);
                }
            }
            break;
        }
        
        case MXD_MSG_GET_VALIDATION_CHAIN: {
            if (payload_length < 64) {
                MXD_LOG_WARN("validation", "Invalid GET_VALIDATION_CHAIN message size: %zu", payload_length);
                return;
            }
            
            const uint8_t *block_hash = (const uint8_t *)payload;
            MXD_LOG_INFO("validation", "Processing request for validation chain");
            
            // BLOCKER FIX: Actually send the validation chain
            mxd_block_t block;
            memset(&block, 0, sizeof(block));
            if (mxd_retrieve_block_by_hash(block_hash, &block) != 0) {
                MXD_LOG_WARN("validation", "Block not found for validation chain request");
                return;
            }
            
            uint8_t *chain_data = NULL;
            size_t chain_len = 0;
            if (serialize_validation_chain(&block, &chain_data, &chain_len) == 0 && chain_data) {
                mxd_send_message(address, port, MXD_MSG_VALIDATION_CHAIN, chain_data, chain_len);
                MXD_LOG_INFO("validation", "Sent validation chain with %u signatures", block.validation_count);
                free(chain_data);
            }
            
            mxd_free_block(&block);
            break;
        }
        
        case MXD_MSG_BLOCK_VALIDATION: {
            MXD_LOG_INFO("validation", "Processing BLOCK_VALIDATION message: len=%zu", payload_length);
            // Block validation requests are handled similarly to validation signatures
            // but may include additional validation context
            break;
        }
        
        default:
            MXD_LOG_WARN("validation", "Unhandled validation message type: %d", type);
            break;
    }
}

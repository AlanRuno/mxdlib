#include "../include/mxd_p2p.h"
#include "../include/mxd_rsc.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_endian.h"
#include <string.h>

void mxd_validation_message_handler(const char *address, uint16_t port,
                                      mxd_message_type_t type,
                                      const void *payload,
                                      size_t payload_length) {
    MXD_LOG_INFO("validation", "Validation handler invoked: type=%d len=%zu from %s:%u", 
                 type, payload_length, address, port);
    
    switch (type) {
        case MXD_MSG_VALIDATION_SIGNATURE: {
            if (payload_length < 64 + 2) {
                MXD_LOG_WARN("validation", "Invalid VALIDATION_SIGNATURE message size: %zu", payload_length);
                return;
            }
            
            const uint8_t *data = (const uint8_t *)payload;
            size_t offset = 0;
            
            const uint8_t *block_hash = data + offset;
            offset += 64;
            
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
            
            uint32_t chain_position;
            memcpy(&chain_position, data + offset, 4);
            offset += 4;
            
            uint64_t timestamp;
            memcpy(&timestamp, data + offset, 8);
            
            MXD_LOG_INFO("validation", "Received validation signature: sig_len=%u, chain_pos=%u, timestamp=%lu",
                         sig_len, chain_position, timestamp);
            
            break;
        }
        
        case MXD_MSG_VALIDATION_CHAIN: {
            MXD_LOG_INFO("validation", "Received validation chain message: len=%zu", payload_length);
            break;
        }
        
        case MXD_MSG_BLOCKS: {
            MXD_LOG_INFO("validation", "Received block message: len=%zu", payload_length);
            break;
        }
        
        case MXD_MSG_GET_VALIDATION_CHAIN: {
            if (payload_length < 64) {
                MXD_LOG_WARN("validation", "Invalid GET_VALIDATION_CHAIN message size: %zu", payload_length);
                return;
            }
            
            const uint8_t *block_hash = (const uint8_t *)payload;
            MXD_LOG_INFO("validation", "Received request for validation chain");
            break;
        }
        
        default:
            MXD_LOG_WARN("validation", "Unhandled validation message type: %d", type);
            break;
    }
}

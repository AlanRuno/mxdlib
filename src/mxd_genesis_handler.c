#include "../include/mxd_rsc.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_endian.h"
#include <string.h>

void mxd_genesis_message_handler(const char *address, uint16_t port,
                                  mxd_message_type_t type,
                                  const void *payload,
                                  size_t payload_length) {
    MXD_LOG_INFO("genesis", "Genesis handler invoked: type=%d len=%zu from %s:%u", 
                 type, payload_length, address, port);
    switch (type) {
        case MXD_MSG_GENESIS_ANNOUNCE: {
            if (payload_length < 20 + 256 + 8 + 2) {
                MXD_LOG_WARN("genesis", "Invalid GENESIS_ANNOUNCE message size");
                return;
            }
            
            const uint8_t *data = (const uint8_t *)payload;
            size_t offset = 0;
            
            const uint8_t *node_address = data + offset;
            offset += 20;
            const uint8_t *public_key = data + offset;
            offset += 256;
            uint64_t timestamp_net;
            memcpy(&timestamp_net, data + offset, 8);
            uint64_t timestamp = mxd_ntohll(timestamp_net);
            offset += 8;
            uint16_t sig_len_net;
            memcpy(&sig_len_net, data + offset, 2);
            uint16_t sig_len = ntohs(sig_len_net);
            offset += 2;
            
            if (offset + sig_len > payload_length) {
                MXD_LOG_WARN("genesis", "Invalid GENESIS_ANNOUNCE signature length");
                return;
            }
            
            const uint8_t *signature = data + offset;
            
            mxd_handle_genesis_announce(node_address, public_key, timestamp, signature, sig_len);
            break;
        }
        
        case MXD_MSG_GENESIS_SIGN_REQUEST: {
            if (payload_length < 20 + 64 + 20 + 4) {
                MXD_LOG_WARN("genesis", "Invalid GENESIS_SIGN_REQUEST message size");
                return;
            }
            
            const uint8_t *data = (const uint8_t *)payload;
            size_t offset = 0;
            
            const uint8_t *target_address = data + offset;
            offset += 20;
            const uint8_t *membership_digest = data + offset;
            offset += 64;
            const uint8_t *proposer_id = data + offset;
            offset += 20;
            uint32_t height;
            memcpy(&height, data + offset, 4);
            
            mxd_handle_genesis_sign_request(target_address, membership_digest, proposer_id, height);
            break;
        }
        
        case MXD_MSG_GENESIS_SIGN_RESPONSE: {
            if (payload_length < 20 + 64 + 2) {
                MXD_LOG_WARN("genesis", "Invalid GENESIS_SIGN_RESPONSE message size");
                return;
            }
            
            const uint8_t *data = (const uint8_t *)payload;
            size_t offset = 0;
            
            const uint8_t *signer_address = data + offset;
            offset += 20;
            const uint8_t *membership_digest = data + offset;
            offset += 64;
            uint16_t sig_len;
            memcpy(&sig_len, data + offset, 2);
            offset += 2;
            
            if (offset + sig_len > payload_length) {
                MXD_LOG_WARN("genesis", "Invalid GENESIS_SIGN_RESPONSE signature length");
                return;
            }
            
            const uint8_t *signature = data + offset;
            
            mxd_handle_genesis_sign_response(signer_address, membership_digest, signature, sig_len);
            break;
        }
        
        default:
            break;
    }
}

#include "../include/mxd_http_api.h"
#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_logging.h"
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static struct MHD_Daemon *http_daemon = NULL;

// Helper to convert block to JSON
static char* block_to_json(const mxd_block_t *block) {
    if (!block) return NULL;
    
    // Convert block hash to hex string
    char hash_hex[129] = {0};
    for (int i = 0; i < 64; i++) {
        snprintf(hash_hex + i*2, 3, "%02x", block->block_hash[i]);
    }
    
    // Convert prev hash to hex string
    char prev_hash_hex[129] = {0};
    for (int i = 0; i < 64; i++) {
        snprintf(prev_hash_hex + i*2, 3, "%02x", block->prev_block_hash[i]);
    }
    
    // Convert proposer_id to hex string
    char proposer_hex[41] = {0};
    for (int i = 0; i < 20; i++) {
        snprintf(proposer_hex + i*2, 3, "%02x", block->proposer_id[i]);
    }
    
    // Build JSON response
    char *json = malloc(4096);
    if (!json) return NULL;
    
    snprintf(json, 4096,
        "{"
        "\"height\":%u,"
        "\"hash\":\"%s\","
        "\"prev_hash\":\"%s\","
        "\"timestamp\":%lu,"
        "\"proposer\":\"%s\","
        "\"version\":%u,"
        "\"difficulty\":%u,"
        "\"nonce\":%lu,"
        "\"validation_count\":%u,"
        "\"rapid_membership_count\":%u,"
        "\"total_supply\":%lu"
        "}",
        block->height,
        hash_hex,
        prev_hash_hex,
        (unsigned long)block->timestamp,
        proposer_hex,
        block->version,
        block->difficulty,
        (unsigned long)block->nonce,
        block->validation_count,
        block->rapid_membership_count,
        (unsigned long)block->total_supply
    );
    
    return json;
}

static enum MHD_Result handle_request(void *cls,
                                       struct MHD_Connection *connection,
                                       const char *url,
                                       const char *method,
                                       const char *version,
                                       const char *upload_data,
                                       size_t *upload_data_size,
                                       void **con_cls) {
    (void)cls;
    (void)version;
    (void)upload_data;
    (void)upload_data_size;
    (void)con_cls;
    
    if (strcmp(method, "GET") != 0) {
        const char *error = "{\"error\":\"Method not allowed\"}";
        struct MHD_Response *response = MHD_create_response_from_buffer(
            strlen(error), (void*)error, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(response, "Content-Type", "application/json");
        MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_METHOD_NOT_ALLOWED, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    char *json_response = NULL;
    int status_code = MHD_HTTP_OK;
    
    // Handle /status endpoint
    if (strcmp(url, "/status") == 0 || strcmp(url, "/") == 0) {
        uint32_t height = 0;
        mxd_get_blockchain_height(&height);
        
        // Get latest block if available
        mxd_block_t block;
        char latest_hash[129] = {0};
        if (height > 0 && mxd_retrieve_block_by_height(height - 1, &block) == 0) {
            for (int i = 0; i < 64; i++) {
                snprintf(latest_hash + i*2, 3, "%02x", block.block_hash[i]);
            }
            mxd_free_block(&block);
        } else if (height == 0) {
            // Check for genesis block at height 0
            if (mxd_retrieve_block_by_height(0, &block) == 0) {
                for (int i = 0; i < 64; i++) {
                    snprintf(latest_hash + i*2, 3, "%02x", block.block_hash[i]);
                }
                height = 1; // We have genesis
                mxd_free_block(&block);
            }
        }
        
        json_response = malloc(512);
        if (json_response) {
            snprintf(json_response, 512,
                "{\"status\":\"ok\",\"height\":%u,\"latest_hash\":\"%s\"}",
                height, latest_hash);
        }
    }
    // Handle /block/{height} endpoint
    else if (strncmp(url, "/block/", 7) == 0) {
        const char *height_str = url + 7;
        uint32_t height = (uint32_t)atoi(height_str);
        
        mxd_block_t block;
        if (mxd_retrieve_block_by_height(height, &block) == 0) {
            json_response = block_to_json(&block);
            mxd_free_block(&block);
        } else {
            json_response = strdup("{\"error\":\"Block not found\"}");
            status_code = MHD_HTTP_NOT_FOUND;
        }
    }
    // Handle /blocks/latest endpoint
    else if (strcmp(url, "/blocks/latest") == 0) {
        const char *limit_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "limit");
        int limit = limit_str ? atoi(limit_str) : 10;
        if (limit > 100) limit = 100;
        if (limit < 1) limit = 1;
        
        uint32_t height = 0;
        mxd_get_blockchain_height(&height);
        
        // Build JSON array of blocks
        json_response = malloc(limit * 1024 + 256);
        if (json_response) {
            strcpy(json_response, "{\"blocks\":[");
            int first = 1;
            
            for (int i = 0; i < limit && height > 0; i++) {
                mxd_block_t block;
                if (mxd_retrieve_block_by_height(height - 1 - i, &block) == 0) {
                    char *block_json = block_to_json(&block);
                    if (block_json) {
                        if (!first) strcat(json_response, ",");
                        strcat(json_response, block_json);
                        free(block_json);
                        first = 0;
                    }
                    mxd_free_block(&block);
                }
            }
            
            strcat(json_response, "]}");
        }
    }
    else {
        json_response = strdup("{\"error\":\"Endpoint not found\"}");
        status_code = MHD_HTTP_NOT_FOUND;
    }
    
    if (!json_response) {
        json_response = strdup("{\"error\":\"Internal server error\"}");
        status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(json_response), json_response, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    
    enum MHD_Result ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    
    return ret;
}

int mxd_http_api_start(uint16_t port) {
    if (http_daemon) {
        MXD_LOG_WARN("http_api", "HTTP API server already running");
        return 0;
    }
    
    http_daemon = MHD_start_daemon(
        MHD_USE_THREAD_PER_CONNECTION,
        port,
        NULL, NULL,
        &handle_request, NULL,
        MHD_OPTION_END);
    
    if (!http_daemon) {
        MXD_LOG_ERROR("http_api", "Failed to start HTTP API server on port %u", port);
        return -1;
    }
    
    MXD_LOG_INFO("http_api", "HTTP API server started on port %u", port);
    return 0;
}

void mxd_http_api_stop(void) {
    if (http_daemon) {
        MHD_stop_daemon(http_daemon);
        http_daemon = NULL;
        MXD_LOG_INFO("http_api", "HTTP API server stopped");
    }
}

int mxd_http_api_is_running(void) {
    return http_daemon != NULL;
}

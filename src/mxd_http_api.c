#include "../include/mxd_http_api.h"
#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_mempool.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_address.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_rsc.h"
#include "../include/mxd_smart_contracts.h"
#include "../include/mxd_contracts_db.h"
#include "../include/mxd_gas_metering.h"
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <cjson/cJSON.h>
#include <wasm3/wasm3.h>

// Connection context for POST data accumulation
typedef struct {
    char *post_data;
    size_t post_data_size;
} connection_info_t;

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
        "\"transaction_count\":%u,"
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
        block->transaction_count,
        block->validation_count,
        block->rapid_membership_count,
        (unsigned long)block->total_supply
    );
    
    return json;
}

// Helper to parse hex string to bytes
static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len) {
    if (!hex || !bytes) return -1;
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) return -1;
    
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        bytes[i] = (uint8_t)byte;
    }
    return (int)(hex_len / 2);
}

// Handle POST /transaction endpoint - submit a new transaction
// Required fields: from (hex), to (hex), amount (MXD), private_key (hex), public_key (hex), algo_id (1=Ed25519, 2=Dilithium5)
static char* handle_transaction_submit(const char *post_data, int *status_code) {
    *status_code = MHD_HTTP_OK;
    
    if (!post_data || strlen(post_data) == 0) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Empty request body\"}");
    }
    
    cJSON *json = cJSON_Parse(post_data);
    if (!json) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid JSON\"}");
    }
    
    // Extract required fields
    cJSON *from_addr = cJSON_GetObjectItem(json, "from");
    cJSON *to_addr = cJSON_GetObjectItem(json, "to");
    cJSON *amount_obj = cJSON_GetObjectItem(json, "amount");
    cJSON *privkey_hex = cJSON_GetObjectItem(json, "private_key");
    cJSON *pubkey_hex = cJSON_GetObjectItem(json, "public_key");
    cJSON *algo_id_obj = cJSON_GetObjectItem(json, "algo_id");
    
    if (!from_addr || !cJSON_IsString(from_addr) ||
        !to_addr || !cJSON_IsString(to_addr) ||
        !amount_obj || !cJSON_IsNumber(amount_obj) ||
        !privkey_hex || !cJSON_IsString(privkey_hex) ||
        !pubkey_hex || !cJSON_IsString(pubkey_hex)) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Missing required fields: from, to, amount, private_key, public_key\"}");
    }
    
    // Parse algo_id (default to Ed25519 = 1)
    uint8_t algo_id = 1;
    if (algo_id_obj && cJSON_IsNumber(algo_id_obj)) {
        algo_id = (uint8_t)algo_id_obj->valueint;
    }
    
    // Parse addresses
    uint8_t from_bytes[20], to_bytes[20];
    if (hex_to_bytes(from_addr->valuestring, from_bytes, 20) != 20 ||
        hex_to_bytes(to_addr->valuestring, to_bytes, 20) != 20) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid address format (expected 40 hex chars)\"}");
    }
    
    // Parse public key
    uint8_t pubkey[2592]; // Max size for Dilithium5
    int pubkey_len = hex_to_bytes(pubkey_hex->valuestring, pubkey, sizeof(pubkey));
    if (pubkey_len <= 0) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid public key format\"}");
    }
    
    // Parse private key
    uint8_t privkey[4864]; // Max size for Dilithium5
    int privkey_len = hex_to_bytes(privkey_hex->valuestring, privkey, sizeof(privkey));
    if (privkey_len <= 0) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid private key format\"}");
    }
    
    // Parse amount (in MXD, convert to base units)
    double amount_mxd = amount_obj->valuedouble;
    if (amount_mxd <= 0) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Amount must be positive\"}");
    }
    mxd_amount_t amount = (mxd_amount_t)(amount_mxd * 100000000.0 + 0.5);
    
    // Create transaction
    mxd_transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    
    if (mxd_create_transaction(&tx) != 0) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to create transaction\"}");
    }
    
    // Find UTXOs for the sender
    mxd_utxo_t *utxos = NULL;
    size_t utxo_count = 0;
    if (mxd_get_utxos_by_pubkey_hash(from_bytes, &utxos, &utxo_count) != 0 || utxo_count == 0) {
        mxd_free_transaction(&tx);
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"No UTXOs found for sender address\"}");
    }
    
    // Select UTXOs to cover the amount
    mxd_amount_t total_input = 0;
    size_t inputs_added = 0;
    for (size_t i = 0; i < utxo_count && total_input < amount; i++) {
        if (mxd_add_tx_input(&tx, utxos[i].tx_hash, utxos[i].output_index, 
                             algo_id, pubkey, (size_t)pubkey_len) == 0) {
            total_input += utxos[i].amount;
            inputs_added++;
        }
    }
    
    if (total_input < amount) {
        mxd_free_transaction(&tx);
        free(utxos);
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        char *error = malloc(128);
        snprintf(error, 128, "{\"error\":\"Insufficient balance: have %llu, need %llu\"}",
                 (unsigned long long)total_input, (unsigned long long)amount);
        return error;
    }
    
    // Add output to recipient
    if (mxd_add_tx_output(&tx, to_bytes, amount) != 0) {
        mxd_free_transaction(&tx);
        free(utxos);
        cJSON_Delete(json);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to add transaction output\"}");
    }
    
    // Add change output if needed
    mxd_amount_t change = total_input - amount;
    if (change > 0) {
        if (mxd_add_tx_output(&tx, from_bytes, change) != 0) {
            mxd_free_transaction(&tx);
            free(utxos);
            cJSON_Delete(json);
            *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
            return strdup("{\"error\":\"Failed to add change output\"}");
        }
    }
    
    // Sign all inputs
    for (size_t i = 0; i < inputs_added; i++) {
        if (mxd_sign_tx_input(&tx, (uint32_t)i, algo_id, privkey) != 0) {
            mxd_free_transaction(&tx);
            free(utxos);
            cJSON_Delete(json);
            *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
            return strdup("{\"error\":\"Failed to sign transaction input\"}");
        }
    }
    
    // Calculate transaction hash
    uint8_t tx_hash[64];
    if (mxd_calculate_tx_hash(&tx, tx_hash) != 0) {
        mxd_free_transaction(&tx);
        free(utxos);
        cJSON_Delete(json);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to calculate transaction hash\"}");
    }
    
    // Add to mempool with medium priority
    if (mxd_add_to_mempool(&tx, MXD_PRIORITY_MEDIUM) != 0) {
        mxd_free_transaction(&tx);
        free(utxos);
        cJSON_Delete(json);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to add transaction to mempool\"}");
    }
    
    // Build success response with transaction hash
    char tx_hash_hex[129] = {0};
    for (int i = 0; i < 64; i++) {
        snprintf(tx_hash_hex + i*2, 3, "%02x", tx_hash[i]);
    }
    
    char *response = malloc(256);
    snprintf(response, 256, "{\"success\":true,\"tx_hash\":\"%s\"}", tx_hash_hex);
    
    mxd_free_transaction(&tx);
    free(utxos);
    cJSON_Delete(json);
    
    MXD_LOG_INFO("http_api", "Transaction submitted: %s", tx_hash_hex);
    return response;
}

// Handle GET /validators endpoint - list RSC members from genesis
static char* handle_validators(int *status_code) {
    *status_code = MHD_HTTP_OK;

    mxd_block_t genesis;
    if (mxd_retrieve_block_by_height(0, &genesis) != 0) {
        *status_code = MHD_HTTP_NOT_FOUND;
        return strdup("{\"error\":\"Genesis block not found\"}");
    }

    // Build JSON response
    size_t buf_size = 256 + genesis.rapid_membership_count * 256;
    char *response = malloc(buf_size);
    if (!response) {
        mxd_free_block(&genesis);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }

    int offset = snprintf(response, buf_size, "{\"count\":%u,\"validators\":[", genesis.rapid_membership_count);

    for (uint32_t i = 0; i < genesis.rapid_membership_count; i++) {
        mxd_rapid_membership_entry_t *entry = &genesis.rapid_membership_entries[i];

        // Convert address to hex
        char addr_hex[41] = {0};
        for (int j = 0; j < 20; j++) {
            snprintf(addr_hex + j*2, 3, "%02x", entry->node_address[j]);
        }

        // Convert public key to hex (first 32 bytes for display)
        char pk_hex[65] = {0};
        int pk_display_len = entry->public_key_length < 32 ? entry->public_key_length : 32;
        for (int j = 0; j < pk_display_len; j++) {
            snprintf(pk_hex + j*2, 3, "%02x", entry->public_key[j]);
        }

        offset += snprintf(response + offset, buf_size - offset,
            "%s{\"index\":%u,\"address\":\"%s\",\"algo_id\":%u,\"public_key\":\"%s\",\"timestamp\":%lu}",
            i > 0 ? "," : "", i, addr_hex, entry->algo_id, pk_hex, (unsigned long)entry->timestamp);
    }

    snprintf(response + offset, buf_size - offset, "]}");
    mxd_free_block(&genesis);
    return response;
}

// Handle GET /node/identity endpoint - get local node's identity for testing
static char* handle_node_identity(int *status_code) {
    *status_code = MHD_HTTP_OK;

    uint8_t address[20];
    uint8_t pubkey[2592];
    uint8_t privkey[4864];
    size_t pubkey_len = 0, privkey_len = 0;
    uint8_t algo_id = 0;

    if (mxd_get_local_node_identity(address, pubkey, &pubkey_len, privkey, &privkey_len, &algo_id) != 0) {
        *status_code = MHD_HTTP_SERVICE_UNAVAILABLE;
        return strdup("{\"error\":\"Node identity not initialized\"}");
    }

    // Convert to hex strings
    char addr_hex[41] = {0};
    for (int i = 0; i < 20; i++) {
        snprintf(addr_hex + i*2, 3, "%02x", address[i]);
    }

    char *pubkey_hex = malloc(pubkey_len * 2 + 1);
    char *privkey_hex = malloc(privkey_len * 2 + 1);
    if (!pubkey_hex || !privkey_hex) {
        free(pubkey_hex);
        free(privkey_hex);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }

    for (size_t i = 0; i < pubkey_len; i++) {
        snprintf(pubkey_hex + i*2, 3, "%02x", pubkey[i]);
    }
    pubkey_hex[pubkey_len * 2] = '\0';

    for (size_t i = 0; i < privkey_len; i++) {
        snprintf(privkey_hex + i*2, 3, "%02x", privkey[i]);
    }
    privkey_hex[privkey_len * 2] = '\0';

    // Build response
    size_t response_size = 256 + pubkey_len * 2 + privkey_len * 2;
    char *response = malloc(response_size);
    if (!response) {
        free(pubkey_hex);
        free(privkey_hex);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }

    snprintf(response, response_size,
        "{\"address\":\"%s\",\"public_key\":\"%s\",\"private_key\":\"%s\",\"algo_id\":%u}",
        addr_hex, pubkey_hex, privkey_hex, algo_id);

    free(pubkey_hex);
    free(privkey_hex);
    return response;
}

// Handle GET /rsc endpoint - get full rapid stake table
static char* handle_rsc(int *status_code) {
    *status_code = MHD_HTTP_OK;

    const mxd_rapid_table_t *table = mxd_get_rapid_table();
    if (!table) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Rapid table not available\"}");
    }

    // Build JSON response with full RSC data
    size_t buf_size = 512 + table->count * 1024;
    char *response = malloc(buf_size);
    if (!response) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }

    int offset = snprintf(response, buf_size,
        "{\"count\":%zu,\"last_update\":%lu,\"nodes\":[",
        table->count, (unsigned long)table->last_update);

    for (size_t i = 0; i < table->count; i++) {
        mxd_node_stake_t *node = table->nodes[i];
        if (!node) continue;

        // Convert address to hex
        char addr_hex[41] = {0};
        for (int j = 0; j < 20; j++) {
            snprintf(addr_hex + j*2, 3, "%02x", node->node_address[j]);
        }

        // Calculate stake in MXD
        double stake_mxd = (double)node->stake_amount / 100000000.0;

        offset += snprintf(response + offset, buf_size - offset,
            "%s{"
            "\"index\":%zu,"
            "\"node_id\":\"%s\","
            "\"address\":\"%s\","
            "\"stake\":%llu,"
            "\"stake_mxd\":%.8f,"
            "\"rank\":%u,"
            "\"rank_score\":%u,"
            "\"active\":%d,"
            "\"in_rapid_table\":%d,"
            "\"rapid_table_position\":%u,"
            "\"metrics\":{"
            "\"avg_response_time\":%llu,"
            "\"min_response_time\":%llu,"
            "\"max_response_time\":%llu,"
            "\"response_count\":%u,"
            "\"message_success\":%u,"
            "\"message_total\":%u,"
            "\"reliability_score\":%.6f,"
            "\"performance_score\":%.6f,"
            "\"last_update\":%llu,"
            "\"tip_share\":%llu,"
            "\"peer_count\":%zu"
            "}}",
            i > 0 ? "," : "",
            i,
            node->node_id,
            addr_hex,
            (unsigned long long)node->stake_amount,
            stake_mxd,
            node->rapid_table_position,
            node->rank,
            node->active,
            node->in_rapid_table,
            node->rapid_table_position,
            (unsigned long long)node->metrics.avg_response_time,
            (unsigned long long)node->metrics.min_response_time,
            (unsigned long long)node->metrics.max_response_time,
            node->metrics.response_count,
            node->metrics.message_success,
            node->metrics.message_total,
            node->metrics.reliability_score,
            node->metrics.performance_score,
            (unsigned long long)node->metrics.last_update,
            (unsigned long long)node->metrics.tip_share,
            node->metrics.peer_count);
    }

    snprintf(response + offset, buf_size - offset, "]}");
    return response;
}

// Handle GET /wallet/generate endpoint - generate new wallet
static char* handle_wallet_generate(int *status_code) {
    *status_code = MHD_HTTP_OK;

    // Generate passphrase
    char passphrase[256] = {0};
    if (mxd_generate_passphrase(passphrase, sizeof(passphrase)) != 0) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to generate passphrase\"}");
    }

    // Generate keypair using Ed25519
    uint8_t public_key[32];
    uint8_t private_key[64];
    if (mxd_sig_keygen(MXD_SIGALG_ED25519, public_key, private_key) != 0) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to generate keypair\"}");
    }

    // Generate address from public key
    char address[64] = {0};
    if (mxd_address_to_string_v2(MXD_SIGALG_ED25519, public_key, 32, address, sizeof(address)) != 0) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to generate address\"}");
    }

    // Derive address20 for balance lookups
    uint8_t addr20[20];
    if (mxd_derive_address(MXD_SIGALG_ED25519, public_key, 32, addr20) != 0) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to derive address20\"}");
    }

    // Convert keys to hex
    char pubkey_hex[65] = {0};
    char privkey_hex[129] = {0};
    char addr20_hex[41] = {0};
    for (int i = 0; i < 32; i++) {
        snprintf(pubkey_hex + i*2, 3, "%02x", public_key[i]);
    }
    for (int i = 0; i < 64; i++) {
        snprintf(privkey_hex + i*2, 3, "%02x", private_key[i]);
    }
    for (int i = 0; i < 20; i++) {
        snprintf(addr20_hex + i*2, 3, "%02x", addr20[i]);
    }

    // Build response
    char *response = malloc(1024);
    if (!response) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }

    snprintf(response, 1024,
        "{"
        "\"passphrase\":\"%s\","
        "\"address\":\"mx%s\","
        "\"address20\":\"%s\","
        "\"public_key\":\"%s\","
        "\"private_key\":\"%s\","
        "\"algo\":\"ed25519\","
        "\"algo_id\":1"
        "}",
        passphrase, address, addr20_hex, pubkey_hex, privkey_hex);

    MXD_LOG_INFO("http_api", "Generated new wallet: mx%s", address);
    return response;
}

// Handle GET /balance/{address} endpoint
static char* handle_balance(const char *address_hex, int *status_code) {
    *status_code = MHD_HTTP_OK;
    
    uint8_t address[20];
    if (hex_to_bytes(address_hex, address, 20) != 20) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid address format (expected 40 hex chars)\"}");
    }
    
    mxd_utxo_t *utxos = NULL;
    size_t utxo_count = 0;
    mxd_amount_t balance = 0;
    
    if (mxd_get_utxos_by_pubkey_hash(address, &utxos, &utxo_count) == 0) {
        for (size_t i = 0; i < utxo_count; i++) {
            balance += utxos[i].amount;
        }
        free(utxos);
    }
    
    char *response = malloc(256);
    snprintf(response, 256, "{\"address\":\"%s\",\"balance\":%llu,\"balance_mxd\":%.8f,\"utxo_count\":%zu}",
             address_hex, (unsigned long long)balance, (double)balance / 100000000.0, utxo_count);
    return response;
}

// Handle POST /contract/deploy - Deploy a new smart contract
static char* handle_contract_deploy(const char *post_data, int *status_code) {
    *status_code = MHD_HTTP_OK;

    if (!post_data) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"No POST data provided\"}");
    }

    // Parse JSON input
    cJSON *json = cJSON_Parse(post_data);
    if (!json) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid JSON\"}");
    }

    // Extract code (hex string)
    cJSON *code_item = cJSON_GetObjectItem(json, "code");
    if (!code_item || !cJSON_IsString(code_item)) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Missing or invalid 'code' field (hex string required)\"}");
    }

    const char *code_hex = code_item->valuestring;
    size_t code_len = strlen(code_hex);
    if (code_len % 2 != 0 || code_len > MXD_MAX_CONTRACT_SIZE * 2) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid code length or exceeds maximum size\"}");
    }

    // Convert hex to bytes
    uint8_t *code = malloc(code_len / 2);
    if (!code) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }

    if (hex_to_bytes(code_hex, code, code_len / 2) != (int)(code_len / 2)) {
        free(code);
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid hex encoding\"}");
    }

    // Extract deployer address (optional, defaults to zeros if not provided)
    uint8_t deployer[20] = {0};
    cJSON *deployer_item = cJSON_GetObjectItem(json, "deployer");
    if (deployer_item && cJSON_IsString(deployer_item)) {
        const char *deployer_hex = deployer_item->valuestring;
        if (strlen(deployer_hex) == 40) {
            // SECURITY FIX: Check hex_to_bytes return value
            if (hex_to_bytes(deployer_hex, deployer, 20) != 20) {
                free(code);
                cJSON_Delete(json);
                *status_code = MHD_HTTP_BAD_REQUEST;
                return strdup("{\"error\":\"Invalid deployer address hex encoding\"}");
            }
        }
    }

    // Deploy contract
    mxd_contract_state_t state;
    int result = mxd_deploy_contract(code, code_len / 2, deployer, &state);
    free(code);
    cJSON_Delete(json);

    if (result != 0) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Contract deployment failed\",\"details\":\"Check node logs for details\"}");
    }

    // Convert contract hash to hex
    char hash_hex[129] = {0};
    for (int i = 0; i < 64; i++) {
        snprintf(hash_hex + i*2, 3, "%02x", state.contract_hash[i]);
    }

    // Build success response
    char *response = malloc(512);
    snprintf(response, 512,
        "{\"success\":true,\"contract_hash\":\"%s\",\"gas_used\":%llu}",
        hash_hex, (unsigned long long)state.gas_used);

    return response;
}

// Handle POST /contract/call - Call a contract function
static char* handle_contract_call(const char *post_data, int *status_code) {
    *status_code = MHD_HTTP_OK;

    if (!post_data) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"No POST data provided\"}");
    }

    // Parse JSON input
    cJSON *json = cJSON_Parse(post_data);
    if (!json) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid JSON\"}");
    }

    // Extract contract_hash (hex string)
    cJSON *hash_item = cJSON_GetObjectItem(json, "contract_hash");
    if (!hash_item || !cJSON_IsString(hash_item)) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Missing or invalid 'contract_hash' field\"}");
    }

    const char *hash_hex = hash_item->valuestring;
    uint8_t contract_hash[64];
    if (hex_to_bytes(hash_hex, contract_hash, 64) != 64) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid contract_hash format (expected 128 hex chars)\"}");
    }

    // Extract function name
    cJSON *function_item = cJSON_GetObjectItem(json, "function");
    if (!function_item || !cJSON_IsString(function_item)) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Missing or invalid 'function' field\"}");
    }

    // Copy function name before freeing JSON
    char *function_name = strdup(function_item->valuestring);
    if (!function_name) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }

    // Extract params (optional, hex string)
    const char *params_hex = "";
    cJSON *params_item = cJSON_GetObjectItem(json, "params");
    if (params_item && cJSON_IsString(params_item)) {
        params_hex = params_item->valuestring;
    }

    // Convert params to bytes
    size_t params_len = strlen(params_hex);
    uint8_t *params = NULL;
    if (params_len > 0) {
        // SECURITY FIX: Limit params size to prevent DoS (1MB max = 2MB hex)
        if (params_len > MXD_MAX_CONTRACT_SIZE * 2) {
            free(function_name);
            cJSON_Delete(json);
            *status_code = MHD_HTTP_BAD_REQUEST;
            return strdup("{\"error\":\"Params too large (max 1MB)\"}");
        }

        if (params_len % 2 != 0) {
            free(function_name);
            cJSON_Delete(json);
            *status_code = MHD_HTTP_BAD_REQUEST;
            return strdup("{\"error\":\"Invalid params hex encoding\"}");
        }
        params = malloc(params_len / 2);
        if (!params) {
            free(function_name);
            cJSON_Delete(json);
            *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
            return strdup("{\"error\":\"Memory allocation failed\"}");
        }
        if (hex_to_bytes(params_hex, params, params_len / 2) != (int)(params_len / 2)) {
            free(function_name);
            free(params);
            cJSON_Delete(json);
            *status_code = MHD_HTTP_BAD_REQUEST;
            return strdup("{\"error\":\"Invalid params hex encoding\"}");
        }
        params_len /= 2;
    }

    cJSON_Delete(json);

    // Load contract metadata from database
    mxd_contract_metadata_t contract_metadata;
    memset(&contract_metadata, 0, sizeof(contract_metadata));

    if (mxd_contracts_db_load_contract(contract_hash, &contract_metadata) != 0) {
        free(function_name);
        if (params) free(params);
        *status_code = MHD_HTTP_NOT_FOUND;
        return strdup("{\"error\":\"Contract not found in database\"}");
    }

    // Use existing deploy function to properly initialize the state
    mxd_contract_state_t state;
    memset(&state, 0, sizeof(state));

    uint8_t zero_address[20] = {0};
    if (mxd_deploy_contract(contract_metadata.bytecode, contract_metadata.bytecode_size,
                           zero_address, &state) != 0) {
        free(function_name);
        free(contract_metadata.bytecode);
        if (params) free(params);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to initialize contract runtime\"}");
    }

    // Free contract metadata bytecode (state has its own copy)
    free(contract_metadata.bytecode);

    // Find the requested function
    IM3Runtime runtime = (IM3Runtime)state.runtime;
    IM3Function func;
    M3Result result = m3_FindFunction(&func, runtime, function_name);
    if (result) {
        free(function_name);
        if (params) free(params);
        mxd_free_contract_state(&state);

        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg),
                "{\"error\":\"Function not found\",\"function\":\"%s\",\"details\":\"%s\"}",
                function_name, result);
        *status_code = MHD_HTTP_NOT_FOUND;
        return strdup(error_msg);
    }

    // Function name no longer needed after finding function
    free(function_name);

    // Calculate gas cost
    uint64_t gas_used = mxd_calculate_gas_from_bytecode(state.bytecode, state.bytecode_size);
    if (gas_used == 0) {
        gas_used = 1000 + (state.bytecode_size / 10) + (params_len * 2);
    }

    // Execute function based on parameters
    uint32_t ret = 0;

    if (params_len == 0) {
        // No parameters
        result = m3_CallV(func);
    } else if (params_len == 4) {
        // One i32 parameter
        uint32_t param1;
        memcpy(&param1, params, 4);
        result = m3_CallV(func, param1);
    } else if (params_len == 8) {
        // Two i32 parameters
        uint32_t param1, param2;
        memcpy(&param1, params, 4);
        memcpy(&param2, params + 4, 4);
        result = m3_CallV(func, param1, param2);
    } else {
        if (params) free(params);
        mxd_free_contract_state(&state);

        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Unsupported parameter size (must be 0, 4, or 8 bytes for i32 functions)\"}");
    }

    if (params) free(params);

    if (result) {
        mxd_free_contract_state(&state);

        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg),
                "{\"error\":\"Contract execution failed\",\"details\":\"%s\"}", result);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup(error_msg);
    }

    // Get result
    result = m3_GetResultsV(func, &ret);
    if (result) {
        mxd_free_contract_state(&state);

        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg),
                "{\"error\":\"Failed to get function result\",\"details\":\"%s\"}", result);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup(error_msg);
    }

    // Build JSON response
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", 1);
    cJSON_AddNumberToObject(response, "result", ret);
    cJSON_AddNumberToObject(response, "gas_used", gas_used);

    // Convert result to hex
    char result_hex[9] = {0};
    snprintf(result_hex, sizeof(result_hex), "%08x", ret);
    cJSON_AddStringToObject(response, "result_hex", result_hex);

    char *response_str = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);

    // Cleanup
    mxd_free_contract_state(&state);

    *status_code = MHD_HTTP_OK;
    return response_str;
}

// Handle GET /contracts - List all deployed contracts
static char* handle_contracts_list(int *status_code) {
    *status_code = MHD_HTTP_OK;

    // Query database for all contracts
    mxd_contract_metadata_t *contracts = NULL;
    uint32_t count = 0;

    if (mxd_contracts_db_get_all_contracts(&contracts, &count) != 0) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to query contracts database\"}");
    }

    // Build JSON response
    cJSON *root = cJSON_CreateObject();
    cJSON *contracts_array = cJSON_CreateArray();

    for (uint32_t i = 0; i < count; i++) {
        cJSON *contract_obj = cJSON_CreateObject();

        // Convert hash to hex
        char hash_hex[129] = {0};
        for (int j = 0; j < 64; j++) {
            snprintf(hash_hex + j*2, 3, "%02x", contracts[i].contract_hash[j]);
        }
        cJSON_AddStringToObject(contract_obj, "hash", hash_hex);

        // Convert deployer to hex
        char deployer_hex[41] = {0};
        for (int j = 0; j < 20; j++) {
            snprintf(deployer_hex + j*2, 3, "%02x", contracts[i].deployer[j]);
        }
        cJSON_AddStringToObject(contract_obj, "deployer", deployer_hex);

        cJSON_AddNumberToObject(contract_obj, "deployed_at", contracts[i].deployed_at);
        cJSON_AddNumberToObject(contract_obj, "deployed_timestamp", contracts[i].deployed_timestamp);
        cJSON_AddNumberToObject(contract_obj, "bytecode_size", contracts[i].bytecode_size);
        cJSON_AddNumberToObject(contract_obj, "total_gas_used", contracts[i].total_gas_used);
        cJSON_AddNumberToObject(contract_obj, "call_count", contracts[i].call_count);

        cJSON_AddItemToArray(contracts_array, contract_obj);

        // Free bytecode if allocated
        if (contracts[i].bytecode) {
            free(contracts[i].bytecode);
        }
    }

    cJSON_AddItemToObject(root, "contracts", contracts_array);
    cJSON_AddNumberToObject(root, "count", count);

    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    // Free contracts array
    if (contracts) {
        free(contracts);
    }

    return json_str;
}

// Handle GET /contract/{hash} - Get contract info
static char* handle_contract_info(const char *hash_hex, int *status_code) {
    *status_code = MHD_HTTP_OK;

    if (strlen(hash_hex) != 128) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid contract hash (expected 128 hex chars)\"}");
    }

    uint8_t contract_hash[64];
    if (hex_to_bytes(hash_hex, contract_hash, 64) != 64) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid contract hash format\"}");
    }

    // TODO: Query database for contract info
    // For now, return not found

    *status_code = MHD_HTTP_NOT_FOUND;
    return strdup("{\"error\":\"Contract not found\",\"note\":\"Contract storage not yet implemented\"}");
}

// Handle GET /contract/{hash}/state - Get contract state
static char* handle_contract_state(const char *hash_hex, int *status_code) {
    *status_code = MHD_HTTP_OK;

    if (strlen(hash_hex) != 128) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid contract hash (expected 128 hex chars)\"}");
    }

    uint8_t contract_hash[64];
    if (hex_to_bytes(hash_hex, contract_hash, 64) != 64) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid contract hash format\"}");
    }

    // TODO: Query database for contract state
    // For now, return not found

    *status_code = MHD_HTTP_NOT_FOUND;
    return strdup("{\"error\":\"Contract not found\",\"note\":\"Contract storage not yet implemented\"}");
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
    
    // Handle POST data accumulation
    if (strcmp(method, "POST") == 0) {
        if (*con_cls == NULL) {
            // First call - allocate connection context
            connection_info_t *con_info = calloc(1, sizeof(connection_info_t));
            if (!con_info) return MHD_NO;
            *con_cls = con_info;
            return MHD_YES;
        }
        
        connection_info_t *con_info = *con_cls;
        
        if (*upload_data_size > 0) {
            // Accumulate POST data
            char *new_data = realloc(con_info->post_data, con_info->post_data_size + *upload_data_size + 1);
            if (!new_data) return MHD_NO;
            memcpy(new_data + con_info->post_data_size, upload_data, *upload_data_size);
            con_info->post_data_size += *upload_data_size;
            new_data[con_info->post_data_size] = '\0';
            con_info->post_data = new_data;
            *upload_data_size = 0;
            return MHD_YES;
        }
        
        // All data received - process request
        char *json_response = NULL;
        int status_code = MHD_HTTP_OK;

        if (strcmp(url, "/transaction") == 0) {
            json_response = handle_transaction_submit(con_info->post_data, &status_code);
        }
        else if (strcmp(url, "/contract/deploy") == 0) {
            json_response = handle_contract_deploy(con_info->post_data, &status_code);
        }
        else if (strcmp(url, "/contract/call") == 0) {
            json_response = handle_contract_call(con_info->post_data, &status_code);
        }
        else {
            json_response = strdup("{\"error\":\"Endpoint not found\"}");
            status_code = MHD_HTTP_NOT_FOUND;
        }
        
        // Clean up connection context
        free(con_info->post_data);
        free(con_info);
        *con_cls = NULL;
        
        struct MHD_Response *response = MHD_create_response_from_buffer(
            strlen(json_response), json_response, MHD_RESPMEM_MUST_FREE);
        MHD_add_response_header(response, "Content-Type", "application/json");
        MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
        enum MHD_Result ret = MHD_queue_response(connection, status_code, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    // Handle OPTIONS for CORS preflight
    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    }
    
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

        // Get latest block and calculate statistics
        char latest_hash[129] = {0};
        uint64_t total_transactions = 0;
        double avg_block_time = 0.0;
        double current_tps = 0.0;
        uint32_t validator_count = 0;
        uint32_t difficulty = 1;
        uint64_t total_supply = 0;

        // Get validator count from rapid table
        const mxd_rapid_table_t *table = mxd_get_rapid_table();
        if (table) {
            validator_count = (uint32_t)table->count;
        }

        if (height > 0) {
            // Get latest block for hash
            mxd_block_t block;
            if (mxd_retrieve_block_by_height(height - 1, &block) == 0) {
                for (int i = 0; i < 64; i++) {
                    snprintf(latest_hash + i*2, 3, "%02x", block.block_hash[i]);
                }
                difficulty = block.difficulty;
                total_supply = block.total_supply;
                mxd_free_block(&block);
            }

            // Calculate stats from recent blocks (last 100 or all)
            uint32_t sample_size = (height > 100) ? 100 : height;
            uint64_t first_timestamp = 0;
            uint64_t last_timestamp = 0;

            for (uint32_t i = 0; i < sample_size; i++) {
                uint32_t bh = height - 1 - i;
                mxd_block_t b = {0};
                if (mxd_retrieve_block_by_height(bh, &b) == 0) {
                    total_transactions += b.transaction_count;
                    if (i == 0) last_timestamp = b.timestamp;
                    if (i == sample_size - 1 || bh == 0) first_timestamp = b.timestamp;
                    mxd_free_block(&b);
                }
                if (bh == 0) break;
            }

            // Average block time
            if (sample_size > 1 && last_timestamp > first_timestamp) {
                avg_block_time = (double)(last_timestamp - first_timestamp) / (double)(sample_size - 1);
            }

            // TPS
            if (last_timestamp > first_timestamp) {
                uint64_t time_span = last_timestamp - first_timestamp;
                if (time_span > 0) {
                    current_tps = (double)total_transactions / (double)time_span;
                }
            }
        } else {
            // Check for genesis block at height 0
            mxd_block_t block;
            if (mxd_retrieve_block_by_height(0, &block) == 0) {
                for (int i = 0; i < 64; i++) {
                    snprintf(latest_hash + i*2, 3, "%02x", block.block_hash[i]);
                }
                height = 1;
                total_supply = block.total_supply;
                total_transactions = block.transaction_count;
                mxd_free_block(&block);
            }
        }

        json_response = malloc(1024);
        if (json_response) {
            snprintf(json_response, 1024,
                "{\"status\":\"ok\","
                "\"height\":%u,"
                "\"latest_hash\":\"%s\","
                "\"total_transactions\":%llu,"
                "\"validator_count\":%u,"
                "\"difficulty\":%u,"
                "\"total_supply\":%llu,"
                "\"avg_block_time\":%.2f,"
                "\"current_tps\":%.4f}",
                height, latest_hash,
                (unsigned long long)total_transactions,
                validator_count, difficulty,
                (unsigned long long)total_supply,
                avg_block_time, current_tps);
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
    // Handle /balance/{address} endpoint
    else if (strncmp(url, "/balance/", 9) == 0) {
        const char *address_hex = url + 9;
        json_response = handle_balance(address_hex, &status_code);
    }
    // Handle /wallet/generate endpoint
    else if (strcmp(url, "/wallet/generate") == 0) {
        json_response = handle_wallet_generate(&status_code);
    }
    // Handle /validators endpoint
    else if (strcmp(url, "/validators") == 0) {
        json_response = handle_validators(&status_code);
    }
    // Handle /rsc endpoint - full rapid stake table
    else if (strcmp(url, "/rsc") == 0) {
        json_response = handle_rsc(&status_code);
    }
    // Handle /node/identity endpoint - for testing transactions
    else if (strcmp(url, "/node/identity") == 0) {
        json_response = handle_node_identity(&status_code);
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
    // Handle /contracts endpoint - list all contracts
    else if (strcmp(url, "/contracts") == 0) {
        json_response = handle_contracts_list(&status_code);
    }
    // Handle /contract/{hash} endpoint - get contract info
    else if (strncmp(url, "/contract/", 10) == 0 && strlen(url) == 138) {
        const char *hash_hex = url + 10;
        // Check if it's a state query
        if (strlen(url) > 138 && strcmp(url + 138, "/state") == 0) {
            json_response = handle_contract_state(hash_hex, &status_code);
        } else {
            json_response = handle_contract_info(hash_hex, &status_code);
        }
    }
    // Handle /contract/{hash}/state endpoint
    else if (strncmp(url, "/contract/", 10) == 0 && strlen(url) > 138) {
        const char *remainder = url + 10;
        char hash_hex[129];
        strncpy(hash_hex, remainder, 128);
        hash_hex[128] = '\0';
        if (strcmp(remainder + 128, "/state") == 0) {
            json_response = handle_contract_state(hash_hex, &status_code);
        } else {
            json_response = strdup("{\"error\":\"Endpoint not found\"}");
            status_code = MHD_HTTP_NOT_FOUND;
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

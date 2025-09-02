#include "mxd_bridge.h"
#include "utils/mxd_http.h"
#include "mxd_transaction.h"
#include "mxd_smart_contracts.h"
#include "mxd_crypto.h"
#include "mxd_logging.h"
#include "mxd_utxo.h"
#include "mxd_rocksdb_globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include <time.h>
#include <rocksdb/c.h>

static int bridge_initialized = 0;
static mxd_bridge_limits_t daily_limits = {0};

int mxd_init_bridge(void) {
    if (bridge_initialized) {
        return 0;
    }
    
    daily_limits.daily_total = 0.0;
    daily_limits.reset_timestamp = time(NULL) + 86400;
    
    bridge_initialized = 1;
    MXD_LOG_INFO("bridge", "Bridge system initialized");
    return 0;
}

void mxd_cleanup_bridge(void) {
    bridge_initialized = 0;
    MXD_LOG_INFO("bridge", "Bridge system cleaned up");
}

int mxd_validate_bnb_transaction(const char *tx_hash, mxd_bsc_transaction_t *tx_info) {
    if (!tx_hash || !tx_info || !bridge_initialized) {
        return -1;
    }
    
    char url[512];
    snprintf(url, sizeof(url), "%s", MXD_BRIDGE_BSC_RPC_URL);
    
    char json_payload[1024];
    snprintf(json_payload, sizeof(json_payload),
        "{"
        "\"jsonrpc\":\"2.0\","
        "\"method\":\"eth_getTransactionByHash\","
        "\"params\":[\"%s\"],"
        "\"id\":1"
        "}", tx_hash);
    
    mxd_http_response_t *response = mxd_http_post(url, json_payload, "application/json");
    if (!response || response->status_code != 200) {
        MXD_LOG_ERROR("bridge", "Failed to fetch BNB transaction: %s", tx_hash);
        if (response) mxd_http_free_response(response);
        return -1;
    }
    
    cJSON *root = cJSON_Parse(response->data);
    if (!root) {
        MXD_LOG_ERROR("bridge", "Failed to parse JSON response");
        mxd_http_free_response(response);
        return -1;
    }
    
    cJSON *result = cJSON_GetObjectItem(root, "result");
    if (!result) {
        MXD_LOG_ERROR("bridge", "Transaction not found: %s", tx_hash);
        cJSON_Delete(root);
        mxd_http_free_response(response);
        return -1;
    }
    
    cJSON *block_number_obj = cJSON_GetObjectItem(result, "blockNumber");
    if (block_number_obj && cJSON_IsString(block_number_obj)) {
        const char *block_hex = cJSON_GetStringValue(block_number_obj);
        tx_info->block_number = strtoull(block_hex, NULL, 16);
    }
    
    cJSON *from_obj = cJSON_GetObjectItem(result, "from");
    if (from_obj && cJSON_IsString(from_obj)) {
        strncpy(tx_info->from_address, cJSON_GetStringValue(from_obj), 42);
        tx_info->from_address[42] = '\0';
    }
    
    cJSON *to_obj = cJSON_GetObjectItem(result, "to");
    if (to_obj && cJSON_IsString(to_obj)) {
        strncpy(tx_info->to_address, cJSON_GetStringValue(to_obj), 42);
        tx_info->to_address[42] = '\0';
    }
    
    cJSON *input_obj = cJSON_GetObjectItem(result, "input");
    if (input_obj && cJSON_IsString(input_obj)) {
        strncpy(tx_info->input_data, cJSON_GetStringValue(input_obj), 2047);
        tx_info->input_data[2047] = '\0';
    }
    
    strncpy(tx_info->tx_hash, tx_hash, 66);
    tx_info->tx_hash[66] = '\0';
    
    cJSON_Delete(root);
    mxd_http_free_response(response);
    
    return mxd_get_block_confirmations(tx_info->block_number, &tx_info->confirmations);
}

int mxd_get_block_confirmations(uint64_t block_number, uint64_t *confirmations) {
    if (!confirmations || !bridge_initialized) {
        return -1;
    }
    
    char url[512];
    snprintf(url, sizeof(url), "%s", MXD_BRIDGE_BSC_RPC_URL);
    
    char json_payload[256];
    snprintf(json_payload, sizeof(json_payload),
        "{"
        "\"jsonrpc\":\"2.0\","
        "\"method\":\"eth_blockNumber\","
        "\"params\":[],"
        "\"id\":1"
        "}");
    
    mxd_http_response_t *response = mxd_http_post(url, json_payload, "application/json");
    if (!response || response->status_code != 200) {
        MXD_LOG_ERROR("bridge", "Failed to fetch latest block number");
        if (response) mxd_http_free_response(response);
        return -1;
    }
    
    cJSON *root = cJSON_Parse(response->data);
    if (!root) {
        MXD_LOG_ERROR("bridge", "Failed to parse block number response");
        mxd_http_free_response(response);
        return -1;
    }
    
    cJSON *result = cJSON_GetObjectItem(root, "result");
    if (result && cJSON_IsString(result)) {
        const char *latest_hex = cJSON_GetStringValue(result);
        uint64_t latest_block = strtoull(latest_hex, NULL, 16);
        *confirmations = (latest_block > block_number) ? (latest_block - block_number) : 0;
    } else {
        *confirmations = 0;
    }
    
    cJSON_Delete(root);
    mxd_http_free_response(response);
    return 0;
}

int mxd_check_daily_limits(double amount) {
    if (!bridge_initialized || amount <= 0) {
        return -1;
    }
    
    time_t current_time = time(NULL);
    
    if (current_time >= daily_limits.reset_timestamp) {
        daily_limits.daily_total = 0.0;
        daily_limits.reset_timestamp = current_time + 86400;
    }
    
    if (daily_limits.daily_total + amount > MXD_BRIDGE_DAILY_LIMIT) {
        MXD_LOG_WARN("bridge", "Daily limit exceeded: %.2f + %.2f > %.2f", 
                     daily_limits.daily_total, amount, MXD_BRIDGE_DAILY_LIMIT);
        return -1;
    }
    
    if (amount > MXD_BRIDGE_MAX_SINGLE_TRANSFER) {
        MXD_LOG_WARN("bridge", "Single transfer limit exceeded: %.2f > %.2f", 
                     amount, MXD_BRIDGE_MAX_SINGLE_TRANSFER);
        return -1;
    }
    
    return 0;
}

int mxd_mint_bridged_mxd(const uint8_t recipient_key[256], double amount) {
    if (!recipient_key || amount <= 0 || !bridge_initialized) {
        return -1;
    }
    
    mxd_transaction_t tx;
    if (mxd_create_coinbase_transaction(&tx, recipient_key, amount) != 0) {
        MXD_LOG_ERROR("bridge", "Failed to create coinbase transaction for bridge mint");
        return -1;
    }
    
    if (mxd_validate_transaction(&tx) != 0) {
        MXD_LOG_ERROR("bridge", "Bridge coinbase transaction validation failed");
        mxd_free_transaction(&tx);
        return -1;
    }
    
    if (mxd_apply_transaction_to_utxo(&tx) != 0) {
        MXD_LOG_ERROR("bridge", "Failed to apply bridge transaction to UTXO");
        mxd_free_transaction(&tx);
        return -1;
    }
    
    daily_limits.daily_total += amount;
    
    MXD_LOG_INFO("bridge", "Successfully minted %.2f MXD for bridge transfer", amount);
    mxd_free_transaction(&tx);
    return 0;
}

int mxd_parse_bridge_event(const char *log_data, mxd_bridge_transfer_t *transfer) {
    if (!log_data || !transfer || !bridge_initialized) {
        return -1;
    }
    
    cJSON *root = cJSON_Parse(log_data);
    if (!root) {
        MXD_LOG_ERROR("bridge", "Failed to parse bridge event log");
        return -1;
    }
    
    cJSON *sender_obj = cJSON_GetObjectItem(root, "sender");
    if (sender_obj && cJSON_IsString(sender_obj)) {
        strncpy(transfer->bnb_sender, cJSON_GetStringValue(sender_obj), 42);
        transfer->bnb_sender[42] = '\0';
    }
    
    cJSON *recipient_obj = cJSON_GetObjectItem(root, "mxdRecipient");
    if (recipient_obj && cJSON_IsString(recipient_obj)) {
        const char *recipient_str = cJSON_GetStringValue(recipient_obj);
        if (mxd_extract_mxd_recipient(recipient_str, transfer->mxd_recipient) != 0) {
            MXD_LOG_ERROR("bridge", "Failed to extract MXD recipient address");
            cJSON_Delete(root);
            return -1;
        }
    }
    
    cJSON *amount_obj = cJSON_GetObjectItem(root, "amount");
    if (amount_obj && cJSON_IsString(amount_obj)) {
        const char *amount_str = cJSON_GetStringValue(amount_obj);
        transfer->amount = strtod(amount_str, NULL) / 1e18;
    }
    
    cJSON *transfer_id_obj = cJSON_GetObjectItem(root, "transferId");
    if (transfer_id_obj && cJSON_IsString(transfer_id_obj)) {
        const char *id_str = cJSON_GetStringValue(transfer_id_obj);
        if (strlen(id_str) >= 2 && id_str[0] == '0' && id_str[1] == 'x') {
            for (int i = 0; i < 32 && (i * 2 + 2) < strlen(id_str); i++) {
                sscanf(&id_str[i * 2 + 2], "%2hhx", &transfer->transfer_id[i]);
            }
        }
    }
    
    cJSON *timestamp_obj = cJSON_GetObjectItem(root, "timestamp");
    if (timestamp_obj && cJSON_IsNumber(timestamp_obj)) {
        transfer->timestamp = (uint64_t)cJSON_GetNumberValue(timestamp_obj);
    }
    
    transfer->status = 0;
    
    cJSON_Delete(root);
    return 0;
}

int mxd_extract_mxd_recipient(const char *input_data, uint8_t recipient_key[256]) {
    if (!input_data || !recipient_key) {
        return -1;
    }
    
    size_t len = strlen(input_data);
    if (len < 64) {
        return -1;
    }
    
    for (int i = 0; i < 256 && (i * 2) < len; i++) {
        if (sscanf(&input_data[i * 2], "%2hhx", &recipient_key[i]) != 1) {
            return -1;
        }
    }
    
    return 0;
}

int mxd_process_bridge_transfer(const mxd_bridge_transfer_t *transfer) {
    if (!transfer || !bridge_initialized) {
        return -1;
    }
    
    if (mxd_is_transfer_processed(transfer->transfer_id) == 1) {
        MXD_LOG_WARN("bridge", "Transfer already processed");
        return -1;
    }
    
    if (mxd_check_daily_limits(transfer->amount) != 0) {
        MXD_LOG_ERROR("bridge", "Transfer amount exceeds limits");
        return -1;
    }
    
    mxd_bsc_transaction_t tx_info;
    char tx_hash_str[67];
    snprintf(tx_hash_str, sizeof(tx_hash_str), "0x");
    for (int i = 0; i < 32; i++) {
        snprintf(&tx_hash_str[2 + i * 2], 3, "%02x", transfer->bnb_tx_hash[i]);
    }
    
    if (mxd_validate_bnb_transaction(tx_hash_str, &tx_info) != 0) {
        MXD_LOG_ERROR("bridge", "BNB transaction validation failed");
        return -1;
    }
    
    if (tx_info.confirmations < MXD_BRIDGE_MIN_CONFIRMATIONS) {
        MXD_LOG_INFO("bridge", "Insufficient confirmations: %lu < %d", 
                     tx_info.confirmations, MXD_BRIDGE_MIN_CONFIRMATIONS);
        return -2;
    }
    
    if (mxd_mint_bridged_mxd(transfer->mxd_recipient, transfer->amount) != 0) {
        MXD_LOG_ERROR("bridge", "Failed to mint MXD tokens");
        return -1;
    }
    
    if (mxd_store_processed_transfer(transfer->transfer_id) != 0) {
        MXD_LOG_WARN("bridge", "Failed to store processed transfer ID");
    }
    
    MXD_LOG_INFO("bridge", "Successfully processed bridge transfer: %.2f MXD", transfer->amount);
    return 0;
}

int mxd_store_processed_transfer(const uint8_t transfer_id[32]) {
    if (!transfer_id || !bridge_initialized || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    char key[82] = "bridge_processed_";
    for (int i = 0; i < 32; i++) {
        snprintf(&key[17 + i * 2], 3, "%02x", transfer_id[i]);
    }
    
    char *err = NULL;
    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), 
                key, strlen(key), "1", 1, &err);
    if (err) {
        MXD_LOG_ERROR("bridge", "Failed to store processed transfer: %s", err);
        free(err);
        return -1;
    }
    
    return 0;
}

int mxd_is_transfer_processed(const uint8_t transfer_id[32]) {
    if (!transfer_id || !bridge_initialized || !mxd_get_rocksdb_db()) {
        return 0;
    }
    
    char key[82] = "bridge_processed_";
    for (int i = 0; i < 32; i++) {
        snprintf(&key[17 + i * 2], 3, "%02x", transfer_id[i]);
    }
    
    char *err = NULL;
    char *value = NULL;
    size_t value_len = 0;
    value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(), 
                        key, strlen(key), &value_len, &err);
    
    if (err) {
        MXD_LOG_ERROR("bridge", "Failed to check processed transfer: %s", err);
        free(err);
        return 0;
    }
    
    if (value && value_len > 0 && value[0] == '1') {
        free(value);
        return 1;
    }
    
    if (value) {
        free(value);
    }
    
    return 0;
}

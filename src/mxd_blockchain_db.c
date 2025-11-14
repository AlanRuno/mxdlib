#include "mxd_logging.h"

#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_rocksdb_globals.h"
#include "../include/blockchain/mxd_rsc.h"
#include "../include/mxd_endian.h"
#include <rocksdb/c.h>
#include <stdlib.h>
#include <string.h>

static rocksdb_options_t *options = NULL;
static char *db_path_global = NULL;

static uint32_t current_height = 0;

static int serialize_block(const mxd_block_t *block, uint8_t **data, size_t *data_len) {
    if (!block || !data || !data_len) {
        return -1;
    }

    size_t size = 0;
    
    size += sizeof(uint32_t);  // version
    size += 64;                // prev_block_hash
    size += 64;                // merkle_root
    size += sizeof(time_t);    // timestamp
    size += sizeof(uint32_t);  // difficulty
    size += sizeof(uint64_t);  // nonce
    size += 64;                // block_hash
    size += 20;                // proposer_id
    size += sizeof(uint32_t);  // height
    size += sizeof(uint32_t);  // validation_count
    size += sizeof(uint32_t);  // rapid_membership_count
    size += sizeof(double);    // total_supply
    size += sizeof(uint8_t);   // transaction_set_frozen
    
    if (block->validation_count > 0 && block->validation_chain) {
        size += block->validation_count * sizeof(mxd_validator_signature_t);
    }
    
    if (block->rapid_membership_count > 0 && block->rapid_membership_entries) {
        size += block->rapid_membership_count * sizeof(mxd_rapid_membership_entry_t);
    }

    *data = malloc(size);
    if (!*data) {
        return -1;
    }

    uint8_t *ptr = *data;
    
    memcpy(ptr, &block->version, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(ptr, block->prev_block_hash, 64); ptr += 64;
    memcpy(ptr, block->merkle_root, 64); ptr += 64;
    memcpy(ptr, &block->timestamp, sizeof(time_t)); ptr += sizeof(time_t);
    memcpy(ptr, &block->difficulty, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(ptr, &block->nonce, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    memcpy(ptr, block->block_hash, 64); ptr += 64;
    memcpy(ptr, block->proposer_id, 20); ptr += 20;
    memcpy(ptr, &block->height, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(ptr, &block->validation_count, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(ptr, &block->rapid_membership_count, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(ptr, &block->total_supply, sizeof(double)); ptr += sizeof(double);
    memcpy(ptr, &block->transaction_set_frozen, sizeof(uint8_t)); ptr += sizeof(uint8_t);
    
    if (block->validation_count > 0 && block->validation_chain) {
        memcpy(ptr, block->validation_chain, 
               block->validation_count * sizeof(mxd_validator_signature_t));
        ptr += block->validation_count * sizeof(mxd_validator_signature_t);
    }
    
    if (block->rapid_membership_count > 0 && block->rapid_membership_entries) {
        memcpy(ptr, block->rapid_membership_entries,
               block->rapid_membership_count * sizeof(mxd_rapid_membership_entry_t));
        ptr += block->rapid_membership_count * sizeof(mxd_rapid_membership_entry_t);
    }

    *data_len = size;
    return 0;
}

static int deserialize_block(const uint8_t *data, size_t data_len, mxd_block_t *block) {
    if (!data || !block) {
        return -1;
    }

    size_t min_size = sizeof(uint32_t) + 64 + 64 + sizeof(time_t) + sizeof(uint32_t) + 
                      sizeof(uint64_t) + 64 + 20 + sizeof(uint32_t) + sizeof(uint32_t) + 
                      sizeof(uint32_t) + sizeof(double) + sizeof(uint8_t);
    
    if (data_len < min_size) {
        return -1;
    }

    const uint8_t *ptr = data;
    
    memcpy(&block->version, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(block->prev_block_hash, ptr, 64); ptr += 64;
    memcpy(block->merkle_root, ptr, 64); ptr += 64;
    memcpy(&block->timestamp, ptr, sizeof(time_t)); ptr += sizeof(time_t);
    memcpy(&block->difficulty, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(&block->nonce, ptr, sizeof(uint64_t)); ptr += sizeof(uint64_t);
    memcpy(block->block_hash, ptr, 64); ptr += 64;
    memcpy(block->proposer_id, ptr, 20); ptr += 20;
    memcpy(&block->height, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(&block->validation_count, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(&block->rapid_membership_count, ptr, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(&block->total_supply, ptr, sizeof(double)); ptr += sizeof(double);
    memcpy(&block->transaction_set_frozen, ptr, sizeof(uint8_t)); ptr += sizeof(uint8_t);
    
    block->validation_chain = NULL;
    block->validation_capacity = 0;
    block->rapid_membership_entries = NULL;
    block->rapid_membership_capacity = 0;
    
    if (block->validation_count > 0) {
        size_t validation_size = block->validation_count * sizeof(mxd_validator_signature_t);
        if ((size_t)(ptr - data) + validation_size > data_len) {
            return -1;
        }
        
        block->validation_chain = malloc(validation_size);
        if (!block->validation_chain) {
            return -1;
        }
        memcpy(block->validation_chain, ptr, validation_size);
        ptr += validation_size;
        block->validation_capacity = block->validation_count;
    }
    
    if (block->rapid_membership_count > 0) {
        size_t membership_size = block->rapid_membership_count * sizeof(mxd_rapid_membership_entry_t);
        if ((size_t)(ptr - data) + membership_size > data_len) {
            if (block->validation_chain) {
                free(block->validation_chain);
                block->validation_chain = NULL;
            }
            return -1;
        }
        
        block->rapid_membership_entries = malloc(membership_size);
        if (!block->rapid_membership_entries) {
            if (block->validation_chain) {
                free(block->validation_chain);
                block->validation_chain = NULL;
            }
            return -1;
        }
        memcpy(block->rapid_membership_entries, ptr, membership_size);
        ptr += membership_size;
        block->rapid_membership_capacity = block->rapid_membership_count;
    }

    return 0;
}

static void create_block_height_key(uint32_t height, uint8_t *key, size_t *key_len) {
    memcpy(key, "block:height:", 13);
    memcpy(key + 13, &height, sizeof(uint32_t));
    *key_len = 13 + sizeof(uint32_t);
}

static void create_block_hash_key(const uint8_t hash[64], uint8_t *key, size_t *key_len) {
    memcpy(key, "block:hash:", 11);
    memcpy(key + 11, hash, 64);
    *key_len = 11 + 64;
}

static void create_signature_key(uint32_t height, const uint8_t validator_id[20], uint8_t *key, size_t *key_len) {
    memcpy(key, "sig:", 4);
    memcpy(key + 4, &height, sizeof(uint32_t));
    memcpy(key + 4 + sizeof(uint32_t), validator_id, 20);
    *key_len = 4 + sizeof(uint32_t) + 20;
}

static void create_validator_key(const uint8_t validator_id[20], uint8_t *key, size_t *key_len) {
    memcpy(key, "validator:", 10);
    memcpy(key + 10, validator_id, 20);
    *key_len = 10 + 20;
}

int mxd_init_blockchain_db(const char *db_path) {
    if (!db_path) return -1;
    
    if (db_path_global) free(db_path_global);
    db_path_global = strdup(db_path);
    
    options = rocksdb_options_create();
    mxd_set_rocksdb_readoptions(rocksdb_readoptions_create());
    mxd_set_rocksdb_writeoptions(rocksdb_writeoptions_create());
    
    rocksdb_options_set_create_if_missing(options, 1);
    rocksdb_options_set_compression(options, rocksdb_lz4_compression);
    
    size_t write_buffer_size = 32 * 1024 * 1024; // 32MB (reduced from 128MB)
    int max_write_buffer_number = 2; // 2 (reduced from 4)
    size_t block_cache_size = 64 * 1024 * 1024; // 64MB (reduced from 256MB)
    
    rocksdb_options_set_write_buffer_size(options, write_buffer_size);
    rocksdb_options_set_max_write_buffer_number(options, max_write_buffer_number);
    rocksdb_options_set_target_file_size_base(options, 32 * 1024 * 1024); // 32MB (reduced from 64MB)
    rocksdb_options_set_level_compaction_dynamic_level_bytes(options, 1);
    rocksdb_options_set_max_open_files(options, 200); // Limit open file handles
    rocksdb_options_set_max_background_jobs(options, 2); // Limit concurrent compaction memory
    
    MXD_LOG_INFO("blockchain_db", "RocksDB Blockchain settings: write_buffer=%zu MB, max_buffers=%d, block_cache=%zu MB, total_est=%zu MB",
                 write_buffer_size / (1024*1024), max_write_buffer_number, block_cache_size / (1024*1024),
                 (write_buffer_size * max_write_buffer_number + block_cache_size) / (1024*1024));
    
    rocksdb_cache_t *cache = rocksdb_cache_create_lru(block_cache_size);
    rocksdb_block_based_table_options_t *table_options = rocksdb_block_based_options_create();
    rocksdb_block_based_options_set_block_cache(table_options, cache);
    rocksdb_options_set_block_based_table_factory(options, table_options);
    
    rocksdb_readoptions_set_verify_checksums(mxd_get_rocksdb_readoptions(), 1);
    
    rocksdb_writeoptions_set_sync(mxd_get_rocksdb_writeoptions(), 1);
    
    char *err = NULL;
    mxd_set_rocksdb_db(rocksdb_open(options, db_path, &err));
    if (err) {
        MXD_LOG_ERROR("db", "Failed to open blockchain database: %s", err);
        free(err);
        return -1;
    }
    
    mxd_get_blockchain_height(&current_height);
    
    mxd_load_all_validator_metadata();
    
    return 0;
}

int mxd_close_blockchain_db(void) {
    if (!mxd_get_rocksdb_db()) {
        return -1;
    }
    
    rocksdb_close(mxd_get_rocksdb_db());
    mxd_set_rocksdb_db(NULL);
    
    rocksdb_options_destroy(options);
    rocksdb_readoptions_destroy(mxd_get_rocksdb_readoptions());
    rocksdb_writeoptions_destroy(mxd_get_rocksdb_writeoptions());
    options = NULL;
    mxd_set_rocksdb_readoptions(NULL);
    mxd_set_rocksdb_writeoptions(NULL);
    
    free(db_path_global);
    db_path_global = NULL;
    
    return 0;
}

int mxd_store_block(const mxd_block_t *block) {
    if (!block || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    uint8_t height_key[13 + sizeof(uint32_t)];
    size_t height_key_len;
    create_block_height_key(block->height, height_key, &height_key_len);
    
    uint8_t hash_key[11 + 64];
    size_t hash_key_len;
    create_block_hash_key(block->block_hash, hash_key, &hash_key_len);
    
    uint8_t *data = NULL;
    size_t data_len = 0;
    if (serialize_block(block, &data, &data_len) != 0) {
        return -1;
    }
    
    char *err = NULL;
    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), (char *)height_key, height_key_len, (char *)data, data_len, &err);
    if (err) {
        MXD_LOG_ERROR("db", "Failed to store block by height: %s", err);
        free(err);
        free(data);
        return -1;
    }
    
    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), (char *)hash_key, hash_key_len, (char *)data, data_len, &err);
    if (err) {
        MXD_LOG_ERROR("db", "Failed to store block by hash: %s", err);
        free(err);
        free(data);
        return -1;
    }
    
    for (uint32_t i = 0; i < block->validation_count; i++) {
        mxd_store_signature(block->height,
                            block->validation_chain[i].validator_id,
                            block->validation_chain[i].signature,
                            block->validation_chain[i].signature_length);
    }
    
    if (block->height > current_height) {
        current_height = block->height;
        
        uint8_t height_meta_key[] = "current_height";
        rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), (char *)height_meta_key, sizeof(height_meta_key) - 1, 
                   (char *)&current_height, sizeof(current_height), &err);
        if (err) {
            MXD_LOG_ERROR("db", "Failed to store current height: %s", err);
            free(err);
        }
    }
    
    free(data);
    return 0;
}

int mxd_retrieve_block_by_height(uint32_t height, mxd_block_t *block) {
    if (!block || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    uint8_t key[13 + sizeof(uint32_t)];
    size_t key_len;
    create_block_height_key(height, key, &key_len);
    
    char *err = NULL;
    char *value = NULL;
    size_t value_len = 0;
    value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(), (char *)key, key_len, &value_len, &err);
    if (err) {
        MXD_LOG_ERROR("db", "Failed to retrieve block by height: %s", err);
        free(err);
        return -1;
    }
    
    if (!value) {
        return -1; // Block not found
    }
    
    int result = deserialize_block((uint8_t *)value, value_len, block);
    
    free(value);
    return result;
}

int mxd_retrieve_block_by_hash(const uint8_t hash[64], mxd_block_t *block) {
    if (!hash || !block || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    uint8_t key[11 + 64];
    size_t key_len;
    create_block_hash_key(hash, key, &key_len);
    
    char *err = NULL;
    char *value = NULL;
    size_t value_len = 0;
    value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(), (char *)key, key_len, &value_len, &err);
    if (err) {
        MXD_LOG_ERROR("db", "Failed to retrieve block by hash: %s", err);
        free(err);
        return -1;
    }
    
    if (!value) {
        return -1; // Block not found
    }
    
    int result = deserialize_block((uint8_t *)value, value_len, block);
    
    free(value);
    return result;
}

int mxd_get_blockchain_height(uint32_t *height) {
    if (!height || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    uint8_t key[] = "current_height";
    char *err = NULL;
    char *value = NULL;
    size_t value_len = 0;
    value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(), (char *)key, sizeof(key) - 1, &value_len, &err);
    if (err) {
        MXD_LOG_ERROR("db", "Failed to retrieve current height: %s", err);
        free(err);
        *height = 0;
        return 0;
    }
    
    if (value && value_len == sizeof(uint32_t)) {
        memcpy(height, value, sizeof(uint32_t));
        current_height = *height;
        free(value);
    } else {
        *height = 0;
        current_height = 0;
        if (value) free(value);
    }
    
    return 0;
}

int mxd_store_signature(uint32_t height, const uint8_t validator_id[20], const uint8_t *signature, uint16_t signature_length) {
    if (!validator_id || !signature || !mxd_get_rocksdb_db() || signature_length == 0 || signature_length > MXD_SIGNATURE_MAX) {
        return -1;
    }
    
    uint8_t sig_key[4 + sizeof(uint32_t) + 20];
    size_t sig_key_len;
    create_signature_key(height, validator_id, sig_key, &sig_key_len);
    
    char *err = NULL;
    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), (char *)sig_key, sig_key_len, (char *)signature, signature_length, &err);
    if (err) {
        MXD_LOG_ERROR("db", "Failed to store signature: %s", err);
        free(err);
        return -1;
    }
    
    uint8_t validator_key[10 + 20 + sizeof(uint32_t)];
    size_t validator_key_len;
    create_validator_key(validator_id, validator_key, &validator_key_len);
    memcpy(validator_key + validator_key_len, &height, sizeof(uint32_t));
    validator_key_len += sizeof(uint32_t);
    
    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), (char *)validator_key, validator_key_len, "", 0, &err);
    if (err) {
        MXD_LOG_ERROR("db", "Failed to store validator signature index: %s", err);
        free(err);
        return -1;
    }
    
    return 0;
}

int mxd_signature_exists(uint32_t height, const uint8_t validator_id[20], const uint8_t *signature, uint16_t signature_length) {
    if (!validator_id || !signature || !mxd_get_rocksdb_db() || signature_length == 0 || signature_length > MXD_SIGNATURE_MAX) {
        return -1;
    }
    
    uint8_t key[4 + sizeof(uint32_t) + 20];
    size_t key_len;
    create_signature_key(height, validator_id, key, &key_len);
    
    char *err = NULL;
    char *value = NULL;
    size_t value_len = 0;
    value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(), (char *)key, key_len, &value_len, &err);
    if (err) {
        MXD_LOG_ERROR("db", "Failed to check signature: %s", err);
        free(err);
        return -1;
    }
    
    if (!value) {
        return 0; // Signature does not exist
    }
    
    int result = (value_len == signature_length && memcmp(value, signature, value_len) == 0) ? 1 : 0;
    
    free(value);
    return result;
}

int mxd_prune_expired_signatures(uint32_t current_height) {
    if (!mxd_get_rocksdb_db() || current_height < 5) {
        return -1;
    }
    
    uint32_t expiry_height = current_height - 5;
    
    rocksdb_iterator_t *iter = rocksdb_create_iterator(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions());
    rocksdb_iter_seek(iter, "sig:", 4);
    
    size_t pruned = 0;
    
    while (rocksdb_iter_valid(iter)) {
        size_t key_len;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        if (key_len > 4 && memcmp(key, "sig:", 4) == 0) {
            uint32_t height;
            memcpy(&height, key + 4, sizeof(uint32_t));
            
            if (height < expiry_height) {
                uint8_t validator_id[20];
                memcpy(validator_id, key + 4 + sizeof(uint32_t), 20);
                
                uint8_t validator_key[10 + 20 + sizeof(uint32_t)];
                size_t validator_key_len;
                create_validator_key(validator_id, validator_key, &validator_key_len);
                memcpy(validator_key + validator_key_len, &height, sizeof(uint32_t));
                validator_key_len += sizeof(uint32_t);
                
                char *err = NULL;
                rocksdb_delete(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), (char *)validator_key, validator_key_len, &err);
                if (err) {
                    MXD_LOG_ERROR("db", "Failed to remove validator signature index: %s", err);
                    free(err);
                }
                
                rocksdb_delete(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), key, key_len, &err);
                if (err) {
                    MXD_LOG_ERROR("db", "Failed to remove signature: %s", err);
                    free(err);
                } else {
                    pruned++;
                }
            }
        } else {
            break; // No more signatures
        }
        
        rocksdb_iter_next(iter);
    }
    
    rocksdb_iter_destroy(iter);
    
    return 0;
}

int mxd_get_signatures_by_height(uint32_t height, mxd_validator_signature_t **signatures, size_t *signature_count) {
    if (!signatures || !signature_count || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    uint8_t prefix_key[4 + sizeof(uint32_t)];
    memcpy(prefix_key, "sig:", 4);
    memcpy(prefix_key + 4, &height, sizeof(uint32_t));
    size_t prefix_key_len = 4 + sizeof(uint32_t);
    
    rocksdb_iterator_t *iter = rocksdb_create_iterator(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions());
    rocksdb_iter_seek(iter, (char *)prefix_key, prefix_key_len);
    
    size_t count = 0;
    while (rocksdb_iter_valid(iter)) {
        size_t key_len;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        if (key_len < prefix_key_len || memcmp(key, prefix_key, prefix_key_len) != 0) {
            break; // No more matches
        }
        
        count++;
        rocksdb_iter_next(iter);
    }
    
    *signatures = NULL;
    *signature_count = 0;
    if (count == 0) {
        rocksdb_iter_destroy(iter);
        return 0; // No signatures found
    }
    
    *signatures = malloc(count * sizeof(mxd_validator_signature_t));
    if (!*signatures) {
        rocksdb_iter_destroy(iter);
        return -1;
    }
    memset(*signatures, 0, count * sizeof(mxd_validator_signature_t));
    
    rocksdb_iter_seek(iter, (char *)prefix_key, prefix_key_len);
    
    size_t index = 0;
    while (rocksdb_iter_valid(iter) && index < count) {
        size_t key_len;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        if (key_len < prefix_key_len || memcmp(key, prefix_key, prefix_key_len) != 0) {
            break; // No more matches
        }
        
        memcpy((*signatures)[index].validator_id, key + prefix_key_len, 20);
        
        size_t value_len;
        const char *value = rocksdb_iter_value(iter, &value_len);
        if (value && value_len > 0 && value_len <= MXD_SIGNATURE_MAX) {
            (*signatures)[index].signature_length = (uint16_t)value_len;
            memcpy((*signatures)[index].signature, value, (*signatures)[index].signature_length);
            (*signatures)[index].chain_position = index;
            
            (*signatures)[index].timestamp = 0;
            
            index++;
        }
        
        rocksdb_iter_next(iter);
    }
    
    rocksdb_iter_destroy(iter);
    *signature_count = index;
    
    return 0;
}

int mxd_get_signatures_by_validator(const uint8_t validator_id[20], mxd_validator_signature_t **signatures, 
                                   uint32_t **heights, size_t *signature_count) {
    if (!validator_id || !signatures || !heights || !signature_count || !mxd_get_rocksdb_db()) {
        return -1;
    }
    
    uint8_t prefix_key[10 + 20];
    size_t prefix_key_len;
    create_validator_key(validator_id, prefix_key, &prefix_key_len);
    
    rocksdb_iterator_t *iter = rocksdb_create_iterator(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions());
    rocksdb_iter_seek(iter, (char *)prefix_key, prefix_key_len);
    
    size_t count = 0;
    while (rocksdb_iter_valid(iter)) {
        size_t key_len;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        if (key_len < prefix_key_len || memcmp(key, prefix_key, prefix_key_len) != 0) {
            break; // No more matches
        }
        
        count++;
        rocksdb_iter_next(iter);
    }
    
    *signatures = NULL;
    *heights = NULL;
    *signature_count = 0;
    if (count == 0) {
        rocksdb_iter_destroy(iter);
        return 0; // No signatures found
    }
    
    *signatures = malloc(count * sizeof(mxd_validator_signature_t));
    if (!*signatures) {
        rocksdb_iter_destroy(iter);
        return -1;
    }
    memset(*signatures, 0, count * sizeof(mxd_validator_signature_t));
    
    *heights = malloc(count * sizeof(uint32_t));
    if (!*heights) {
        free(*signatures);
        *signatures = NULL;
        rocksdb_iter_destroy(iter);
        return -1;
    }
    
    rocksdb_iter_seek(iter, (char *)prefix_key, prefix_key_len);
    
    size_t index = 0;
    while (rocksdb_iter_valid(iter) && index < count) {
        size_t key_len;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        if (key_len < prefix_key_len || memcmp(key, prefix_key, prefix_key_len) != 0) {
            break; // No more matches
        }
        
        uint32_t height;
        memcpy(&height, key + prefix_key_len, sizeof(uint32_t));
        (*heights)[index] = height;
        
        memcpy((*signatures)[index].validator_id, validator_id, 20);
        
        uint8_t sig_key[4 + sizeof(uint32_t) + 20];
        size_t sig_key_len;
        create_signature_key(height, validator_id, sig_key, &sig_key_len);
        
        char *err = NULL;
        char *value = NULL;
        size_t value_len = 0;
        value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(), (char *)sig_key, sig_key_len, &value_len, &err);
        if (err) {
            MXD_LOG_ERROR("db", "Failed to retrieve signature: %s", err);
            free(err);
        } else if (value && value_len > 0 && value_len <= MXD_SIGNATURE_MAX) {
            (*signatures)[index].signature_length = (uint16_t)value_len;
            memcpy((*signatures)[index].signature, value, (*signatures)[index].signature_length);
            (*signatures)[index].chain_position = 0; // Unknown position
            (*signatures)[index].timestamp = 0; // Unknown timestamp
            
            index++;
        }
        
        if (value) free(value);
        rocksdb_iter_next(iter);
    }
    
    rocksdb_iter_destroy(iter);
    *signature_count = index;
    
    return 0;
}

double mxd_calculate_block_latency_score(const mxd_block_t *block) {
    if (!block || !block->validation_chain || block->validation_count == 0) {
        return 0.0;
    }
    
    double score = 0.0;
    for (uint32_t i = 0; i < block->validation_count; i++) {
        double latency = 50.0 + (10.0 * block->validation_chain[i].chain_position);
        score += 1.0 / latency;
    }
    
    return score;
}

int mxd_flush_blockchain_db(void) {
    if (!mxd_get_rocksdb_db()) {
        return -1;
    }
    
    char *err = NULL;
    rocksdb_flushoptions_t *flushoptions = rocksdb_flushoptions_create();
    rocksdb_flushoptions_set_wait(flushoptions, 1);
    
    rocksdb_flush(mxd_get_rocksdb_db(), flushoptions, &err);
    rocksdb_flushoptions_destroy(flushoptions);
    
    if (err) {
        MXD_LOG_ERROR("db", "Failed to flush blockchain database: %s", err);
        free(err);
        return -1;
    }
    
    return 0;
}

int mxd_compact_blockchain_db(void) {
    if (!mxd_get_rocksdb_db()) {
        return -1;
    }
    
    rocksdb_compact_range(mxd_get_rocksdb_db(), NULL, 0, NULL, 0);
    
    MXD_LOG_INFO("db", "Blockchain database compaction completed");
    return 0;
}

int mxd_store_validator_metadata(const uint8_t validator_id[20], uint8_t algo_id, 
                                  const uint8_t *public_key, size_t pubkey_len) {
    if (!validator_id || !public_key || pubkey_len == 0) {
        return -1;
    }
    
    if (!mxd_get_rocksdb_db()) {
        MXD_LOG_ERROR("db", "Database not initialized");
        return -1;
    }
    
    uint8_t key[30];
    memcpy(key, "validator:", 10);
    memcpy(key + 10, validator_id, 20);
    size_t key_len = 30;
    
    size_t value_len = 1 + 2 + pubkey_len;
    uint8_t *value = malloc(value_len);
    if (!value) {
        return -1;
    }
    
    value[0] = algo_id;
    uint16_t len_field = htons((uint16_t)pubkey_len);
    memcpy(value + 1, &len_field, 2);
    memcpy(value + 3, public_key, pubkey_len);
    
    char *err = NULL;
    rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(), 
                (char *)key, key_len, (char *)value, value_len, &err);
    
    free(value);
    
    if (err) {
        MXD_LOG_ERROR("db", "Failed to store validator metadata: %s", err);
        free(err);
        return -1;
    }
    
    return 0;
}

int mxd_retrieve_validator_metadata(const uint8_t validator_id[20], uint8_t *out_algo_id,
                                     uint8_t *out_public_key, size_t out_capacity, size_t *out_len) {
    if (!validator_id || !out_algo_id || !out_public_key || !out_len) {
        return -1;
    }
    
    if (!mxd_get_rocksdb_db()) {
        return -1;
    }
    
    uint8_t key[30];
    memcpy(key, "validator:", 10);
    memcpy(key + 10, validator_id, 20);
    size_t key_len = 30;
    
    char *err = NULL;
    size_t value_len = 0;
    char *value = rocksdb_get(mxd_get_rocksdb_db(), mxd_get_rocksdb_readoptions(),
                              (char *)key, key_len, &value_len, &err);
    
    if (err) {
        free(err);
        return -1;
    }
    
    if (!value || value_len < 3) {
        if (value) free(value);
        return -1;
    }
    
    *out_algo_id = (uint8_t)value[0];
    uint16_t pubkey_len_net = 0;
    memcpy(&pubkey_len_net, value + 1, 2);
    uint16_t pubkey_len = ntohs(pubkey_len_net);
    
    if (pubkey_len > out_capacity || value_len < 3 + pubkey_len) {
        free(value);
        return -1;
    }
    
    memcpy(out_public_key, value + 3, pubkey_len);
    *out_len = pubkey_len;
    
    free(value);
    return 0;
}

int mxd_load_all_validator_metadata(void) {
    if (!mxd_get_rocksdb_db()) {
        return -1;
    }
    
    rocksdb_iterator_t *iter = rocksdb_create_iterator(mxd_get_rocksdb_db(), 
                                                        mxd_get_rocksdb_readoptions());
    if (!iter) {
        return -1;
    }
    
    uint8_t prefix[10];
    memcpy(prefix, "validator:", 10);
    
    int loaded_count = 0;
    
    for (rocksdb_iter_seek(iter, (char *)prefix, 10);
         rocksdb_iter_valid(iter);
         rocksdb_iter_next(iter)) {
        
        size_t key_len = 0;
        const char *key = rocksdb_iter_key(iter, &key_len);
        
        if (key_len != 30 || memcmp(key, prefix, 10) != 0) {
            break;
        }
        
        size_t value_len = 0;
        const char *value = rocksdb_iter_value(iter, &value_len);
        
        if (!value || value_len < 3) {
            continue;
        }
        
        uint8_t validator_id[20];
        memcpy(validator_id, key + 10, 20);
        
        uint8_t algo_id = (uint8_t)value[0];
        uint16_t pubkey_len_net = 0;
        memcpy(&pubkey_len_net, value + 1, 2);
        uint16_t pubkey_len = ntohs(pubkey_len_net);
        
        if (value_len < 3 + pubkey_len) {
            continue;
        }
        
        if (mxd_test_register_validator_pubkey(validator_id, (const uint8_t *)(value + 3), pubkey_len) == 0) {
            loaded_count++;
        }
    }
    
    rocksdb_iter_destroy(iter);
    
    MXD_LOG_INFO("db", "Loaded %d validator metadata entries from database", loaded_count);
    return 0;
}

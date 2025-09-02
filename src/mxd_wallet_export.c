#include "../include/mxd_wallet_export.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_monitoring.h"
#include "../include/mxd_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/mman.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <cjson/cJSON.h>

static int wallet_export_initialized = 0;
static char export_response_buffer[MXD_EXPORT_MAX_JSON_SIZE];

int mxd_init_wallet_export(void) {
    if (wallet_export_initialized) {
        return 0;
    }
    
    if (RAND_status() != 1) {
        MXD_LOG_ERROR("wallet_export", "OpenSSL random number generator not properly seeded");
        return -1;
    }
    
    wallet_export_initialized = 1;
    MXD_LOG_INFO("wallet_export", "Wallet export system initialized");
    return 0;
}

void mxd_cleanup_wallet_export(void) {
    if (wallet_export_initialized) {
        mxd_secure_zero_memory(export_response_buffer, sizeof(export_response_buffer));
        wallet_export_initialized = 0;
        MXD_LOG_INFO("wallet_export", "Wallet export system cleaned up");
    }
}

void mxd_secure_zero_memory(void* ptr, size_t size) {
    if (ptr && size > 0) {
        volatile uint8_t* volatile_ptr = (volatile uint8_t*)ptr;
        for (size_t i = 0; i < size; i++) {
            volatile_ptr[i] = 0;
        }
    }
}

int mxd_secure_lock_memory(void* ptr, size_t size) {
    if (!ptr || size == 0) {
        return -1;
    }
    
    if (mlock(ptr, size) != 0) {
        MXD_LOG_WARN("wallet_export", "Failed to lock memory: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

int mxd_secure_unlock_memory(void* ptr, size_t size) {
    if (!ptr || size == 0) {
        return -1;
    }
    
    if (munlock(ptr, size) != 0) {
        MXD_LOG_WARN("wallet_export", "Failed to unlock memory: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

static int derive_key_from_password(const char* password, const uint8_t* salt, 
                                   uint8_t* derived_key, size_t key_len) {
    if (!password || !salt || !derived_key || key_len != 32) {
        return -1;
    }
    
    EVP_KDF* kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    if (!kdf) {
        MXD_LOG_ERROR("wallet_export", "Failed to fetch Argon2ID KDF");
        return -1;
    }
    
    EVP_KDF_CTX* kdf_ctx = EVP_KDF_CTX_new(kdf);
    if (!kdf_ctx) {
        EVP_KDF_free(kdf);
        MXD_LOG_ERROR("wallet_export", "Failed to create KDF context");
        return -1;
    }
    
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string("pass", (void*)password, strlen(password)),
        OSSL_PARAM_construct_octet_string("salt", (void*)salt, MXD_EXPORT_SALT_SIZE),
        OSSL_PARAM_construct_uint32("memory", (uint32_t[]){65536}),
        OSSL_PARAM_construct_uint32("iter", (uint32_t[]){3}),
        OSSL_PARAM_construct_uint32("lanes", (uint32_t[]){1}),
        OSSL_PARAM_END
    };
    
    int result = -1;
    if (EVP_KDF_derive(kdf_ctx, derived_key, key_len, params) == 1) {
        result = 0;
    } else {
        MXD_LOG_ERROR("wallet_export", "Argon2ID key derivation failed");
    }
    
    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);
    return result;
}

int mxd_secure_encrypt_data(const uint8_t* plaintext, size_t plaintext_len,
                           const char* password, mxd_export_data_t* export_data) {
    if (!plaintext || plaintext_len == 0 || !password || !export_data) {
        return -1;
    }
    
    if (RAND_bytes(export_data->salt, MXD_EXPORT_SALT_SIZE) != 1) {
        MXD_LOG_ERROR("wallet_export", "Failed to generate random salt");
        return -1;
    }
    
    if (RAND_bytes(export_data->iv, MXD_EXPORT_IV_SIZE) != 1) {
        MXD_LOG_ERROR("wallet_export", "Failed to generate random IV");
        return -1;
    }
    
    uint8_t derived_key[32];
    if (derive_key_from_password(password, export_data->salt, derived_key, sizeof(derived_key)) != 0) {
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        return -1;
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        MXD_LOG_ERROR("wallet_export", "Failed to create cipher context");
        return -1;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        MXD_LOG_ERROR("wallet_export", "Failed to initialize AES-256-GCM encryption");
        return -1;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, MXD_EXPORT_IV_SIZE, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        MXD_LOG_ERROR("wallet_export", "Failed to set IV length");
        return -1;
    }
    
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, derived_key, export_data->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        MXD_LOG_ERROR("wallet_export", "Failed to set key and IV");
        return -1;
    }
    
    export_data->encrypted_data = malloc(plaintext_len + 16);
    if (!export_data->encrypted_data) {
        EVP_CIPHER_CTX_free(ctx);
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        MXD_LOG_ERROR("wallet_export", "Failed to allocate memory for encrypted data");
        return -1;
    }
    
    int len;
    if (EVP_EncryptUpdate(ctx, export_data->encrypted_data, &len, plaintext, plaintext_len) != 1) {
        free(export_data->encrypted_data);
        export_data->encrypted_data = NULL;
        EVP_CIPHER_CTX_free(ctx);
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        MXD_LOG_ERROR("wallet_export", "Failed to encrypt data");
        return -1;
    }
    
    export_data->encrypted_data_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, export_data->encrypted_data + len, &len) != 1) {
        free(export_data->encrypted_data);
        export_data->encrypted_data = NULL;
        EVP_CIPHER_CTX_free(ctx);
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        MXD_LOG_ERROR("wallet_export", "Failed to finalize encryption");
        return -1;
    }
    
    export_data->encrypted_data_len += len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MXD_EXPORT_TAG_SIZE, export_data->auth_tag) != 1) {
        free(export_data->encrypted_data);
        export_data->encrypted_data = NULL;
        EVP_CIPHER_CTX_free(ctx);
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        MXD_LOG_ERROR("wallet_export", "Failed to get authentication tag");
        return -1;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    mxd_secure_zero_memory(derived_key, sizeof(derived_key));
    
    strncpy(export_data->version, MXD_EXPORT_VERSION, sizeof(export_data->version) - 1);
    strncpy(export_data->algorithm, "AES-256-GCM", sizeof(export_data->algorithm) - 1);
    strncpy(export_data->kdf, "Argon2id", sizeof(export_data->kdf) - 1);
    export_data->kdf_memory = 65536;
    export_data->kdf_iterations = 3;
    export_data->kdf_parallelism = 1;
    
    return 0;
}

int mxd_secure_decrypt_data(const mxd_export_data_t* export_data, const char* password,
                           uint8_t* plaintext, size_t* plaintext_len) {
    if (!export_data || !password || !plaintext || !plaintext_len) {
        return -1;
    }
    
    if (strcmp(export_data->algorithm, "AES-256-GCM") != 0) {
        MXD_LOG_ERROR("wallet_export", "Unsupported encryption algorithm: %s", export_data->algorithm);
        return -1;
    }
    
    if (strcmp(export_data->kdf, "Argon2id") != 0) {
        MXD_LOG_ERROR("wallet_export", "Unsupported KDF: %s", export_data->kdf);
        return -1;
    }
    
    uint8_t derived_key[32];
    if (derive_key_from_password(password, export_data->salt, derived_key, sizeof(derived_key)) != 0) {
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        return -1;
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        MXD_LOG_ERROR("wallet_export", "Failed to create cipher context");
        return -1;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        MXD_LOG_ERROR("wallet_export", "Failed to initialize AES-256-GCM decryption");
        return -1;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, MXD_EXPORT_IV_SIZE, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        MXD_LOG_ERROR("wallet_export", "Failed to set IV length");
        return -1;
    }
    
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, derived_key, export_data->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        MXD_LOG_ERROR("wallet_export", "Failed to set key and IV");
        return -1;
    }
    
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, export_data->encrypted_data, export_data->encrypted_data_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        MXD_LOG_ERROR("wallet_export", "Failed to decrypt data");
        return -1;
    }
    
    *plaintext_len = len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, MXD_EXPORT_TAG_SIZE, (void*)export_data->auth_tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        MXD_LOG_ERROR("wallet_export", "Failed to set authentication tag");
        return -1;
    }
    
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        mxd_secure_zero_memory(derived_key, sizeof(derived_key));
        MXD_LOG_ERROR("wallet_export", "Failed to finalize decryption - authentication failed");
        return -1;
    }
    
    *plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    mxd_secure_zero_memory(derived_key, sizeof(derived_key));
    
    return 0;
}

static char* base64_encode(const uint8_t* data, size_t len) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, data, len);
    BIO_flush(bio);
    
    char* mem_data;
    long mem_len = BIO_get_mem_data(bio, &mem_data);
    
    char* encoded = malloc(mem_len + 1);
    if (encoded) {
        memcpy(encoded, mem_data, mem_len);
        encoded[mem_len] = '\0';
    }
    
    BIO_free_all(bio);
    return encoded;
}

static uint8_t* base64_decode(const char* encoded, size_t* decoded_len) {
    BIO* bio = BIO_new_mem_buf(encoded, -1);
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    size_t max_len = strlen(encoded) * 3 / 4 + 1;
    uint8_t* decoded = malloc(max_len);
    if (!decoded) {
        BIO_free_all(bio);
        return NULL;
    }
    
    *decoded_len = BIO_read(bio, decoded, max_len);
    BIO_free_all(bio);
    
    if (*decoded_len <= 0) {
        free(decoded);
        return NULL;
    }
    
    return decoded;
}

int mxd_export_data_to_json(const mxd_export_data_t* export_data, char* json_buffer, size_t buffer_size) {
    if (!export_data || !json_buffer || buffer_size == 0) {
        return -1;
    }
    
    char* encrypted_data_b64 = base64_encode(export_data->encrypted_data, export_data->encrypted_data_len);
    char* salt_b64 = base64_encode(export_data->salt, MXD_EXPORT_SALT_SIZE);
    char* iv_b64 = base64_encode(export_data->iv, MXD_EXPORT_IV_SIZE);
    char* tag_b64 = base64_encode(export_data->auth_tag, MXD_EXPORT_TAG_SIZE);
    
    if (!encrypted_data_b64 || !salt_b64 || !iv_b64 || !tag_b64) {
        free(encrypted_data_b64);
        free(salt_b64);
        free(iv_b64);
        free(tag_b64);
        return -1;
    }
    
    cJSON* json = cJSON_CreateObject();
    cJSON* kdf_params = cJSON_CreateObject();
    
    cJSON_AddStringToObject(json, "version", export_data->version);
    cJSON_AddStringToObject(json, "encrypted_data", encrypted_data_b64);
    cJSON_AddStringToObject(json, "salt", salt_b64);
    cJSON_AddStringToObject(json, "iv", iv_b64);
    cJSON_AddStringToObject(json, "auth_tag", tag_b64);
    cJSON_AddStringToObject(json, "algorithm", export_data->algorithm);
    cJSON_AddStringToObject(json, "kdf", export_data->kdf);
    
    cJSON_AddNumberToObject(kdf_params, "memory", export_data->kdf_memory);
    cJSON_AddNumberToObject(kdf_params, "iterations", export_data->kdf_iterations);
    cJSON_AddNumberToObject(kdf_params, "parallelism", export_data->kdf_parallelism);
    cJSON_AddItemToObject(json, "kdf_params", kdf_params);
    
    char* json_string = cJSON_Print(json);
    if (!json_string || strlen(json_string) >= buffer_size) {
        free(encrypted_data_b64);
        free(salt_b64);
        free(iv_b64);
        free(tag_b64);
        free(json_string);
        cJSON_Delete(json);
        return -1;
    }
    
    strcpy(json_buffer, json_string);
    
    free(encrypted_data_b64);
    free(salt_b64);
    free(iv_b64);
    free(tag_b64);
    free(json_string);
    cJSON_Delete(json);
    
    return 0;
}

int mxd_export_data_from_json(const char* json_string, mxd_export_data_t* export_data) {
    if (!json_string || !export_data) {
        return -1;
    }
    
    cJSON* json = cJSON_Parse(json_string);
    if (!json) {
        MXD_LOG_ERROR("wallet_export", "Failed to parse JSON");
        return -1;
    }
    
    cJSON* version = cJSON_GetObjectItem(json, "version");
    cJSON* encrypted_data = cJSON_GetObjectItem(json, "encrypted_data");
    cJSON* salt = cJSON_GetObjectItem(json, "salt");
    cJSON* iv = cJSON_GetObjectItem(json, "iv");
    cJSON* auth_tag = cJSON_GetObjectItem(json, "auth_tag");
    cJSON* algorithm = cJSON_GetObjectItem(json, "algorithm");
    cJSON* kdf = cJSON_GetObjectItem(json, "kdf");
    cJSON* kdf_params = cJSON_GetObjectItem(json, "kdf_params");
    
    if (!cJSON_IsString(version) || !cJSON_IsString(encrypted_data) || 
        !cJSON_IsString(salt) || !cJSON_IsString(iv) || !cJSON_IsString(auth_tag) ||
        !cJSON_IsString(algorithm) || !cJSON_IsString(kdf) || !cJSON_IsObject(kdf_params)) {
        cJSON_Delete(json);
        MXD_LOG_ERROR("wallet_export", "Invalid JSON structure");
        return -1;
    }
    
    strncpy(export_data->version, version->valuestring, sizeof(export_data->version) - 1);
    strncpy(export_data->algorithm, algorithm->valuestring, sizeof(export_data->algorithm) - 1);
    strncpy(export_data->kdf, kdf->valuestring, sizeof(export_data->kdf) - 1);
    
    size_t decoded_len;
    uint8_t* decoded_salt = base64_decode(salt->valuestring, &decoded_len);
    if (!decoded_salt || decoded_len != MXD_EXPORT_SALT_SIZE) {
        free(decoded_salt);
        cJSON_Delete(json);
        return -1;
    }
    memcpy(export_data->salt, decoded_salt, MXD_EXPORT_SALT_SIZE);
    free(decoded_salt);
    
    uint8_t* decoded_iv = base64_decode(iv->valuestring, &decoded_len);
    if (!decoded_iv || decoded_len != MXD_EXPORT_IV_SIZE) {
        free(decoded_iv);
        cJSON_Delete(json);
        return -1;
    }
    memcpy(export_data->iv, decoded_iv, MXD_EXPORT_IV_SIZE);
    free(decoded_iv);
    
    uint8_t* decoded_tag = base64_decode(auth_tag->valuestring, &decoded_len);
    if (!decoded_tag || decoded_len != MXD_EXPORT_TAG_SIZE) {
        free(decoded_tag);
        cJSON_Delete(json);
        return -1;
    }
    memcpy(export_data->auth_tag, decoded_tag, MXD_EXPORT_TAG_SIZE);
    free(decoded_tag);
    
    export_data->encrypted_data = base64_decode(encrypted_data->valuestring, &export_data->encrypted_data_len);
    if (!export_data->encrypted_data) {
        cJSON_Delete(json);
        return -1;
    }
    
    cJSON* memory = cJSON_GetObjectItem(kdf_params, "memory");
    cJSON* iterations = cJSON_GetObjectItem(kdf_params, "iterations");
    cJSON* parallelism = cJSON_GetObjectItem(kdf_params, "parallelism");
    
    if (cJSON_IsNumber(memory)) export_data->kdf_memory = memory->valueint;
    if (cJSON_IsNumber(iterations)) export_data->kdf_iterations = iterations->valueint;
    if (cJSON_IsNumber(parallelism)) export_data->kdf_parallelism = parallelism->valueint;
    
    cJSON_Delete(json);
    return 0;
}

const char* mxd_export_private_key(const char* address, const char* encryption_password) {
    if (!wallet_export_initialized) {
        snprintf(export_response_buffer, sizeof(export_response_buffer),
            "{\"success\":false,\"error\":\"Wallet export system not initialized\"}");
        return export_response_buffer;
    }
    
    if (!address || !encryption_password) {
        snprintf(export_response_buffer, sizeof(export_response_buffer),
            "{\"success\":false,\"error\":\"Invalid parameters\"}");
        return export_response_buffer;
    }
    
    if (strlen(encryption_password) < 8) {
        snprintf(export_response_buffer, sizeof(export_response_buffer),
            "{\"success\":false,\"error\":\"Password must be at least 8 characters\"}");
        return export_response_buffer;
    }
    
    mxd_wallet_t* wallet_ptr = mxd_get_wallet_instance();
    pthread_mutex_t* wallet_mutex = mxd_get_wallet_mutex();
    int* wallet_initialized = mxd_get_wallet_initialized();
    
    if (!wallet_ptr || !wallet_mutex || !wallet_initialized || !(*wallet_initialized)) {
        snprintf(export_response_buffer, sizeof(export_response_buffer),
            "{\"success\":false,\"error\":\"Wallet not initialized\"}");
        return export_response_buffer;
    }
    
    pthread_mutex_lock(wallet_mutex);
    
    mxd_wallet_keypair_t* keypair = NULL;
    for (size_t i = 0; i < wallet_ptr->keypair_count; i++) {
        if (strcmp(wallet_ptr->keypairs[i].address, address) == 0) {
            keypair = &wallet_ptr->keypairs[i];
            break;
        }
    }
    
    if (!keypair) {
        pthread_mutex_unlock(wallet_mutex);
        snprintf(export_response_buffer, sizeof(export_response_buffer),
            "{\"success\":false,\"error\":\"Address not found in wallet\"}");
        return export_response_buffer;
    }
    
    mxd_export_data_t export_data = {0};
    int encrypt_result = mxd_secure_encrypt_data(keypair->private_key, 128, encryption_password, &export_data);
    
    pthread_mutex_unlock(wallet_mutex);
    
    if (encrypt_result != 0) {
        if (export_data.encrypted_data) {
            free(export_data.encrypted_data);
        }
        snprintf(export_response_buffer, sizeof(export_response_buffer),
            "{\"success\":false,\"error\":\"Failed to encrypt private key\"}");
        return export_response_buffer;
    }
    
    char json_buffer[MXD_EXPORT_MAX_JSON_SIZE];
    if (mxd_export_data_to_json(&export_data, json_buffer, sizeof(json_buffer)) != 0) {
        free(export_data.encrypted_data);
        snprintf(export_response_buffer, sizeof(export_response_buffer),
            "{\"success\":false,\"error\":\"Failed to format export data\"}");
        return export_response_buffer;
    }
    
    int max_json_len = sizeof(export_response_buffer) - 50;
    if (strlen(json_buffer) > max_json_len) {
        free(export_data.encrypted_data);
        return "{\"success\":false,\"error\":\"Encrypted data too large\"}";
    }
    
    int result = snprintf(export_response_buffer, sizeof(export_response_buffer),
        "{\"success\":true,\"encrypted_private_key\":%s}", json_buffer);
    
    if (result >= sizeof(export_response_buffer)) {
        free(export_data.encrypted_data);
        return "{\"success\":false,\"error\":\"Response buffer too small\"}";
    }
    
    free(export_data.encrypted_data);
    MXD_LOG_INFO("wallet_export", "Private key exported for address: %.10s...", address);
    
    return export_response_buffer;
}

int mxd_import_private_key(const char* address, const char* encrypted_private_key, const char* encryption_password) {
    if (!wallet_export_initialized || !address || !encrypted_private_key || !encryption_password) {
        return -1;
    }
    
    if (strlen(encryption_password) < 8) {
        MXD_LOG_ERROR("wallet_export", "Password must be at least 8 characters");
        return -1;
    }
    
    mxd_wallet_t* wallet_ptr = mxd_get_wallet_instance();
    pthread_mutex_t* wallet_mutex = mxd_get_wallet_mutex();
    int* wallet_initialized = mxd_get_wallet_initialized();
    
    if (!wallet_ptr || !wallet_mutex || !wallet_initialized || !(*wallet_initialized)) {
        MXD_LOG_ERROR("wallet_export", "Wallet not initialized");
        return -1;
    }

    mxd_export_data_t export_data = {0};
    if (mxd_export_data_from_json(encrypted_private_key, &export_data) != 0) {
        MXD_LOG_ERROR("wallet_export", "Failed to parse encrypted private key data");
        return -1;
    }
    
    uint8_t decrypted_key[128];
    size_t decrypted_len;
    if (mxd_secure_decrypt_data(&export_data, encryption_password, decrypted_key, &decrypted_len) != 0) {
        if (export_data.encrypted_data) {
            free(export_data.encrypted_data);
        }
        mxd_secure_zero_memory(decrypted_key, sizeof(decrypted_key));
        MXD_LOG_ERROR("wallet_export", "Failed to decrypt private key");
        return -1;
    }
    
    if (decrypted_len != 128) {
        if (export_data.encrypted_data) {
            free(export_data.encrypted_data);
        }
        mxd_secure_zero_memory(decrypted_key, sizeof(decrypted_key));
        MXD_LOG_ERROR("wallet_export", "Invalid private key length");
        return -1;
    }
    
    pthread_mutex_lock(wallet_mutex);
    
    if (wallet_ptr->keypair_count >= 10) {
        pthread_mutex_unlock(wallet_mutex);
        if (export_data.encrypted_data) {
            free(export_data.encrypted_data);
        }
        mxd_secure_zero_memory(decrypted_key, sizeof(decrypted_key));
        MXD_LOG_ERROR("wallet_export", "Maximum number of addresses reached");
        return -1;
    }
    
    for (size_t i = 0; i < wallet_ptr->keypair_count; i++) {
        if (strcmp(wallet_ptr->keypairs[i].address, address) == 0) {
            pthread_mutex_unlock(wallet_mutex);
            if (export_data.encrypted_data) {
                free(export_data.encrypted_data);
            }
            mxd_secure_zero_memory(decrypted_key, sizeof(decrypted_key));
            MXD_LOG_ERROR("wallet_export", "Address already exists in wallet");
            return -1;
        }
    }
    
    mxd_wallet_keypair_t* keypair = &wallet_ptr->keypairs[wallet_ptr->keypair_count];
    strncpy(keypair->address, address, sizeof(keypair->address) - 1);
    memcpy(keypair->private_key, decrypted_key, 128);
    
    memset(keypair->public_key, 0, sizeof(keypair->public_key));
    
    strncpy(keypair->passphrase, "imported", sizeof(keypair->passphrase) - 1);
    
    wallet_ptr->keypair_count++;
    
    pthread_mutex_unlock(wallet_mutex);
    
    if (export_data.encrypted_data) {
        free(export_data.encrypted_data);
    }
    mxd_secure_zero_memory(decrypted_key, sizeof(decrypted_key));
    
    MXD_LOG_INFO("wallet_export", "Private key imported for address: %.10s...", address);
    return 0;
}

const char* mxd_export_wallet_json(const char* encryption_password) {
    snprintf(export_response_buffer, sizeof(export_response_buffer),
        "{\"success\":false,\"error\":\"Full wallet export not yet implemented\"}");
    return export_response_buffer;
}

int mxd_import_wallet_json(const char* encrypted_wallet_json, const char* encryption_password) {
    MXD_LOG_ERROR("wallet_export", "Full wallet import not yet implemented");
    return -1;
}

int mxd_serialize_wallet(char* output_buffer, size_t buffer_size, const char* encryption_password) {
    MXD_LOG_ERROR("wallet_export", "Wallet serialization not yet implemented");
    return -1;
}

int mxd_deserialize_wallet(const char* serialized_data, const char* encryption_password) {
    MXD_LOG_ERROR("wallet_export", "Wallet deserialization not yet implemented");
    return -1;
}

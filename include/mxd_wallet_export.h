#ifndef MXD_WALLET_EXPORT_H
#define MXD_WALLET_EXPORT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define MXD_EXPORT_VERSION "1.0"
#define MXD_EXPORT_SALT_SIZE 32
#define MXD_EXPORT_IV_SIZE 12
#define MXD_EXPORT_TAG_SIZE 16
#define MXD_EXPORT_MAX_JSON_SIZE 4096

typedef struct {
    char version[8];
    uint8_t salt[MXD_EXPORT_SALT_SIZE];
    uint8_t iv[MXD_EXPORT_IV_SIZE];
    uint8_t auth_tag[MXD_EXPORT_TAG_SIZE];
    char algorithm[32];
    char kdf[16];
    uint32_t kdf_memory;
    uint32_t kdf_iterations;
    uint32_t kdf_parallelism;
    size_t encrypted_data_len;
    uint8_t* encrypted_data;
} mxd_export_data_t;

typedef struct {
    uint32_t memory;
    uint32_t iterations;
    uint32_t parallelism;
} mxd_kdf_params_t;

int mxd_init_wallet_export(void);
void mxd_cleanup_wallet_export(void);

const char* mxd_export_private_key(const char* address, const char* encryption_password);
const char* mxd_export_wallet_json(const char* encryption_password);
int mxd_import_private_key(const char* address, const char* encrypted_private_key, const char* encryption_password);
int mxd_import_wallet_json(const char* encrypted_wallet_json, const char* encryption_password);

int mxd_serialize_wallet(char* output_buffer, size_t buffer_size, const char* encryption_password);
int mxd_deserialize_wallet(const char* serialized_data, const char* encryption_password);

int mxd_secure_encrypt_data(const uint8_t* plaintext, size_t plaintext_len,
                           const char* password, mxd_export_data_t* export_data);
int mxd_secure_decrypt_data(const mxd_export_data_t* export_data, const char* password,
                           uint8_t* plaintext, size_t* plaintext_len);

int mxd_export_data_to_json(const mxd_export_data_t* export_data, char* json_buffer, size_t buffer_size);
int mxd_export_data_from_json(const char* json_string, mxd_export_data_t* export_data);

void mxd_secure_zero_memory(void* ptr, size_t size);
int mxd_secure_lock_memory(void* ptr, size_t size);
int mxd_secure_unlock_memory(void* ptr, size_t size);

#ifdef __cplusplus
}
#endif

#endif // MXD_WALLET_EXPORT_H

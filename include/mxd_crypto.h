#ifndef MXD_CRYPTO_H
#define MXD_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef enum {
    MXD_SIGALG_ED25519 = 1,
    MXD_SIGALG_DILITHIUM5 = 2
} mxd_sig_alg_t;

#define MXD_PUBKEY_MAX_LEN 2592
#define MXD_PRIVKEY_MAX_LEN 4864
#define MXD_SIG_MAX_LEN 4595

size_t mxd_sig_pubkey_len(uint8_t algo_id);
size_t mxd_sig_privkey_len(uint8_t algo_id);
size_t mxd_sig_signature_len(uint8_t algo_id);
const char* mxd_sig_alg_name(uint8_t algo_id);

// SHA-512 hashing
int mxd_sha512(const uint8_t *input, size_t length, uint8_t output[64]);

// SHA-256 hashing
int mxd_sha256(const uint8_t *input, size_t length, uint8_t output[32]);

// SHA-1 hashing
int mxd_sha1(const uint8_t *input, size_t length, uint8_t output[20]);

// RIPEMD-160 hashing
int mxd_ripemd160(const uint8_t *input, size_t length, uint8_t output[20]);

// HASH160 (SHA-256 followed by RIPEMD-160)
int mxd_hash160(const uint8_t *input, size_t length, uint8_t output[20]);

// Argon2 key derivation (SENSITIVE: ~1GB memory, use for user passwords)
int mxd_argon2(const char *input, const uint8_t *salt, uint8_t *output,
               size_t output_length);

// Argon2 key derivation (INTERACTIVE: ~64MB memory, use for node keypairs)
int mxd_argon2_lowmem(const char *input, const uint8_t *salt, uint8_t *output,
                      size_t output_length);

int mxd_sig_keygen(uint8_t algo_id, uint8_t *public_key, uint8_t *secret_key);
int mxd_sig_sign(uint8_t algo_id, uint8_t *signature, size_t *signature_length,
                 const uint8_t *message, size_t message_length,
                 const uint8_t *secret_key);
int mxd_sig_verify(uint8_t algo_id, const uint8_t *signature, size_t signature_length,
                   const uint8_t *message, size_t message_length,
                   const uint8_t *public_key);

int mxd_derive_address(uint8_t algo_id, const uint8_t *public_key, size_t pubkey_len, uint8_t address[20]);

int mxd_dilithium_keygen(uint8_t *public_key, uint8_t *secret_key);
int mxd_dilithium_sign(uint8_t *signature, size_t *signature_length,
                       const uint8_t *message, size_t message_length,
                       const uint8_t *secret_key);
int mxd_dilithium_verify(const uint8_t *signature, size_t signature_length,
                         const uint8_t *message, size_t message_length,
                         const uint8_t *public_key);

#ifdef __cplusplus
}
#endif

#endif // MXD_CRYPTO_H

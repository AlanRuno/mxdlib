#ifndef MXD_CRYPTO_H
#define MXD_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// SHA-512 hashing
void mxd_sha512(const uint8_t *input, size_t length, uint8_t output[64]);

// RIPEMD-160 hashing
void mxd_ripemd160(const uint8_t *input, size_t length, uint8_t output[20]);

// Argon2 key derivation
void mxd_argon2(const char *input, const uint8_t *salt, uint8_t *output, size_t output_length);

// Dilithium5 functions
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

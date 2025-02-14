#include "../include/mxd_crypto.h"
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <sodium.h>
#include <string.h>

// SHA-512 hashing implementation
void mxd_sha512(const uint8_t *input, size_t length, uint8_t output[64]) {
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, input, length);
    SHA512_Final(output, &ctx);
}

// RIPEMD-160 hashing implementation
void mxd_ripemd160(const uint8_t *input, size_t length, uint8_t output[20]) {
    RIPEMD160_CTX ctx;
    RIPEMD160_Init(&ctx);
    RIPEMD160_Update(&ctx, input, length);
    RIPEMD160_Final(output, &ctx);
}

// Argon2 key derivation implementation
void mxd_argon2(const char *input, const uint8_t *salt, uint8_t *output, size_t output_length) {
    // Using Argon2id variant as recommended for highest security
    crypto_pwhash(output, output_length,
                  input, strlen(input),
                  salt,
                  crypto_pwhash_OPSLIMIT_SENSITIVE, // High security parameters
                  crypto_pwhash_MEMLIMIT_SENSITIVE,
                  crypto_pwhash_ALG_ARGON2ID13);
}

// Dilithium5 key generation
int mxd_dilithium_keygen(uint8_t *public_key, uint8_t *secret_key) {
    // Initialize sodium if not already initialized
    if (sodium_init() < 0) {
        return -1;
    }
    
    // Generate keypair using Dilithium5
    return crypto_sign_keypair(public_key, secret_key);
}

// Dilithium5 signing
int mxd_dilithium_sign(uint8_t *signature, size_t *signature_length,
                       const uint8_t *message, size_t message_length,
                       const uint8_t *secret_key) {
    unsigned long long sig_len;
    int result = crypto_sign_detached(signature, &sig_len,
                                    message, message_length,
                                    secret_key);
    *signature_length = (size_t)sig_len;
    return result;
}

// Dilithium5 verification
int mxd_dilithium_verify(const uint8_t *signature, size_t signature_length,
                         const uint8_t *message, size_t message_length,
                         const uint8_t *public_key) {
    return crypto_sign_verify_detached(signature,
                                     message, message_length,
                                     public_key);
}

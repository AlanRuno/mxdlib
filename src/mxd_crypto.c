#include "../include/mxd_crypto.h"
#include <openssl/evp.h>
#include <openssl/ripemd.h>
#include <sodium.h>
#include <sodium/crypto_sign.h>
#include <string.h>

// SHA-512 hashing implementation using OpenSSL 3.0 EVP interface
int mxd_sha512(const uint8_t *input, size_t length, uint8_t output[64]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (!EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) ||
        !EVP_DigestUpdate(ctx, input, length) ||
        !EVP_DigestFinal_ex(ctx, output, NULL)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

// RIPEMD-160 hashing implementation using OpenSSL 3.0 EVP interface
int mxd_ripemd160(const uint8_t *input, size_t length, uint8_t output[20]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (!EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL) ||
        !EVP_DigestUpdate(ctx, input, length) ||
        !EVP_DigestFinal_ex(ctx, output, NULL)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

// Argon2 key derivation implementation
int mxd_argon2(const char *input, const uint8_t *salt, uint8_t *output, size_t output_length) {
    // Using Argon2id variant as recommended for highest security
    if (crypto_pwhash(output, output_length,
                      input, strlen(input),
                      salt,
                      crypto_pwhash_OPSLIMIT_SENSITIVE,
                      crypto_pwhash_MEMLIMIT_SENSITIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return -1; // Memory allocation or other error
    }
    return 0;
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

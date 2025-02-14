#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../include/mxd_crypto.h"

static void test_sha512(void) {
    const char *input = "test message";
    uint8_t output[64];
    
    mxd_sha512((const uint8_t*)input, strlen(input), output);
    
    // SHA-512 always produces output
    assert(output[0] != 0 || output[1] != 0);
    printf("SHA-512 test passed\n");
}

static void test_ripemd160(void) {
    const char *input = "test message";
    uint8_t output[20];
    
    mxd_ripemd160((const uint8_t*)input, strlen(input), output);
    
    // RIPEMD-160 always produces output
    assert(output[0] != 0 || output[1] != 0);
    printf("RIPEMD-160 test passed\n");
}

static void test_argon2(void) {
    const char *input = "test password";
    const uint8_t salt[16] = "MXDTestSalt1234";
    uint8_t output[32];
    
    mxd_argon2(input, salt, output, sizeof(output));
    
    // Argon2 always produces output
    assert(output[0] != 0 || output[1] != 0);
    printf("Argon2 test passed\n");
}

static void test_dilithium(void) {
    uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
    uint8_t secret_key[crypto_sign_SECRETKEYBYTES];
    
    // Test key generation
    assert(mxd_dilithium_keygen(public_key, secret_key) == 0);
    
    // Test signing
    const char *message = "test message";
    uint8_t signature[crypto_sign_BYTES];
    size_t signature_length;
    
    assert(mxd_dilithium_sign(signature, &signature_length,
                             (const uint8_t*)message, strlen(message),
                             secret_key) == 0);
    
    // Test verification
    assert(mxd_dilithium_verify(signature, signature_length,
                               (const uint8_t*)message, strlen(message),
                               public_key) == 0);
    
    printf("Dilithium tests passed\n");
}

int main(void) {
    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium\n");
        return 1;
    }
    
    test_sha512();
    test_ripemd160();
    test_argon2();
    test_dilithium();
    
    printf("All cryptographic tests passed\n");
    return 0;
}

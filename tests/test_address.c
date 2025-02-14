#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../include/mxd_address.h"

static void test_passphrase_generation(void) {
    char passphrase[256];
    assert(mxd_generate_passphrase(passphrase, sizeof(passphrase)) == 0);
    
    // Verify we got 12 words
    int word_count = 1;
    for (const char *p = passphrase; *p; p++) {
        if (*p == ' ') word_count++;
    }
    assert(word_count == 12);
    
    printf("Passphrase generation test passed\n");
}

static void test_property_key_derivation(void) {
    const char *test_passphrase = "test passphrase";
    const char *test_pin = "1234";
    uint8_t property_key[64];
    
    assert(mxd_derive_property_key(test_passphrase, test_pin, property_key) == 0);
    
    // Property key should not be all zeros
    int is_zero = 1;
    for (int i = 0; i < 64; i++) {
        if (property_key[i] != 0) {
            is_zero = 0;
            break;
        }
    }
    assert(!is_zero);
    
    printf("Property key derivation test passed\n");
}

static void test_keypair_generation(void) {
    uint8_t property_key[64] = {1}; // Test property key
    uint8_t public_key[256];
    uint8_t private_key[128];
    
    assert(mxd_generate_keypair(property_key, public_key, private_key) == 0);
    
    // Keys should not be all zeros
    int pub_zero = 1, priv_zero = 1;
    for (int i = 0; i < 256; i++) {
        if (i < 128 && private_key[i] != 0) priv_zero = 0;
        if (public_key[i] != 0) pub_zero = 0;
    }
    assert(!pub_zero && !priv_zero);
    
    printf("Keypair generation test passed\n");
}

static void test_address_generation(void) {
    uint8_t public_key[256] = {1}; // Test public key
    char address[42];
    
    assert(mxd_generate_address(public_key, address, sizeof(address)) == 0);
    assert(strlen(address) > 25); // Minimum length for valid address
    
    // Validate the generated address
    assert(mxd_validate_address(address) == 0);
    
    printf("Address generation test passed\n");
}

int main(void) {
    printf("Starting address management tests...\n");
    
    test_passphrase_generation();
    test_property_key_derivation();
    test_keypair_generation();
    test_address_generation();
    
    printf("All address management tests passed\n");
    return 0;
}

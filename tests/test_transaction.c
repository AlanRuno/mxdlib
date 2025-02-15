#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../include/mxd_transaction.h"
#include "../include/mxd_crypto.h"

static void test_transaction_creation(void) {
    mxd_transaction_t tx;
    assert(mxd_create_transaction(&tx) == 0);
    assert(tx.version == 1);
    assert(tx.input_count == 0);
    assert(tx.output_count == 0);
    assert(tx.inputs == NULL);
    assert(tx.outputs == NULL);
    
    mxd_free_transaction(&tx);
    printf("Transaction creation test passed\n");
}

static void test_input_output_management(void) {
    mxd_transaction_t tx;
    uint8_t prev_hash[64] = {1};
    uint8_t pub_key[256] = {2};
    uint8_t recv_key[256] = {3};
    
    assert(mxd_create_transaction(&tx) == 0);
    
    // Add input
    assert(mxd_add_tx_input(&tx, prev_hash, 0, pub_key) == 0);
    assert(tx.input_count == 1);
    assert(memcmp(tx.inputs[0].prev_tx_hash, prev_hash, 64) == 0);
    assert(tx.inputs[0].output_index == 0);
    assert(memcmp(tx.inputs[0].public_key, pub_key, 256) == 0);
    
    // Add output
    assert(mxd_add_tx_output(&tx, recv_key, 1.0) == 0);
    assert(tx.output_count == 1);
    assert(memcmp(tx.outputs[0].recipient_key, recv_key, 256) == 0);
    assert(tx.outputs[0].amount == 1.0);
    
    mxd_free_transaction(&tx);
    printf("Input/output management test passed\n");
}

static void test_transaction_signing(void) {
    mxd_transaction_t tx;
    uint8_t prev_hash[64] = {1};
    uint8_t pub_key[256];
    uint8_t priv_key[128];
    
    // Generate keypair
    assert(mxd_dilithium_keygen(pub_key, priv_key) == 0);
    
    // Create and sign transaction
    assert(mxd_create_transaction(&tx) == 0);
    assert(mxd_add_tx_input(&tx, prev_hash, 0, pub_key) == 0);
    assert(mxd_add_tx_output(&tx, pub_key, 1.0) == 0);
    
    // Sign input
    assert(mxd_sign_tx_input(&tx, 0, priv_key) == 0);
    
    // Verify signature
    assert(mxd_verify_tx_input(&tx, 0) == 0);
    
    mxd_free_transaction(&tx);
    printf("Transaction signing test passed\n");
}

static void test_transaction_validation(void) {
    mxd_transaction_t tx;
    uint8_t prev_hash[64] = {1};
    uint8_t pub_key[256];
    uint8_t priv_key[128];
    
    // Generate keypair
    assert(mxd_dilithium_keygen(pub_key, priv_key) == 0);
    
    // Create valid transaction
    assert(mxd_create_transaction(&tx) == 0);
    assert(mxd_add_tx_input(&tx, prev_hash, 0, pub_key) == 0);
    assert(mxd_add_tx_output(&tx, pub_key, 1.0) == 0);
    assert(mxd_sign_tx_input(&tx, 0, priv_key) == 0);
    
    // Validate transaction
    assert(mxd_validate_transaction(&tx) == 0);
    
    // Test invalid cases
    tx.version = 0;
    assert(mxd_validate_transaction(&tx) == -1);
    
    mxd_free_transaction(&tx);
    printf("Transaction validation test passed\n");
}

static void test_transaction_hashing(void) {
    mxd_transaction_t tx;
    uint8_t prev_hash[64] = {1};
    uint8_t pub_key[256] = {2};
    uint8_t hash[64];
    
    assert(mxd_create_transaction(&tx) == 0);
    assert(mxd_add_tx_input(&tx, prev_hash, 0, pub_key) == 0);
    assert(mxd_add_tx_output(&tx, pub_key, 1.0) == 0);
    
    // Calculate hash
    assert(mxd_calculate_tx_hash(&tx, hash) == 0);
    
    // Hash should not be all zeros
    int is_zero = 1;
    for (int i = 0; i < 64; i++) {
        if (hash[i] != 0) {
            is_zero = 0;
            break;
        }
    }
    assert(!is_zero);
    
    mxd_free_transaction(&tx);
    printf("Transaction hashing test passed\n");
}

int main(void) {
    printf("Starting transaction tests...\n");
    
    test_transaction_creation();
    test_input_output_management();
    test_transaction_signing();
    test_transaction_validation();
    test_transaction_hashing();
    
    printf("All transaction tests passed\n");
    return 0;
}

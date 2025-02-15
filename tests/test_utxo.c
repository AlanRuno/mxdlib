#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../include/mxd_utxo.h"
#include "../include/mxd_crypto.h"

static void test_utxo_initialization(void) {
    assert(mxd_init_utxo_db() == 0);
    printf("UTXO initialization test passed\n");
}

static void test_utxo_management(void) {
    mxd_utxo_t utxo = {0};
    uint8_t tx_hash[64] = {1};
    uint8_t owner_key[256] = {2};
    
    // Initialize UTXO
    memcpy(utxo.tx_hash, tx_hash, 64);
    utxo.output_index = 0;
    memcpy(utxo.owner_key, owner_key, 256);
    utxo.amount = 1.0;
    
    // Add UTXO
    assert(mxd_add_utxo(&utxo) == 0);
    
    // Find UTXO
    mxd_utxo_t found_utxo;
    assert(mxd_find_utxo(tx_hash, 0, &found_utxo) == 0);
    assert(memcmp(found_utxo.tx_hash, tx_hash, 64) == 0);
    assert(found_utxo.amount == 1.0);
    
    // Verify UTXO
    assert(mxd_verify_utxo(tx_hash, 0, owner_key) == 0);
    
    // Get balance
    assert(mxd_get_balance(owner_key) == 1.0);
    
    // Remove UTXO
    assert(mxd_remove_utxo(tx_hash, 0) == 0);
    assert(mxd_find_utxo(tx_hash, 0, &found_utxo) == -1);
    
    printf("UTXO management test passed\n");
}

static void test_multisig_utxo(void) {
    mxd_utxo_t utxo = {0};
    uint8_t tx_hash[64] = {1};
    uint8_t owner_key[256] = {2};
    uint8_t cosigner_keys[2 * 256] = {3, 4};
    
    // Initialize UTXO
    memcpy(utxo.tx_hash, tx_hash, 64);
    utxo.output_index = 0;
    memcpy(utxo.owner_key, owner_key, 256);
    utxo.amount = 1.0;
    
    // Create multi-sig UTXO
    assert(mxd_create_multisig_utxo(&utxo, cosigner_keys, 2, 2) == 0);
    assert(utxo.required_signatures == 2);
    assert(utxo.cosigner_count == 2);
    
    // Add UTXO
    assert(mxd_add_utxo(&utxo) == 0);
    
    // Verify cosigners can spend
    assert(mxd_verify_utxo(tx_hash, 0, cosigner_keys) == 0);
    assert(mxd_verify_utxo(tx_hash, 0, cosigner_keys + 256) == 0);
    
    // Clean up
    mxd_free_utxo(&utxo);
    printf("Multi-signature UTXO test passed\n");
}

int main(void) {
    printf("Starting UTXO tests...\n");
    
    test_utxo_initialization();
    test_utxo_management();
    test_multisig_utxo();
    
    printf("All UTXO tests passed\n");
    return 0;
}

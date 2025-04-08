#include "../include/mxd_crypto.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_transaction.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

int main(void) {
    printf("=== MXD UTXO Verification System Demo ===\n\n");
    
    if (mxd_init_utxo_db() != 0) {
        printf("Failed to initialize UTXO database\n");
        return 1;
    }
    
    if (mxd_init_transaction_validation() != 0) {
        printf("Failed to initialize transaction validation\n");
        return 1;
    }
    
    printf("UTXO database and transaction validation initialized\n\n");
    
    uint8_t alice_private_key[32] = {1, 2, 3, 4, 5};
    uint8_t alice_public_key[256];
    uint8_t bob_private_key[32] = {6, 7, 8, 9, 10};
    uint8_t bob_public_key[256];
    
    memset(alice_public_key, 0, 256);
    memset(bob_public_key, 0, 256);
    
    for (int i = 0; i < 32; i++) {
        alice_public_key[i] = alice_private_key[i];
        bob_public_key[i] = bob_private_key[i];
    }
    
    printf("Created test keys for Alice and Bob\n\n");
    
    mxd_utxo_t genesis_utxo = {0};
    uint8_t genesis_tx_hash[64] = {1};
    
    memcpy(genesis_utxo.tx_hash, genesis_tx_hash, 64);
    genesis_utxo.output_index = 0;
    memcpy(genesis_utxo.owner_key, alice_public_key, 256);
    genesis_utxo.amount = 100.0;
    
    if (mxd_add_utxo(&genesis_utxo) != 0) {
        printf("Failed to add genesis UTXO\n");
        return 1;
    }
    
    printf("Added genesis UTXO for Alice with amount 100.0\n\n");
    
    mxd_transaction_t tx1;
    if (mxd_create_transaction(&tx1) != 0) {
        printf("Failed to create transaction\n");
        return 1;
    }
    
    if (mxd_add_tx_input(&tx1, genesis_tx_hash, 0, alice_public_key) != 0) {
        printf("Failed to add transaction input\n");
        return 1;
    }
    
    if (mxd_add_tx_output(&tx1, bob_public_key, 70.0) != 0) {
        printf("Failed to add transaction output to Bob\n");
        return 1;
    }
    
    if (mxd_add_tx_output(&tx1, alice_public_key, 29.0) != 0) {
        printf("Failed to add transaction change output to Alice\n");
        return 1;
    }
    
    if (mxd_set_voluntary_tip(&tx1, 1.0) != 0) {
        printf("Failed to set voluntary tip\n");
        return 1;
    }
    
    tx1.timestamp = time(NULL);
    
    uint8_t tx1_hash[64];
    if (mxd_calculate_tx_hash(&tx1, tx1_hash) != 0) {
        printf("Failed to calculate transaction hash\n");
        return 1;
    }
    memcpy(tx1.tx_hash, tx1_hash, 64);
    
    if (mxd_sign_tx_input(&tx1, 0, alice_private_key) != 0) {
        printf("Failed to sign transaction input\n");
        return 1;
    }
    
    printf("Created transaction from Alice to Bob:\n");
    printf("  - Input: Alice's UTXO (100.0)\n");
    printf("  - Output 1: 70.0 to Bob\n");
    printf("  - Output 2: 29.0 change to Alice\n");
    printf("  - Voluntary tip: 1.0\n\n");
    
    if (mxd_validate_transaction(&tx1) != 0) {
        printf("Transaction validation failed\n");
        return 1;
    }
    
    printf("Transaction validation succeeded\n\n");
    
    if (mxd_process_transaction(&tx1) != 0) {
        printf("Transaction processing failed\n");
        return 1;
    }
    
    printf("Transaction processed successfully\n\n");
    
    mxd_utxo_t found_utxo;
    if (mxd_find_utxo(genesis_tx_hash, 0, &found_utxo) == 0) {
        printf("ERROR: Genesis UTXO still exists after being spent\n");
        return 1;
    }
    
    printf("Genesis UTXO has been spent (no longer in database)\n");
    
    if (mxd_find_utxo(tx1.tx_hash, 0, &found_utxo) != 0) {
        printf("ERROR: Bob's UTXO not found\n");
        return 1;
    }
    
    printf("Bob's UTXO found with amount %.1f\n", found_utxo.amount);
    
    if (mxd_find_utxo(tx1.tx_hash, 1, &found_utxo) != 0) {
        printf("ERROR: Alice's change UTXO not found\n");
        return 1;
    }
    
    printf("Alice's change UTXO found with amount %.1f\n\n", found_utxo.amount);
    
    mxd_transaction_t tx2;
    if (mxd_create_transaction(&tx2) != 0) {
        printf("Failed to create second transaction\n");
        return 1;
    }
    
    if (mxd_add_tx_input(&tx2, genesis_tx_hash, 0, alice_public_key) != 0) {
        printf("Failed to add input to second transaction\n");
        return 1;
    }
    
    if (mxd_add_tx_output(&tx2, alice_public_key, 100.0) != 0) {
        printf("Failed to add output to second transaction\n");
        return 1;
    }
    
    tx2.timestamp = time(NULL);
    
    uint8_t tx2_hash[64];
    if (mxd_calculate_tx_hash(&tx2, tx2_hash) != 0) {
        printf("Failed to calculate second transaction hash\n");
        return 1;
    }
    memcpy(tx2.tx_hash, tx2_hash, 64);
    
    if (mxd_sign_tx_input(&tx2, 0, alice_private_key) != 0) {
        printf("Failed to sign second transaction input\n");
        return 1;
    }
    
    printf("Attempting double-spend attack:\n");
    printf("  - Input: Alice's already spent UTXO (100.0)\n");
    printf("  - Output: 100.0 back to Alice\n\n");
    
    if (mxd_validate_transaction(&tx2) == 0) {
        printf("ERROR: Double-spend transaction validation succeeded\n");
        return 1;
    }
    
    printf("Double-spend prevention successful: Transaction validation failed\n\n");
    
    if (mxd_save_utxo_db("utxo_demo.db") != 0) {
        printf("Failed to save UTXO database\n");
        return 1;
    }
    
    printf("UTXO database saved to utxo_demo.db\n\n");
    
    if (mxd_init_utxo_db() != 0) {
        printf("Failed to reinitialize UTXO database\n");
        return 1;
    }
    
    if (mxd_find_utxo(tx1.tx_hash, 0, &found_utxo) == 0) {
        printf("ERROR: UTXO database not cleared\n");
        return 1;
    }
    
    printf("UTXO database cleared\n\n");
    
    if (mxd_load_utxo_db("utxo_demo.db") != 0) {
        printf("Failed to load UTXO database\n");
        return 1;
    }
    
    printf("UTXO database loaded from utxo_demo.db\n\n");
    
    if (mxd_find_utxo(tx1.tx_hash, 0, &found_utxo) != 0) {
        printf("ERROR: Bob's UTXO not found after loading database\n");
        return 1;
    }
    
    printf("Bob's UTXO found after loading database with amount %.1f\n", found_utxo.amount);
    
    if (mxd_find_utxo(tx1.tx_hash, 1, &found_utxo) != 0) {
        printf("ERROR: Alice's change UTXO not found after loading database\n");
        return 1;
    }
    
    printf("Alice's change UTXO found after loading database with amount %.1f\n\n", found_utxo.amount);
    
    uint8_t merkle_root[64] = {0};
    if (mxd_calculate_utxo_merkle_root(merkle_root) != 0) {
        printf("Failed to calculate UTXO Merkle root\n");
        return 1;
    }
    
    printf("UTXO Merkle root calculated successfully\n");
    printf("First 8 bytes of Merkle root: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", merkle_root[i]);
    }
    printf("\n\n");
    
    printf("=== UTXO Verification System Demo Completed Successfully ===\n");
    
    remove("utxo_demo.db");
    
    return 0;
}

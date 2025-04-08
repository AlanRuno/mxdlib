#include "../include/mxd_crypto.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_transaction.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static uint8_t test_private_key[32] = {1, 2, 3, 4, 5};
static uint8_t test_public_key[256];
static uint8_t test_private_key2[32] = {6, 7, 8, 9, 10};
static uint8_t test_public_key2[256];

static void setup_test_keys(void) {
  memset(test_public_key, 0, 256);
  memset(test_public_key2, 0, 256);
  memcpy(test_public_key, test_private_key, 32);
  memcpy(test_public_key2, test_private_key2, 32);
}

static void test_transaction_validation_with_utxo(void) {
  TEST_START("Transaction Validation with UTXO");
  
  TEST_ASSERT(mxd_init_utxo_db() == 0, "Initialize UTXO database");
  TEST_ASSERT(mxd_init_transaction_validation() == 0, "Initialize transaction validation");
  
  mxd_utxo_t initial_utxo = {0};
  uint8_t initial_tx_hash[64] = {1};
  
  memcpy(initial_utxo.tx_hash, initial_tx_hash, 64);
  initial_utxo.output_index = 0;
  memcpy(initial_utxo.owner_key, test_public_key, 256);
  initial_utxo.amount = 10.0;
  
  TEST_ASSERT(mxd_add_utxo(&initial_utxo) == 0, "Add initial UTXO to database");
  
  mxd_transaction_t tx;
  TEST_ASSERT(mxd_create_transaction(&tx) == 0, "Create transaction");
  
  TEST_ASSERT(mxd_add_tx_input(&tx, initial_tx_hash, 0, test_public_key) == 0, "Add transaction input");
  
  TEST_ASSERT(mxd_add_tx_output(&tx, test_public_key2, 9.5) == 0, "Add transaction output");
  
  TEST_ASSERT(mxd_set_voluntary_tip(&tx, 0.5) == 0, "Set voluntary tip");
  
  uint8_t tx_hash[64];
  TEST_ASSERT(mxd_calculate_tx_hash(&tx, tx_hash) == 0, "Calculate transaction hash");
  memcpy(tx.tx_hash, tx_hash, 64);
  
  TEST_ASSERT(mxd_sign_tx_input(&tx, 0, test_private_key) == 0, "Sign transaction input");
  
  TEST_ASSERT(mxd_validate_transaction(&tx) == 0, "Validate transaction with UTXO verification");
  
  TEST_ASSERT(mxd_process_transaction(&tx) == 0, "Process transaction");
  
  mxd_utxo_t found_utxo;
  TEST_ASSERT(mxd_find_utxo(initial_tx_hash, 0, &found_utxo) == -1, "Initial UTXO should be spent");
  
  TEST_ASSERT(mxd_find_utxo(tx.tx_hash, 0, &found_utxo) == 0, "New UTXO should exist");
  TEST_ASSERT(found_utxo.amount == 9.5, "New UTXO amount should be correct");
  TEST_ASSERT(memcmp(found_utxo.owner_key, test_public_key2, 256) == 0, "New UTXO owner should be correct");
  
  mxd_free_transaction(tx);
  
  TEST_END("Transaction Validation with UTXO");
}

static void test_double_spend_prevention(void) {
  TEST_START("Double Spend Prevention");
  
  TEST_ASSERT(mxd_init_utxo_db() == 0, "Initialize UTXO database");
  TEST_ASSERT(mxd_init_transaction_validation() == 0, "Initialize transaction validation");
  
  mxd_utxo_t initial_utxo = {0};
  uint8_t initial_tx_hash[64] = {1};
  
  memcpy(initial_utxo.tx_hash, initial_tx_hash, 64);
  initial_utxo.output_index = 0;
  memcpy(initial_utxo.owner_key, test_public_key, 256);
  initial_utxo.amount = 10.0;
  
  TEST_ASSERT(mxd_add_utxo(&initial_utxo) == 0, "Add initial UTXO to database");
  
  mxd_transaction_t tx1;
  TEST_ASSERT(mxd_create_transaction(&tx1) == 0, "Create first transaction");
  
  TEST_ASSERT(mxd_add_tx_input(&tx1, initial_tx_hash, 0, test_public_key) == 0, "Add input to first transaction");
  TEST_ASSERT(mxd_add_tx_output(&tx1, test_public_key2, 10.0) == 0, "Add output to first transaction");
  
  uint8_t tx1_hash[64];
  TEST_ASSERT(mxd_calculate_tx_hash(&tx1, tx1_hash) == 0, "Calculate first transaction hash");
  memcpy(tx1.tx_hash, tx1_hash, 64);
  
  TEST_ASSERT(mxd_sign_tx_input(&tx1, 0, test_private_key) == 0, "Sign first transaction input");
  
  TEST_ASSERT(mxd_validate_transaction(&tx1) == 0, "Validate first transaction");
  TEST_ASSERT(mxd_process_transaction(&tx1) == 0, "Process first transaction");
  
  mxd_transaction_t tx2;
  TEST_ASSERT(mxd_create_transaction(&tx2) == 0, "Create second transaction");
  
  TEST_ASSERT(mxd_add_tx_input(&tx2, initial_tx_hash, 0, test_public_key) == 0, "Add input to second transaction");
  TEST_ASSERT(mxd_add_tx_output(&tx2, test_public_key, 10.0) == 0, "Add output to second transaction");
  
  uint8_t tx2_hash[64];
  TEST_ASSERT(mxd_calculate_tx_hash(&tx2, tx2_hash) == 0, "Calculate second transaction hash");
  memcpy(tx2.tx_hash, tx2_hash, 64);
  
  TEST_ASSERT(mxd_sign_tx_input(&tx2, 0, test_private_key) == 0, "Sign second transaction input");
  
  TEST_ASSERT(mxd_validate_transaction(&tx2) == -1, "Second transaction should fail validation");
  TEST_ASSERT(mxd_process_transaction(&tx2) == -1, "Second transaction should fail processing");
  
  TEST_END("Double Spend Prevention");
}

static void test_insufficient_funds(void) {
  TEST_START("Insufficient Funds Detection");
  
  TEST_ASSERT(mxd_init_utxo_db() == 0, "Initialize UTXO database");
  TEST_ASSERT(mxd_init_transaction_validation() == 0, "Initialize transaction validation");
  
  mxd_utxo_t initial_utxo = {0};
  uint8_t initial_tx_hash[64] = {1};
  
  memcpy(initial_utxo.tx_hash, initial_tx_hash, 64);
  initial_utxo.output_index = 0;
  memcpy(initial_utxo.owner_key, test_public_key, 256);
  initial_utxo.amount = 5.0;
  
  TEST_ASSERT(mxd_add_utxo(&initial_utxo) == 0, "Add initial UTXO to database");
  
  mxd_transaction_t tx;
  TEST_ASSERT(mxd_create_transaction(&tx) == 0, "Create transaction");
  
  TEST_ASSERT(mxd_add_tx_input(&tx, initial_tx_hash, 0, test_public_key) == 0, "Add transaction input");
  TEST_ASSERT(mxd_add_tx_output(&tx, test_public_key2, 6.0) == 0, "Add transaction output");
  
  uint8_t tx_hash[64];
  TEST_ASSERT(mxd_calculate_tx_hash(&tx, tx_hash) == 0, "Calculate transaction hash");
  memcpy(tx.tx_hash, tx_hash, 64);
  
  TEST_ASSERT(mxd_sign_tx_input(&tx, 0, test_private_key) == 0, "Sign transaction input");
  
  TEST_ASSERT(mxd_validate_transaction(&tx) == -1, "Transaction should fail validation");
  
  TEST_END("Insufficient Funds Detection");
}

int main(void) {
  TEST_START("Transaction UTXO Integration Tests");
  
  setup_test_keys();
  test_transaction_validation_with_utxo();
  test_double_spend_prevention();
  test_insufficient_funds();
  
  TEST_END("Transaction UTXO Integration Tests");
  return 0;
}

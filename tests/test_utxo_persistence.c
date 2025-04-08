#include "../include/mxd_crypto.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_transaction.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void test_utxo_persistence(void) {
  TEST_START("UTXO Persistence");
  
  TEST_ASSERT(mxd_init_utxo_db() == 0, "Initialize UTXO database");
  
  mxd_utxo_t utxo1 = {0};
  uint8_t tx_hash1[64] = {1};
  uint8_t owner_key1[256] = {2};
  
  memcpy(utxo1.tx_hash, tx_hash1, 64);
  utxo1.output_index = 0;
  memcpy(utxo1.owner_key, owner_key1, 256);
  utxo1.amount = 1.0;
  
  mxd_utxo_t utxo2 = {0};
  uint8_t tx_hash2[64] = {3};
  uint8_t owner_key2[256] = {4};
  
  memcpy(utxo2.tx_hash, tx_hash2, 64);
  utxo2.output_index = 0;
  memcpy(utxo2.owner_key, owner_key2, 256);
  utxo2.amount = 2.0;
  
  TEST_ASSERT(mxd_add_utxo(&utxo1) == 0, "Add first UTXO to database");
  TEST_ASSERT(mxd_add_utxo(&utxo2) == 0, "Add second UTXO to database");
  
  TEST_ASSERT(mxd_save_utxo_db("test_utxo.db") == 0, "Save UTXO database to file");
  
  TEST_ASSERT(mxd_init_utxo_db() == 0, "Reinitialize UTXO database");
  
  mxd_utxo_t found_utxo;
  TEST_ASSERT(mxd_find_utxo(tx_hash1, 0, &found_utxo) == -1, "Database should be empty");
  
  TEST_ASSERT(mxd_load_utxo_db("test_utxo.db") == 0, "Load UTXO database from file");
  
  TEST_ASSERT(mxd_find_utxo(tx_hash1, 0, &found_utxo) == 0, "Find first UTXO after loading");
  TEST_ASSERT(found_utxo.amount == 1.0, "First UTXO amount is correct");
  
  TEST_ASSERT(mxd_find_utxo(tx_hash2, 0, &found_utxo) == 0, "Find second UTXO after loading");
  TEST_ASSERT(found_utxo.amount == 2.0, "Second UTXO amount is correct");
  
  remove("test_utxo.db");
  
  TEST_END("UTXO Persistence");
}

static void test_utxo_merkle_root(void) {
  TEST_START("UTXO Merkle Root");
  
  TEST_ASSERT(mxd_init_utxo_db() == 0, "Initialize UTXO database");
  
  mxd_utxo_t utxo1 = {0};
  uint8_t tx_hash1[64] = {1};
  uint8_t owner_key1[256] = {2};
  
  memcpy(utxo1.tx_hash, tx_hash1, 64);
  utxo1.output_index = 0;
  memcpy(utxo1.owner_key, owner_key1, 256);
  utxo1.amount = 1.0;
  
  mxd_utxo_t utxo2 = {0};
  uint8_t tx_hash2[64] = {3};
  uint8_t owner_key2[256] = {4};
  
  memcpy(utxo2.tx_hash, tx_hash2, 64);
  utxo2.output_index = 0;
  memcpy(utxo2.owner_key, owner_key2, 256);
  utxo2.amount = 2.0;
  
  TEST_ASSERT(mxd_add_utxo(&utxo1) == 0, "Add first UTXO to database");
  TEST_ASSERT(mxd_add_utxo(&utxo2) == 0, "Add second UTXO to database");
  
  uint8_t root1[64] = {0};
  TEST_ASSERT(mxd_calculate_utxo_merkle_root(root1) == 0, "Calculate Merkle root");
  
  mxd_utxo_t utxo3 = {0};
  uint8_t tx_hash3[64] = {5};
  uint8_t owner_key3[256] = {6};
  
  memcpy(utxo3.tx_hash, tx_hash3, 64);
  utxo3.output_index = 0;
  memcpy(utxo3.owner_key, owner_key3, 256);
  utxo3.amount = 3.0;
  
  TEST_ASSERT(mxd_add_utxo(&utxo3) == 0, "Add third UTXO to database");
  
  uint8_t root2[64] = {0};
  TEST_ASSERT(mxd_calculate_utxo_merkle_root(root2) == 0, "Calculate new Merkle root");
  
  TEST_ASSERT(memcmp(root1, root2, 64) != 0, "Merkle roots should be different");
  
  TEST_END("UTXO Merkle Root");
}

int main(void) {
  TEST_START("UTXO Persistence Tests");
  
  test_utxo_persistence();
  test_utxo_merkle_root();
  
  TEST_END("UTXO Persistence Tests");
  return 0;
}

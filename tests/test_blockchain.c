#include "../include/mxd_blockchain.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_block_initialization(void) {
  mxd_block_t block;
  uint8_t prev_hash[64] = {0};

  assert(mxd_init_block(&block, prev_hash) == 0);
  assert(block.version == 1);
  assert(block.difficulty > 0);

  printf("Block initialization test passed\n");
}

static void test_transaction_handling(void) {
  mxd_block_t block;
  uint8_t prev_hash[64] = {0};
  uint8_t transaction_data[32] = {1, 2, 3, 4};

  assert(mxd_init_block(&block, prev_hash) == 0);
  assert(mxd_add_transaction(&block, transaction_data,
                             sizeof(transaction_data)) == 0);

  // Verify merkle root was updated
  int is_zero = 1;
  for (int i = 0; i < 64; i++) {
    if (block.merkle_root[i] != 0) {
      is_zero = 0;
      break;
    }
  }
  assert(!is_zero);

  printf("Transaction handling test passed\n");
}

static void test_block_validation(void) {
  mxd_block_t block;
  uint8_t prev_hash[64] = {0};
  uint8_t transaction_data[32] = {1, 2, 3, 4};

  assert(mxd_init_block(&block, prev_hash) == 0);
  assert(mxd_add_transaction(&block, transaction_data,
                             sizeof(transaction_data)) == 0);
  assert(mxd_validate_block(&block) == 0);

  // Test invalid version
  block.version = 0;
  assert(mxd_validate_block(&block) == -1);

  printf("Block validation test passed\n");
}

static void test_block_hashing(void) {
  mxd_block_t block;
  uint8_t prev_hash[64] = {0};
  uint8_t hash[64];

  assert(mxd_init_block(&block, prev_hash) == 0);
  assert(mxd_calculate_block_hash(&block, hash) == 0);

  // Hash should not be all zeros
  int is_zero = 1;
  for (int i = 0; i < 64; i++) {
    if (hash[i] != 0) {
      is_zero = 0;
      break;
    }
  }
  assert(!is_zero);

  printf("Block hashing test passed\n");
}

int main(void) {
  printf("Starting blockchain tests...\n");

  test_block_initialization();
  test_transaction_handling();
  test_block_validation();
  test_block_hashing();

  printf("All blockchain tests passed\n");
  return 0;
}

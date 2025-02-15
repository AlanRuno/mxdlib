#include "../include/mxd_smart_contracts.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

// Test WebAssembly code (minimal module)
#include "wasm_binary.h"

// Test input/output values
#define TEST_INPUT_VALUE 5
#define EXPECTED_OUTPUT_VALUE 47 // 5 + 42 (from WebAssembly code)

static void test_contract_initialization(void) {
  assert(mxd_init_contracts() == 0);
  printf("Contract initialization test passed\n");
}

static void test_contract_deployment(void) {
  mxd_contract_state_t state;
  memset(&state, 0, sizeof(state));

  // Initialize contracts module
  assert(mxd_init_contracts() == 0);

  // Deploy contract
  assert(mxd_deploy_contract(test_wasm, sizeof(test_wasm), &state) == 0);

  // Verify contract hash
  int is_zero = 1;
  for (int i = 0; i < 64; i++) {
    if (state.contract_hash[i] != 0) {
      is_zero = 0;
      break;
    }
  }
  assert(!is_zero);

  mxd_free_contract_state(&state);
  printf("Contract deployment test passed\n");
}

static void test_contract_execution(void) {
  mxd_contract_state_t state;
  mxd_execution_result_t result;
  uint32_t input = TEST_INPUT_VALUE;

  // Deploy and execute contract
  assert(mxd_deploy_contract(test_wasm, test_wasm_len, &state) == 0);
  assert(mxd_execute_contract(&state, (uint8_t *)&input, sizeof(input),
                              &result) == 0);

  // Verify result
  assert(result.success);
  assert(result.gas_used > 0);
  assert(*(uint32_t *)result.return_data == EXPECTED_OUTPUT_VALUE);

  mxd_free_contract_state(&state);
  printf("Contract execution test passed\n");
}

static void test_contract_storage(void) {
  mxd_contract_state_t state;
  uint8_t key[4] = {1, 2, 3, 4};
  uint8_t value[4] = {5, 6, 7, 8};
  uint8_t retrieved[4];
  size_t value_size = sizeof(retrieved);

  // Deploy contract
  assert(mxd_deploy_contract(test_wasm, sizeof(test_wasm), &state) == 0);

  // Set storage
  assert(mxd_set_contract_storage(&state, key, sizeof(key), value,
                                  sizeof(value)) == 0);

  // Get storage
  assert(mxd_get_contract_storage(&state, key, sizeof(key), retrieved,
                                  &value_size) == 0);
  assert(value_size == sizeof(value));
  assert(memcmp(value, retrieved, value_size) == 0);

  mxd_free_contract_state(&state);
  printf("Contract storage test passed\n");
}

static void test_state_transition(void) {
  mxd_contract_state_t old_state = {0}, new_state = {0};
  uint8_t key[4] = {1, 2, 3, 4};
  uint8_t value[4] = {5, 6, 7, 8};

  // Deploy contract
  assert(mxd_deploy_contract(test_wasm, test_wasm_len, &old_state) == 0);

  // Create new state with deep copy
  memcpy(&new_state, &old_state, sizeof(mxd_contract_state_t));
  new_state.storage = NULL;
  new_state.storage_size = 0;
  new_state.module = old_state.module; // Share the module between states

  // Modify state
  assert(mxd_set_contract_storage(&new_state, key, sizeof(key), value,
                                  sizeof(value)) == 0);

  // Validate transition
  assert(mxd_validate_state_transition(&old_state, &new_state) == 0);

  mxd_free_contract_state(&old_state);
  mxd_free_contract_state(&new_state);
  printf("State transition test passed\n");
}

static void test_gas_calculation(void) {
  uint64_t gas = mxd_calculate_gas(test_wasm, sizeof(test_wasm));
  assert(gas > 0);
  assert(gas <= MXD_MAX_GAS);

  printf("Gas calculation test passed\n");
}

int main(void) {
  printf("Starting smart contracts tests...\n");

  test_contract_initialization();
  test_contract_deployment();
  test_contract_execution();
  test_contract_storage();
  test_state_transition();
  test_gas_calculation();

  printf("All smart contracts tests passed\n");
  return 0;
}

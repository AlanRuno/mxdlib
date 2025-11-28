#include "mxd_logging.h"

#include "../include/mxd_smart_contracts.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_config.h"
#include "../include/mxd_gas_metering.h"
#include "../include/mxd_merkle_trie.h"
#include "../include/mxd_endian.h"
#include "metrics/mxd_prometheus.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wasm3/wasm3.h>

// WASM runtime state
static struct {
  IM3Environment env;
  IM3Runtime runtime;
} wasm_state = {0};

static inline int contracts_disabled(void) {
  const mxd_config_t* config = mxd_get_config();
  return (!config || !config->contracts.enabled);
}

// Initialize smart contracts module
int mxd_init_contracts(void) {
  if (contracts_disabled()) {
    MXD_LOG_WARN("contracts", "Smart contracts are disabled");
    return -1;
  }
  
  // Free existing environment if any
  if (wasm_state.env) {
    if (wasm_state.runtime) {
      m3_FreeRuntime(wasm_state.runtime);
      wasm_state.runtime = NULL;
    }
    m3_FreeEnvironment(wasm_state.env);
    wasm_state.env = NULL;
  }

  // Free existing runtime if any
  if (wasm_state.runtime) {
    m3_FreeRuntime(wasm_state.runtime);
    wasm_state.runtime = NULL;
  }

  // Free existing environment if any
  if (wasm_state.env) {
    m3_FreeEnvironment(wasm_state.env);
    wasm_state.env = NULL;
  }

  // Initialize new WASM environment
  wasm_state.env = m3_NewEnvironment();
  if (!wasm_state.env) {
    return -1;
  }

  // Create new runtime with 64KB memory
  wasm_state.runtime = m3_NewRuntime(wasm_state.env, 64 * 1024, NULL);
  if (!wasm_state.runtime) {
    m3_FreeEnvironment(wasm_state.env);
    wasm_state.env = NULL;
    return -1;
  }
  return 0;
}

// Deploy contract
int mxd_deploy_contract(const uint8_t *code, size_t code_size,
                        mxd_contract_state_t *state) {
  if (contracts_disabled()) {
    MXD_LOG_WARN("contracts", "Smart contracts are disabled");
    return -1;
  }
  
  if (!code || !state || code_size > MXD_MAX_CONTRACT_SIZE) {
    return -1;
  }

  // Calculate contract hash
  mxd_sha512(code, code_size, state->contract_hash);

    // Initialize state
    memset(state->state_hash, 0, sizeof(state->state_hash));
    state->gas_used = 0;
    state->gas_limit = MXD_MAX_GAS;
    state->storage = NULL;
    state->storage_size = 0;
    state->storage_trie = mxd_trie_create();  // Create merkle trie for production storage

  // Calculate contract hash
  mxd_sha512(code, code_size, state->contract_hash);

  // Ensure runtime is initialized
  if (!wasm_state.env || !wasm_state.runtime) {
    if (mxd_init_contracts() != 0) {
      return -1;
    }
  }

  // Parse WASM module
  IM3Module module = NULL;
  M3Result result = m3_ParseModule(wasm_state.env, &module, code, code_size);
  if (!module || result) {
    MXD_LOG_ERROR("contracts", "Parse error: %s", result);
    return -1;
  }

  // Load module into runtime
  result = m3_LoadModule(wasm_state.runtime, module);
  if (result) {
    MXD_LOG_ERROR("contracts", "Load error: %s", result);
    m3_FreeModule(module);
    return -1;
  }

  // Store module in state for later use
  state->module = module;

  return 0;
}

// Execute contract
int mxd_execute_contract(const mxd_contract_state_t *state,
                         const uint8_t *input, size_t input_size,
                         mxd_execution_result_t *result) {
  if (contracts_disabled()) {
    MXD_LOG_WARN("contracts", "Smart contracts are disabled");
    return -1;
  }
  
  if (!state || !input || !result || input_size > MXD_MAX_CONTRACT_SIZE) {
    return -1;
  }

  memset(result, 0, sizeof(mxd_execution_result_t));

  mxd_config_t* config = mxd_get_config();
  int timeout_seconds = 5;
  if (config && config->contracts.timeout_seconds > 0) {
    timeout_seconds = config->contracts.timeout_seconds;
  }

  time_t start_time = time(NULL);

  IM3Function func;
  M3Result res = m3_FindFunction(&func, wasm_state.runtime, "main");
  if (res) {
    MXD_LOG_ERROR("contracts", "Find function error: %s", res);
    mxd_metrics_increment("contract_execution_errors_total");
    return -1;
  }

  // RISKY FIX: Enforce gas limits during contract execution
  // Simple gas calculation based on input size
  uint64_t gas_used = 100 + input_size;
  
  // Check if gas limit would be exceeded before execution
  if (gas_used > state->gas_limit) {
    MXD_LOG_ERROR("contracts", "Gas limit exceeded before execution: %lu > %lu", gas_used, state->gas_limit);
    mxd_metrics_increment("contract_execution_errors_total");
    return -1;
  }

  uint32_t input_val = *(const uint32_t *)input;
  res = m3_CallV(func, input_val);
  
  time_t end_time = time(NULL);
  if (difftime(end_time, start_time) > timeout_seconds) {
    MXD_LOG_ERROR("contracts", "Contract execution timeout exceeded (%d seconds)", timeout_seconds);
    mxd_metrics_increment("contract_timeouts_total");
    return -1;
  }
  
  if (res) {
    MXD_LOG_ERROR("contracts", "Call error: %s", res);
    mxd_metrics_increment("contract_execution_errors_total");
    return -1;
  }

  uint32_t ret = 0;
  res = m3_GetResultsV(func, &ret);
  if (res) {
    MXD_LOG_ERROR("contracts", "Get results error: %s", res);
    mxd_metrics_increment("contract_execution_errors_total");
    return -1;
  }

  if (sizeof(ret) > sizeof(result->return_data)) {
    return -1;
  }
  memcpy(result->return_data, &ret, sizeof(ret));
  result->return_size = sizeof(ret);
  result->success = 1;
  result->gas_used = gas_used;

  mxd_metrics_increment("contract_executions_total");

  return 0;
}

// Validate contract state transition
int mxd_validate_state_transition(const mxd_contract_state_t *old_state,
                                  const mxd_contract_state_t *new_state) {
  if (contracts_disabled()) {
    MXD_LOG_WARN("contracts", "Smart contracts are disabled");
    return -1;
  }
  
  if (!old_state || !new_state) {
    return -1;
  }

  // Validate contract hash hasn't changed
  if (memcmp(old_state->contract_hash, new_state->contract_hash, 64) != 0) {
    return -1;
  }

  // Validate gas usage
  if (new_state->gas_used > new_state->gas_limit) {
    return -1;
  }

  // Validate state hash only if storage exists
  if (new_state->storage && new_state->storage_size > 0) {
    uint8_t computed_hash[64];
    mxd_sha512(new_state->storage, new_state->storage_size, computed_hash);
    if (memcmp(computed_hash, new_state->state_hash, 64) != 0) {
      return -1;
    }
  } else if (old_state->storage && old_state->storage_size > 0) {
    // If new state has no storage but old state did, that's invalid
    return -1;
  }

  return 0;
}

// Calculate contract gas cost
uint64_t mxd_calculate_gas(const uint8_t *code, size_t code_size) {
  if (contracts_disabled()) {
    MXD_LOG_WARN("contracts", "Smart contracts are disabled");
    return 0;
  }
  
  if (!code) {
    return 0;
  }

  // Use proper gas metering with WASM bytecode analysis
  uint64_t gas_cost = mxd_calculate_gas_from_bytecode(code, code_size);
  
  MXD_LOG_DEBUG("contracts", "Calculated gas cost: %lu for contract size: %zu bytes", 
                gas_cost, code_size);
  
  return gas_cost;
}

// Get contract storage
int mxd_get_contract_storage(const mxd_contract_state_t *state,
                             const uint8_t *key, size_t key_size,
                             uint8_t *value, size_t *value_size) {
  if (contracts_disabled()) {
    MXD_LOG_WARN("contracts", "Smart contracts are disabled");
    return -1;
  }
  
  if (!state || !key || !value || !value_size) {
    return -1;
  }

  // Use merkle patricia trie for production storage (O(log n) lookup with cryptographic verification)
  if (state->storage_trie) {
    mxd_merkle_trie_t *trie = (mxd_merkle_trie_t *)state->storage_trie;
    return mxd_trie_get(trie, key, key_size, value, value_size);
  }

  // Fallback to legacy linear storage for backward compatibility
  if (!state->storage) {
    return -1;
  }

  size_t offset = 0;
  while (offset < state->storage_size) {
    uint64_t stored_key_size_be;
    memcpy(&stored_key_size_be, state->storage + offset, sizeof(uint64_t));
    size_t stored_key_size = (size_t)mxd_ntohll(stored_key_size_be);
    offset += sizeof(uint64_t);

    if (stored_key_size == key_size &&
        memcmp(state->storage + offset, key, key_size) == 0) {
      offset += stored_key_size;
      uint64_t stored_value_size_be;
      memcpy(&stored_value_size_be, state->storage + offset, sizeof(uint64_t));
      size_t stored_value_size = (size_t)mxd_ntohll(stored_value_size_be);
      offset += sizeof(uint64_t);

      if (stored_value_size > *value_size) {
        return -1;
      }

      memcpy(value, state->storage + offset, stored_value_size);
      *value_size = stored_value_size;
      return 0;
    }

    offset += stored_key_size;
    uint64_t stored_value_size_be;
    memcpy(&stored_value_size_be, state->storage + offset, sizeof(uint64_t));
    size_t stored_value_size = (size_t)mxd_ntohll(stored_value_size_be);
    offset += sizeof(uint64_t) + stored_value_size;
  }

  return -1;
}

// Set contract storage
int mxd_set_contract_storage(mxd_contract_state_t *state, const uint8_t *key,
                             size_t key_size, const uint8_t *value,
                             size_t value_size) {
  if (contracts_disabled()) {
    MXD_LOG_WARN("contracts", "Smart contracts are disabled");
    return -1;
  }
  
  if (!state || !key || !value) {
    return -1;
  }

  // Use merkle patricia trie for production storage (O(log n) insert with cryptographic verification)
  // Create trie if it doesn't exist yet
  if (!state->storage_trie) {
    state->storage_trie = mxd_trie_create();
    if (!state->storage_trie) {
      MXD_LOG_ERROR("contracts", "Failed to create storage trie");
      return -1;
    }
  }
  
  mxd_merkle_trie_t *trie = (mxd_merkle_trie_t *)state->storage_trie;
  int result = mxd_trie_set(trie, key, key_size, value, value_size);
  if (result == 0) {
    // Update state hash with merkle root
    mxd_trie_get_root_hash(trie, state->state_hash);
  }
  return result;

  // Fallback to legacy linear storage for backward compatibility
  size_t entry_size = sizeof(uint64_t) + key_size + sizeof(uint64_t) + value_size;
  size_t new_size = state->storage_size + entry_size;

  // Reallocate storage
  uint8_t *new_storage = realloc(state->storage, new_size);
  if (!new_storage) {
    return -1;
  }

  // Add new entry with endian conversion for cross-platform compatibility
  size_t offset = state->storage_size;
  uint64_t key_size_be = mxd_htonll((uint64_t)key_size);
  memcpy(new_storage + offset, &key_size_be, sizeof(uint64_t));
  offset += sizeof(uint64_t);
  memcpy(new_storage + offset, key, key_size);
  offset += key_size;
  uint64_t value_size_be = mxd_htonll((uint64_t)value_size);
  memcpy(new_storage + offset, &value_size_be, sizeof(uint64_t));
  offset += sizeof(uint64_t);
  memcpy(new_storage + offset, value, value_size);

  // Update state
  state->storage = new_storage;
  state->storage_size = new_size;

  // Update state hash
  mxd_sha512(state->storage, state->storage_size, state->state_hash);

  return 0;
}

// Free contract state resources
void mxd_free_contract_state(mxd_contract_state_t *state) {
  if (state) {
    if (state->storage) {
      free(state->storage);
      state->storage = NULL;
    }
    if (state->storage_trie) {
      mxd_trie_free((mxd_merkle_trie_t *)state->storage_trie);
      state->storage_trie = NULL;
    }
    // Note: module is managed by the runtime and shared between states
    memset(state, 0, sizeof(mxd_contract_state_t));
  }
}

#include "mxd_logging.h"

#include "../include/mxd_smart_contracts.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_config.h"
#include "metrics/mxd_prometheus.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wasm3/wasm3.h>

typedef struct {
  uint64_t gas_used;
  uint64_t gas_limit;
  time_t start_time;
  int timeout_seconds;
} mxd_gas_context_t;

// WASM runtime state
static struct {
  IM3Environment env;
  IM3Runtime runtime;
  mxd_gas_context_t gas_ctx;
} wasm_state = {0};

#ifdef M3_COMPILE_WITH_METERING
static m3_wasm_metering_t gas_metering_callback(IM3Runtime runtime, uint32_t opcode, void* userdata) {
  mxd_gas_context_t* ctx = (mxd_gas_context_t*)userdata;
  
  if (!ctx) {
    return m3_MeteringResult_Trap;
  }
  
  time_t current_time = time(NULL);
  if (difftime(current_time, ctx->start_time) > ctx->timeout_seconds) {
    MXD_LOG_ERROR("contracts", "Contract execution timeout exceeded (%d seconds)", ctx->timeout_seconds);
    mxd_metrics_increment("contract_timeouts_total");
    return m3_MeteringResult_Trap;
  }
  
  uint64_t gas_cost = 1;
  
  switch (opcode) {
    case 0x10: gas_cost = 5; break;
    case 0x11: gas_cost = 5; break;
    case 0x28: gas_cost = 2; break;
    case 0x29: gas_cost = 2; break;
    case 0x2a: gas_cost = 2; break;
    case 0x2b: gas_cost = 2; break;
    case 0x2c: gas_cost = 2; break;
    case 0x2d: gas_cost = 2; break;
    case 0x2e: gas_cost = 2; break;
    case 0x2f: gas_cost = 2; break;
    case 0x30: gas_cost = 2; break;
    case 0x31: gas_cost = 2; break;
    case 0x32: gas_cost = 2; break;
    case 0x33: gas_cost = 2; break;
    case 0x34: gas_cost = 2; break;
    case 0x35: gas_cost = 2; break;
    case 0x36: gas_cost = 3; break;
    case 0x37: gas_cost = 3; break;
    case 0x38: gas_cost = 3; break;
    case 0x39: gas_cost = 3; break;
    case 0x3a: gas_cost = 3; break;
    case 0x3b: gas_cost = 3; break;
    case 0x3c: gas_cost = 3; break;
    case 0x3d: gas_cost = 3; break;
    case 0x3e: gas_cost = 3; break;
    case 0x3f: gas_cost = 10; break;
    case 0x40: gas_cost = 10; break;
    default: gas_cost = 1; break;
  }
  
  ctx->gas_used += gas_cost;
  
  if (ctx->gas_used > ctx->gas_limit) {
    MXD_LOG_ERROR("contracts", "Contract gas limit exceeded: %lu > %lu", ctx->gas_used, ctx->gas_limit);
    mxd_metrics_increment("contract_gas_exceeded_total");
    return m3_MeteringResult_Trap;
  }
  
  return m3_MeteringResult_Continue;
}
#endif

// Initialize smart contracts module
int mxd_init_contracts(void) {
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
  if (!state || !input || !result || input_size > MXD_MAX_CONTRACT_SIZE) {
    return -1;
  }

  memset(result, 0, sizeof(mxd_execution_result_t));

  mxd_config_t* config = mxd_get_config();
  int timeout_seconds = 5;
  if (config && config->contracts.execution_timeout_seconds > 0) {
    timeout_seconds = config->contracts.execution_timeout_seconds;
  }

  wasm_state.gas_ctx.gas_used = 0;
  wasm_state.gas_ctx.gas_limit = state->gas_limit;
  wasm_state.gas_ctx.start_time = time(NULL);
  wasm_state.gas_ctx.timeout_seconds = timeout_seconds;

#ifdef M3_COMPILE_WITH_METERING
  m3_SetMeteringCallback(wasm_state.runtime, gas_metering_callback, &wasm_state.gas_ctx);
#endif

  IM3Function func;
  M3Result res = m3_FindFunction(&func, wasm_state.runtime, "main");
  if (res) {
    MXD_LOG_ERROR("contracts", "Find function error: %s", res);
    mxd_metrics_increment("contract_execution_errors_total");
    return -1;
  }

  uint64_t gas_used = 100 + input_size;
  wasm_state.gas_ctx.gas_used = gas_used;

  uint32_t input_val = *(const uint32_t *)input;
  res = m3_CallV(func, input_val);
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

  gas_used = wasm_state.gas_ctx.gas_used;

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
  if (!code) {
    return 0;
  }

  // Simple gas calculation based on code size
  // TODO: Implement proper gas metering
  return code_size * 10;
}

// Get contract storage
int mxd_get_contract_storage(const mxd_contract_state_t *state,
                             const uint8_t *key, size_t key_size,
                             uint8_t *value, size_t *value_size) {
  if (!state || !key || !value || !value_size || !state->storage) {
    return -1;
  }

  // Simple key-value storage implementation (use memcpy to avoid misaligned access)
  // TODO: Implement proper storage with merkle trees
  size_t offset = 0;
  while (offset < state->storage_size) {
    size_t stored_key_size;
    memcpy(&stored_key_size, state->storage + offset, sizeof(size_t));
    offset += sizeof(size_t);

    if (stored_key_size == key_size &&
        memcmp(state->storage + offset, key, key_size) == 0) {
      offset += stored_key_size;
      size_t stored_value_size;
      memcpy(&stored_value_size, state->storage + offset, sizeof(size_t));
      offset += sizeof(size_t);

      if (stored_value_size > *value_size) {
        return -1;
      }

      memcpy(value, state->storage + offset, stored_value_size);
      *value_size = stored_value_size;
      return 0;
    }

    offset += stored_key_size;
    size_t stored_value_size;
    memcpy(&stored_value_size, state->storage + offset, sizeof(size_t));
    offset += sizeof(size_t) + stored_value_size;
  }

  return -1;
}

// Set contract storage
int mxd_set_contract_storage(mxd_contract_state_t *state, const uint8_t *key,
                             size_t key_size, const uint8_t *value,
                             size_t value_size) {
  if (!state || !key || !value) {
    return -1;
  }

  // Calculate new storage size
  size_t entry_size = sizeof(size_t) + key_size + sizeof(size_t) + value_size;
  size_t new_size = state->storage_size + entry_size;

  // Reallocate storage
  uint8_t *new_storage = realloc(state->storage, new_size);
  if (!new_storage) {
    return -1;
  }

  // Add new entry (use memcpy to avoid misaligned access)
  size_t offset = state->storage_size;
  memcpy(new_storage + offset, &key_size, sizeof(size_t));
  offset += sizeof(size_t);
  memcpy(new_storage + offset, key, key_size);
  offset += key_size;
  memcpy(new_storage + offset, &value_size, sizeof(size_t));
  offset += sizeof(size_t);
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
    // Note: module is managed by the runtime and shared between states
    memset(state, 0, sizeof(mxd_contract_state_t));
  }
}

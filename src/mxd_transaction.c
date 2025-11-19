#include "../include/mxd_logging.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_rocksdb_globals.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

static int validation_initialized = 0;

// Initialize transaction validation system
int mxd_init_transaction_validation(void) {
    if (!mxd_get_rocksdb_db()) {
        MXD_LOG_ERROR("transaction", "UTXO database not initialized - must be initialized before transaction validation");
        return -1;
    }
    
    validation_initialized = 1;
    return 0;
}

// Reset transaction validation state
void mxd_reset_transaction_validation(void) {
    // The UTXO database is managed externally, so we just reset the validation state
    validation_initialized = 0;
}

// Create a new transaction
int mxd_create_transaction(mxd_transaction_t *tx) {
  if (!tx) {
    return -1;
  }

  memset(tx, 0, sizeof(mxd_transaction_t));
  tx->version = 2;
  tx->inputs = NULL;
  tx->outputs = NULL;
  tx->input_count = 0;
  tx->output_count = 0;
  tx->voluntary_tip = 0.0;
  tx->timestamp = time(NULL);
  tx->is_coinbase = 0;

  return 0;
}

// Add input to transaction (v2 - algo-aware)
int mxd_add_tx_input(mxd_transaction_t *tx, const uint8_t prev_tx_hash[64],
                     uint32_t output_index, uint8_t algo_id,
                     const uint8_t *public_key, size_t pubkey_len) {
  if (!tx || !prev_tx_hash || !public_key ||
      tx->input_count >= MXD_MAX_TX_INPUTS) {
    return -1;
  }

  mxd_tx_input_t *new_inputs =
      realloc(tx->inputs, (tx->input_count + 1) * sizeof(mxd_tx_input_t));
  if (!new_inputs) {
    return -1;
  }
  tx->inputs = new_inputs;

  mxd_tx_input_t *input = &tx->inputs[tx->input_count];
  memset(input, 0, sizeof(mxd_tx_input_t));
  memcpy(input->prev_tx_hash, prev_tx_hash, 64);
  input->output_index = output_index;
  input->algo_id = algo_id;
  input->public_key_length = (uint16_t)pubkey_len;
  
  input->public_key = malloc(pubkey_len);
  if (!input->public_key) {
    return -1;
  }
  memcpy(input->public_key, public_key, pubkey_len);
  
  input->signature = NULL;
  input->signature_length = 0;
  input->amount = 0.0;

  if (mxd_verify_tx_input_utxo(input, &input->amount) != 0) {
    MXD_LOG_WARN("transaction", "UTXO not found or insufficient funds for input %u", tx->input_count);
  }

  tx->input_count++;
  return 0;
}

// Add output to transaction (v2 - uses address20)
int mxd_add_tx_output(mxd_transaction_t *tx, const uint8_t recipient_addr[20],
                      double amount) {
  if (!tx || !recipient_addr || amount <= 0 ||
      tx->output_count >= MXD_MAX_TX_OUTPUTS) {
    return -1;
  }

  mxd_tx_output_t *new_outputs =
      realloc(tx->outputs, (tx->output_count + 1) * sizeof(mxd_tx_output_t));
  if (!new_outputs) {
    return -1;
  }
  tx->outputs = new_outputs;

  mxd_tx_output_t *output = &tx->outputs[tx->output_count];
  memcpy(output->recipient_addr, recipient_addr, 20);
  output->amount = amount;

  tx->output_count++;
  return 0;
}

// Calculate transaction hash
int mxd_calculate_tx_hash(const mxd_transaction_t *tx, uint8_t hash[64]) {
  if (!tx || !hash) {
    return -1;
  }

  // Calculate buffer size based on actual input lengths
  size_t buffer_size =
      sizeof(uint32_t) * 3 +                            // version + counts
      sizeof(double) +                                   // voluntary tip
      sizeof(uint64_t);                                 // timestamp
  
  // Add input sizes (using actual public key lengths)
  for (uint32_t i = 0; i < tx->input_count; i++) {
    buffer_size += 64 + sizeof(uint32_t) + tx->inputs[i].public_key_length;
  }
  
  // Add output sizes
  buffer_size += tx->output_count * (20 + sizeof(double));

  uint8_t *buffer = malloc(buffer_size);
  if (!buffer) {
    return -1;
  }

  // Serialize transaction data
  size_t offset = 0;
  memcpy(buffer + offset, &tx->version, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  memcpy(buffer + offset, &tx->input_count, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  memcpy(buffer + offset, &tx->output_count, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  memcpy(buffer + offset, &tx->voluntary_tip, sizeof(double));
  offset += sizeof(double);
  memcpy(buffer + offset, &tx->timestamp, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // Serialize inputs (excluding signatures)
  for (uint32_t i = 0; i < tx->input_count; i++) {
    memcpy(buffer + offset, tx->inputs[i].prev_tx_hash, 64);
    offset += 64;
    memcpy(buffer + offset, &tx->inputs[i].output_index, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(buffer + offset, tx->inputs[i].public_key, tx->inputs[i].public_key_length);
    offset += tx->inputs[i].public_key_length;
  }

  // Serialize outputs
  for (uint32_t i = 0; i < tx->output_count; i++) {
    memcpy(buffer + offset, tx->outputs[i].recipient_addr, 20);
    offset += 20;
    memcpy(buffer + offset, &tx->outputs[i].amount, sizeof(double));
    offset += sizeof(double);
  }

  // Calculate double SHA-512 hash
  uint8_t temp_hash[64];
  int result = -1;
  if (mxd_sha512(buffer, offset, temp_hash) == 0 &&
      mxd_sha512(temp_hash, 64, hash) == 0) {
    result = 0;
  }

  free(buffer);
  return result;
}

// Sign transaction input
int mxd_sign_tx_input(mxd_transaction_t *tx, uint32_t input_index,
                      uint8_t algo_id, const uint8_t *private_key) {
  if (!tx || !private_key || input_index >= tx->input_count) {
    return -1;
  }

  uint8_t tx_hash[64];
  if (mxd_calculate_tx_hash(tx, tx_hash) != 0) {
    return -1;
  }

  mxd_tx_input_t *input = &tx->inputs[input_index];
  size_t sig_len = mxd_sig_signature_len(algo_id);
  
  if (input->signature) {
    free(input->signature);
  }
  input->signature = malloc(sig_len);
  if (!input->signature) {
    return -1;
  }

  size_t actual_sig_len = sig_len;
  if (mxd_sig_sign(algo_id, input->signature, &actual_sig_len, tx_hash, 64, private_key) != 0) {
    free(input->signature);
    input->signature = NULL;
    return -1;
  }
  
  input->signature_length = (uint16_t)actual_sig_len;
  return 0;
}

int mxd_verify_tx_input(const mxd_transaction_t *tx, uint32_t input_index) {
  if (!tx || input_index >= tx->input_count) {
    return -1;
  }

  uint8_t tx_hash[64];
  if (mxd_calculate_tx_hash(tx, tx_hash) != 0) {
    return -1;
  }

  const mxd_tx_input_t *input = &tx->inputs[input_index];
  if (!input->signature || input->signature_length == 0) {
    return -1;
  }

  return mxd_sig_verify(input->algo_id, input->signature, input->signature_length,
                        tx_hash, 64, input->public_key);
}

int mxd_validate_transaction(const mxd_transaction_t *tx) {
  MXD_LOG_DEBUG("transaction", "Transaction validation - initialized: %d", validation_initialized);
  if (!validation_initialized || !tx || tx->version != 2 || 
      (tx->input_count == 0 && !tx->is_coinbase) ||
      tx->input_count > MXD_MAX_TX_INPUTS || tx->output_count == 0 ||
      tx->output_count > MXD_MAX_TX_OUTPUTS || tx->voluntary_tip < 0) {
    MXD_LOG_DEBUG("transaction", "Transaction validation failed - early checks");
    return -1;
  }

  if (!tx->is_coinbase) {
    for (uint32_t i = 0; i < tx->input_count; i++) {
      if (mxd_verify_tx_input(tx, i) != 0) {
        MXD_LOG_ERROR("transaction", "Invalid signature on input %u", i);
        return -1;
      }
    }
    
    // Verify transaction inputs against UTXO database
    if (mxd_validate_transaction_inputs(tx) != 0) {
      MXD_LOG_ERROR("transaction", "Transaction validation failed: UTXO verification failed");
      return -1;
    }
  }

  // Verify output amounts are positive
  double total_output = 0;
  for (uint32_t i = 0; i < tx->output_count; i++) {
    if (tx->outputs[i].amount <= 0) {
      return -1;
    }
    total_output += tx->outputs[i].amount;
  }

  // For non-coinbase transactions, verify total output plus tip doesn't exceed input amount
  if (!tx->is_coinbase) {
    double total_input = 0;
    for (uint32_t i = 0; i < tx->input_count; i++) {
      total_input += tx->inputs[i].amount;
    }
    
    if (total_output + tx->voluntary_tip > total_input) {
      MXD_LOG_ERROR("transaction", "Transaction validation failed: outputs (%f) + tip (%f) exceed inputs (%f)",
             total_output, tx->voluntary_tip, total_input);
      return -1;
    }
  }

  // Verify timestamp is set
  if (tx->timestamp == 0) {
    return -1;
  }

  return 0;
}

// Set voluntary tip for transaction
int mxd_set_voluntary_tip(mxd_transaction_t *tx, double tip_amount) {
  if (!tx || tip_amount < 0) {
    return -1;
  }
  tx->voluntary_tip = tip_amount;
  return 0;
}

// Get voluntary tip amount
double mxd_get_voluntary_tip(const mxd_transaction_t *tx) {
  if (!tx) {
    return -1;
  }
  return tx->voluntary_tip;
}

int mxd_peek_voluntary_tip_from_bytes(const uint8_t *data, size_t length, double *tip_out) {
  if (!data || !tip_out) {
    return -1;
  }
  
  _Static_assert(sizeof(double) == 8, "double must be 8 bytes");
  
  const size_t header_min = sizeof(uint32_t) * 3 + sizeof(double) + sizeof(uint64_t);
  
  if (length < header_min) {
    return -1;
  }
  
  uint32_t version;
  memcpy(&version, data, sizeof(uint32_t));
  
  if (version != 2) {
    return -1;
  }
  
  const size_t tip_offset = sizeof(uint32_t) * 3;
  
  double tip_value;
  memcpy(&tip_value, data + tip_offset, sizeof(double));
  
  if (tip_value < 0.0 || !isfinite(tip_value)) {
    *tip_out = 0.0;
  } else {
    *tip_out = tip_value;
  }
  
  return 0;
}

// Validate transaction inputs against UTXO database
int mxd_validate_transaction_inputs(const mxd_transaction_t *tx) {
  if (!tx || tx->is_coinbase) {
    return -1;
  }
  
  // Verify each input UTXO exists and has sufficient funds
  for (uint32_t i = 0; i < tx->input_count; i++) {
    double amount = 0.0;
    if (mxd_verify_tx_input_utxo(&tx->inputs[i], &amount) != 0) {
      MXD_LOG_ERROR("transaction", "UTXO verification failed for input %u", i);
      return -1;
    }
    
    // Verify amount matches cached amount
    if (amount != tx->inputs[i].amount) {
      MXD_LOG_ERROR("transaction", "UTXO amount mismatch for input %u: cached=%f, actual=%f", 
             i, tx->inputs[i].amount, amount);
      return -1;
    }
  }
  
  return 0;
}

// Verify transaction input UTXO exists and has sufficient funds
int mxd_verify_tx_input_utxo(const mxd_tx_input_t *input, double *amount) {
  if (!input || !amount) {
    return -1;
  }
  
  mxd_utxo_t utxo;
  if (mxd_get_utxo(input->prev_tx_hash, input->output_index, &utxo) != 0) {
    MXD_LOG_WARN("transaction", "UTXO not found for given input (index=%u)", input->output_index);
    return -1;
  }
  
  // Verify UTXO is not spent
  if (utxo.is_spent) {
    MXD_LOG_ERROR("transaction", "UTXO is already spent");
    return -1;
  }
  
  uint8_t input_addr[20];
  if (mxd_derive_address(input->algo_id, input->public_key, input->public_key_length, input_addr) != 0) {
    MXD_LOG_ERROR("transaction", "Failed to derive address from input public key");
    return -1;
  }
  
  if (memcmp(utxo.owner_key, input_addr, 20) != 0) {
    MXD_LOG_ERROR("transaction", "UTXO owner address mismatch");
    return -1;
  }
  
  *amount = utxo.amount;
  
  return 0;
}


int mxd_apply_transaction_to_utxo(const mxd_transaction_t *tx) {
  if (!tx) {
    return -1;
  }
  
  // Calculate transaction hash if not already calculated
  uint8_t tx_hash[64];
  if (tx->tx_hash[0] == 0 && tx->tx_hash[1] == 0) {
    if (mxd_calculate_tx_hash(tx, tx_hash) != 0) {
      return -1;
    }
  } else {
    memcpy(tx_hash, tx->tx_hash, 64);
  }
  
  // Create UTXOs from transaction outputs
  if (mxd_create_utxos_from_tx(tx, tx_hash) != 0) {
    MXD_LOG_ERROR("transaction", "Failed to create UTXOs from transaction outputs");
    return -1;
  }
  
  if (!tx->is_coinbase && mxd_mark_tx_inputs_spent(tx) != 0) {
    MXD_LOG_ERROR("transaction", "Failed to mark transaction inputs as spent");
    return -1;
  }
  
  return 0;
}

// Create UTXOs from transaction outputs
int mxd_create_utxos_from_tx(const mxd_transaction_t *tx, const uint8_t tx_hash[64]) {
  if (!tx || !tx_hash) {
    return -1;
  }
  
  for (uint32_t i = 0; i < tx->output_count; i++) {
    mxd_utxo_t utxo;
    memcpy(utxo.tx_hash, tx_hash, 64);
    utxo.output_index = i;
    utxo.amount = tx->outputs[i].amount;
    memcpy(utxo.owner_key, tx->outputs[i].recipient_addr, 20);
    utxo.required_signatures = 1;
    utxo.cosigner_keys = NULL;
    utxo.cosigner_count = 0;
    utxo.is_spent = 0;
    
    if (mxd_add_utxo(&utxo) != 0) {
      MXD_LOG_ERROR("transaction", "Failed to add UTXO for output %u", i);
      return -1;
    }
  }
  
  return 0;
}

// Mark transaction inputs as spent in UTXO database
int mxd_mark_tx_inputs_spent(const mxd_transaction_t *tx) {
  if (!tx || tx->is_coinbase) {
    return -1;
  }
  
  for (uint32_t i = 0; i < tx->input_count; i++) {
    if (mxd_mark_utxo_spent(tx->inputs[i].prev_tx_hash, tx->inputs[i].output_index) != 0) {
      MXD_LOG_ERROR("transaction", "Failed to mark UTXO as spent for input %u", i);
      return -1;
    }
  }
  
  return 0;
}

int mxd_create_coinbase_transaction(mxd_transaction_t *tx, const uint8_t recipient_addr[20],
                                   double reward_amount) {
  if (!tx || !recipient_addr || reward_amount <= 0) {
    return -1;
  }
  
  if (mxd_create_transaction(tx) != 0) {
    return -1;
  }
  
  tx->is_coinbase = 1;
  
  if (mxd_add_tx_output(tx, recipient_addr, reward_amount) != 0) {
    return -1;
  }
  
  return mxd_calculate_tx_hash(tx, tx->tx_hash);
}

int mxd_tx_deep_copy(mxd_transaction_t *dst, const mxd_transaction_t *src) {
  if (!dst || !src) return -1;
  
  memcpy(dst, src, sizeof(mxd_transaction_t));
  dst->inputs = NULL;
  dst->outputs = NULL;
  
  if (src->inputs && src->input_count > 0) {
    dst->inputs = malloc(src->input_count * sizeof(mxd_tx_input_t));
    if (!dst->inputs) return -1;
    
    for (uint32_t i = 0; i < src->input_count; i++) {
      memcpy(&dst->inputs[i], &src->inputs[i], sizeof(mxd_tx_input_t));
      dst->inputs[i].public_key = NULL;
      dst->inputs[i].signature = NULL;
      
      if (src->inputs[i].public_key && src->inputs[i].public_key_length > 0) {
        dst->inputs[i].public_key = malloc(src->inputs[i].public_key_length);
        if (!dst->inputs[i].public_key) {
          mxd_free_transaction(dst);
          return -1;
        }
        memcpy(dst->inputs[i].public_key, src->inputs[i].public_key, 
               src->inputs[i].public_key_length);
      }
      
      if (src->inputs[i].signature && src->inputs[i].signature_length > 0) {
        dst->inputs[i].signature = malloc(src->inputs[i].signature_length);
        if (!dst->inputs[i].signature) {
          mxd_free_transaction(dst);
          return -1;
        }
        memcpy(dst->inputs[i].signature, src->inputs[i].signature,
               src->inputs[i].signature_length);
      }
    }
  }
  
  if (src->outputs && src->output_count > 0) {
    dst->outputs = malloc(src->output_count * sizeof(mxd_tx_output_t));
    if (!dst->outputs) {
      mxd_free_transaction(dst);
      return -1;
    }
    memcpy(dst->outputs, src->outputs, 
           src->output_count * sizeof(mxd_tx_output_t));
  }
  
  return 0;
}

void mxd_free_transaction(mxd_transaction_t *tx) {
  if (tx) {
    for (uint32_t i = 0; i < tx->input_count; i++) {
      if (tx->inputs[i].public_key) {
        free(tx->inputs[i].public_key);
      }
      if (tx->inputs[i].signature) {
        free(tx->inputs[i].signature);
      }
    }
    free(tx->inputs);
    free(tx->outputs);
    memset(tx, 0, sizeof(mxd_transaction_t));
  }
}

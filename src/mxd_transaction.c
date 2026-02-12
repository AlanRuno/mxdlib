#include "../include/mxd_logging.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_rocksdb_globals.h"
#include "../include/mxd_serialize.h"
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
                      mxd_amount_t amount) {
  if (!tx || !recipient_addr || amount == 0 ||
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

  // Calculate buffer size with canonical serialization
  size_t buffer_size =
      4 +                                               // version (u32)
      4 +                                               // input_count (u32)
      4 +                                               // output_count (u32)
      8 +                                               // voluntary_tip (u64)
      8;                                                // timestamp (u64)
  
  // Add input sizes (using actual public key lengths)
  for (uint32_t i = 0; i < tx->input_count; i++) {
    buffer_size += 64 + 4 + 1 + 2 + tx->inputs[i].public_key_length;
  }
  
  // Add output sizes
  buffer_size += tx->output_count * (20 + 8);

  uint8_t *buffer = malloc(buffer_size);
  if (!buffer) {
    return -1;
  }

  // Serialize transaction data using canonical big-endian format
  uint8_t *ptr = buffer;
  
  mxd_write_u32_be(&ptr, tx->version);
  mxd_write_u32_be(&ptr, tx->input_count);
  mxd_write_u32_be(&ptr, tx->output_count);
  mxd_write_u64_be(&ptr, tx->voluntary_tip);
  mxd_write_u64_be(&ptr, tx->timestamp);

  // Serialize inputs (excluding signatures)
  for (uint32_t i = 0; i < tx->input_count; i++) {
    mxd_write_bytes(&ptr, tx->inputs[i].prev_tx_hash, 64);
    mxd_write_u32_be(&ptr, tx->inputs[i].output_index);
    mxd_write_u8(&ptr, tx->inputs[i].algo_id);
    mxd_write_u16_be(&ptr, tx->inputs[i].public_key_length);
    mxd_write_bytes(&ptr, tx->inputs[i].public_key, tx->inputs[i].public_key_length);
  }

  // Serialize outputs
  for (uint32_t i = 0; i < tx->output_count; i++) {
    mxd_write_bytes(&ptr, tx->outputs[i].recipient_addr, 20);
    mxd_write_u64_be(&ptr, tx->outputs[i].amount);
  }

  // Calculate double SHA-512 hash
  uint8_t temp_hash[64];
  int result = -1;
  if (mxd_sha512(buffer, buffer_size, temp_hash) == 0 &&
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

  // Verify output amounts are positive and calculate total using integer arithmetic
  // to ensure consensus-critical calculations are deterministic across platforms
  mxd_amount_t total_output = 0;
  for (uint32_t i = 0; i < tx->output_count; i++) {
    if (tx->outputs[i].amount == 0) {
      MXD_LOG_ERROR("transaction", "Transaction validation failed: output %u has zero amount", i);
      return -1;
    }
    // Check for overflow before adding
    if (total_output > UINT64_MAX - tx->outputs[i].amount) {
      MXD_LOG_ERROR("transaction", "Transaction validation failed: output sum overflow");
      return -1;
    }
    total_output += tx->outputs[i].amount;
  }

  // For non-coinbase transactions, verify total output plus tip doesn't exceed input amount
  if (!tx->is_coinbase) {
    mxd_amount_t total_input = 0;
    for (uint32_t i = 0; i < tx->input_count; i++) {
      // Check for overflow before adding
      if (total_input > UINT64_MAX - tx->inputs[i].amount) {
        MXD_LOG_ERROR("transaction", "Transaction validation failed: input sum overflow");
        return -1;
      }
      total_input += tx->inputs[i].amount;
    }
    
    // Check for overflow when adding tip to outputs
    if (total_output > UINT64_MAX - tx->voluntary_tip) {
      MXD_LOG_ERROR("transaction", "Transaction validation failed: output + tip overflow");
      return -1;
    }
    
    if (total_output + tx->voluntary_tip > total_input) {
      MXD_LOG_ERROR("transaction", "Transaction validation failed: outputs (%lu) + tip (%lu) exceed inputs (%lu)",
             (unsigned long)total_output, (unsigned long)tx->voluntary_tip, (unsigned long)total_input);
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
int mxd_set_voluntary_tip(mxd_transaction_t *tx, mxd_amount_t tip_amount) {
  if (!tx) {
    return -1;
  }
  tx->voluntary_tip = tip_amount;
  return 0;
}

// Get voluntary tip amount
mxd_amount_t mxd_get_voluntary_tip(const mxd_transaction_t *tx) {
  if (!tx) {
    return 0;
  }
  return tx->voluntary_tip;
}

int mxd_peek_voluntary_tip_from_bytes(const uint8_t *data, size_t length, mxd_amount_t *tip_out) {
  if (!data || !tip_out) {
    return -1;
  }
  
  const size_t header_min = sizeof(uint32_t) * 3 + sizeof(uint64_t) + sizeof(uint64_t);
  
  if (length < header_min) {
    return -1;
  }
  
  uint32_t version;
  memcpy(&version, data, sizeof(uint32_t));
  
  if (version != 2) {
    return -1;
  }
  
  const size_t tip_offset = sizeof(uint32_t) * 3;
  
  uint64_t tip_value;
  memcpy(&tip_value, data + tip_offset, sizeof(uint64_t));
  
  *tip_out = tip_value;
  
  return 0;
}

// Validate transaction inputs against UTXO database
int mxd_validate_transaction_inputs(const mxd_transaction_t *tx) {
  if (!tx || tx->is_coinbase) {
    return -1;
  }
  
  // Verify each input UTXO exists and has sufficient funds
  for (uint32_t i = 0; i < tx->input_count; i++) {
    mxd_amount_t amount = 0;
    if (mxd_verify_tx_input_utxo(&tx->inputs[i], &amount) != 0) {
      MXD_LOG_ERROR("transaction", "UTXO verification failed for input %u", i);
      return -1;
    }
    
    // Verify amount matches cached amount
    if (amount != tx->inputs[i].amount) {
      MXD_LOG_ERROR("transaction", "UTXO amount mismatch for input %u: cached=%lu, actual=%lu", 
             i, tx->inputs[i].amount, amount);
      return -1;
    }
  }
  
  return 0;
}

// Verify transaction input UTXO exists and has sufficient funds
int mxd_verify_tx_input_utxo(const mxd_tx_input_t *input, mxd_amount_t *amount) {
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
  
  // Mark inputs as spent FIRST (before creating outputs)
  // This prevents supply inflation: if input UTXOs don't exist (e.g. because
  // the transaction wasn't gossiped to this node), we fail early without
  // creating orphan output UTXOs that would mint coins from nothing.
  if (!tx->is_coinbase && mxd_mark_tx_inputs_spent(tx) != 0) {
    MXD_LOG_ERROR("transaction", "Failed to mark transaction inputs as spent");
    return -1;
  }

  // Create UTXOs from transaction outputs only after inputs are validated
  if (mxd_create_utxos_from_tx(tx, tx_hash) != 0) {
    MXD_LOG_ERROR("transaction", "Failed to create UTXOs from transaction outputs");
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

// Serialize transaction to bytes for P2P broadcast
uint8_t* mxd_serialize_transaction(const mxd_transaction_t *tx, size_t *out_len) {
  if (!tx || !out_len) return NULL;

  // Calculate total size
  size_t size = 4 + 4 + 4 + 8 + 8 + 1 + 64; // header fields

  for (uint32_t i = 0; i < tx->input_count; i++) {
    size += 64 + 4 + 1 + 2 + tx->inputs[i].public_key_length + 2 + tx->inputs[i].signature_length;
  }

  for (uint32_t i = 0; i < tx->output_count; i++) {
    size += 20 + 8;
  }

  uint8_t *buffer = malloc(size);
  if (!buffer) return NULL;

  uint8_t *ptr = buffer;
  mxd_write_u32_be(&ptr, tx->version);
  mxd_write_u32_be(&ptr, tx->input_count);
  mxd_write_u32_be(&ptr, tx->output_count);
  mxd_write_u64_be(&ptr, tx->voluntary_tip);
  mxd_write_u64_be(&ptr, tx->timestamp);
  mxd_write_u8(&ptr, tx->is_coinbase);
  mxd_write_bytes(&ptr, tx->tx_hash, 64);

  for (uint32_t i = 0; i < tx->input_count; i++) {
    mxd_write_bytes(&ptr, tx->inputs[i].prev_tx_hash, 64);
    mxd_write_u32_be(&ptr, tx->inputs[i].output_index);
    mxd_write_u8(&ptr, tx->inputs[i].algo_id);
    mxd_write_u16_be(&ptr, tx->inputs[i].public_key_length);
    mxd_write_bytes(&ptr, tx->inputs[i].public_key, tx->inputs[i].public_key_length);
    mxd_write_u16_be(&ptr, tx->inputs[i].signature_length);
    if (tx->inputs[i].signature_length > 0 && tx->inputs[i].signature) {
      mxd_write_bytes(&ptr, tx->inputs[i].signature, tx->inputs[i].signature_length);
    }
  }

  for (uint32_t i = 0; i < tx->output_count; i++) {
    mxd_write_bytes(&ptr, tx->outputs[i].recipient_addr, 20);
    mxd_write_u64_be(&ptr, tx->outputs[i].amount);
  }

  *out_len = size;
  return buffer;
}

int mxd_create_coinbase_transaction(mxd_transaction_t *tx, const uint8_t recipient_addr[20],
                                   mxd_amount_t reward_amount) {
  if (!tx || !recipient_addr || reward_amount == 0) {
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
    if (tx->inputs) {
      for (uint32_t i = 0; i < tx->input_count; i++) {
        if (tx->inputs[i].public_key) {
          free(tx->inputs[i].public_key);
        }
        if (tx->inputs[i].signature) {
          free(tx->inputs[i].signature);
        }
      }
      free(tx->inputs);
    }
    if (tx->outputs) {
      free(tx->outputs);
    }
    memset(tx, 0, sizeof(mxd_transaction_t));
  }
}

// ========== Bridge Transaction Functions (v3) ==========

// Create a bridge mint transaction (BNB → MXD)
int mxd_create_bridge_mint_tx(mxd_transaction_v3_t *tx,
                               const mxd_bridge_payload_t *payload) {
  if (!tx || !payload) {
    return -1;
  }

  memset(tx, 0, sizeof(mxd_transaction_v3_t));
  tx->version = 3;
  tx->type = MXD_TX_TYPE_BRIDGE_MINT;
  tx->input_count = 0;  // Bridge mints have no inputs
  tx->output_count = 0;
  tx->voluntary_tip = 0;
  tx->timestamp = time(NULL);
  tx->inputs = NULL;
  tx->outputs = NULL;

  // Allocate and copy bridge payload
  tx->payload.bridge = malloc(sizeof(mxd_bridge_payload_t));
  if (!tx->payload.bridge) {
    return -1;
  }
  memcpy(tx->payload.bridge, payload, sizeof(mxd_bridge_payload_t));

  // Create output for minted MXD
  tx->outputs = malloc(sizeof(mxd_tx_output_t));
  if (!tx->outputs) {
    free(tx->payload.bridge);
    tx->payload.bridge = NULL;
    return -1;
  }

  memcpy(tx->outputs[0].recipient_addr, payload->recipient_addr, 20);
  tx->outputs[0].amount = payload->amount;
  tx->output_count = 1;

  return 0;
}

// Create a bridge burn transaction (MXD → BNB)
int mxd_create_bridge_burn_tx(mxd_transaction_v3_t *tx,
                               const uint8_t sender_addr[20],
                               mxd_amount_t burn_amount,
                               const uint8_t bridge_contract[64],
                               uint32_t dest_chain_id,
                               const uint8_t dest_recipient[20]) {
  if (!tx || !sender_addr || !bridge_contract || !dest_recipient || burn_amount == 0) {
    return -1;
  }

  memset(tx, 0, sizeof(mxd_transaction_v3_t));
  tx->version = 3;
  tx->type = MXD_TX_TYPE_BRIDGE_BURN;
  tx->input_count = 0;  // Will be set when inputs are added
  tx->output_count = 0;
  tx->voluntary_tip = 0;
  tx->timestamp = time(NULL);
  tx->inputs = NULL;
  tx->outputs = NULL;

  // Allocate bridge payload
  tx->payload.bridge = malloc(sizeof(mxd_bridge_payload_t));
  if (!tx->payload.bridge) {
    return -1;
  }

  // Initialize bridge payload
  memcpy(tx->payload.bridge->bridge_contract, bridge_contract, 64);
  memset(tx->payload.bridge->source_chain_id, 0, 32);
  // Store dest_chain_id in source_chain_id field (repurposed for burn)
  memcpy(tx->payload.bridge->source_chain_id, &dest_chain_id, sizeof(uint32_t));
  memset(tx->payload.bridge->source_tx_hash, 0, 32);  // Not applicable for burn
  tx->payload.bridge->source_block_number = 0;         // Not applicable for burn
  memcpy(tx->payload.bridge->recipient_addr, dest_recipient, 20);
  tx->payload.bridge->amount = burn_amount;
  tx->payload.bridge->proof_length = 0;                // No proof needed for burn
  memset(tx->payload.bridge->proof, 0, 1024);

  // Create burn output (to zero address)
  tx->outputs = malloc(sizeof(mxd_tx_output_t));
  if (!tx->outputs) {
    free(tx->payload.bridge);
    tx->payload.bridge = NULL;
    return -1;
  }

  // Burn address (all zeros)
  memset(tx->outputs[0].recipient_addr, 0, 20);
  tx->outputs[0].amount = burn_amount;
  tx->output_count = 1;

  return 0;
}

// Validate bridge mint transaction
int mxd_validate_bridge_mint_tx(const mxd_transaction_v3_t *tx) {
  if (!tx || tx->version != 3 || tx->type != MXD_TX_TYPE_BRIDGE_MINT) {
    MXD_LOG_ERROR("transaction", "Invalid bridge mint transaction: wrong version or type");
    return -1;
  }

  if (!tx->payload.bridge) {
    MXD_LOG_ERROR("transaction", "Bridge mint transaction missing payload");
    return -1;
  }

  mxd_bridge_payload_t *bridge = tx->payload.bridge;

  // 1. Verify bridge contract is authorized
  if (!mxd_is_bridge_contract_authorized(bridge->bridge_contract)) {
    MXD_LOG_ERROR("transaction", "Bridge contract not authorized");
    return -1;
  }

  // 2. Verify source chain is supported (BNB mainnet 56 or testnet 97)
  uint32_t chain_id;
  memcpy(&chain_id, bridge->source_chain_id, sizeof(uint32_t));
  if (chain_id != 56 && chain_id != 97) {
    MXD_LOG_ERROR("transaction", "Unsupported source chain ID: %u", chain_id);
    return -1;
  }

  // 3. Verify source transaction hasn't been processed before (replay protection)
  if (mxd_is_bridge_tx_processed(bridge->source_tx_hash)) {
    MXD_LOG_ERROR("transaction", "Bridge transaction already processed (replay attack)");
    return -1;
  }

  // 4. Verify amount is positive
  if (bridge->amount == 0) {
    MXD_LOG_ERROR("transaction", "Bridge mint amount must be positive");
    return -1;
  }

  // 5. Verify recipient address is valid (not zero)
  uint8_t zero_addr[20] = {0};
  if (memcmp(bridge->recipient_addr, zero_addr, 20) == 0) {
    MXD_LOG_ERROR("transaction", "Bridge mint recipient cannot be zero address");
    return -1;
  }

  // 6. Verify proof is present
  if (bridge->proof_length == 0 || bridge->proof_length > 1024) {
    MXD_LOG_ERROR("transaction", "Invalid bridge proof length: %u", bridge->proof_length);
    return -1;
  }

  // 7. Verify transaction has exactly one output matching the payload
  if (tx->output_count != 1) {
    MXD_LOG_ERROR("transaction", "Bridge mint must have exactly one output");
    return -1;
  }

  if (memcmp(tx->outputs[0].recipient_addr, bridge->recipient_addr, 20) != 0) {
    MXD_LOG_ERROR("transaction", "Output recipient mismatch");
    return -1;
  }

  if (tx->outputs[0].amount != bridge->amount) {
    MXD_LOG_ERROR("transaction", "Output amount mismatch");
    return -1;
  }

  // 8. Verify no inputs (mint creates new coins)
  if (tx->input_count != 0) {
    MXD_LOG_ERROR("transaction", "Bridge mint must have zero inputs");
    return -1;
  }

  return 0;
}

// Validate bridge burn transaction
int mxd_validate_bridge_burn_tx(const mxd_transaction_v3_t *tx) {
  if (!tx || tx->version != 3 || tx->type != MXD_TX_TYPE_BRIDGE_BURN) {
    MXD_LOG_ERROR("transaction", "Invalid bridge burn transaction: wrong version or type");
    return -1;
  }

  if (!tx->payload.bridge) {
    MXD_LOG_ERROR("transaction", "Bridge burn transaction missing payload");
    return -1;
  }

  mxd_bridge_payload_t *bridge = tx->payload.bridge;

  // 1. Verify bridge contract is authorized
  if (!mxd_is_bridge_contract_authorized(bridge->bridge_contract)) {
    MXD_LOG_ERROR("transaction", "Bridge contract not authorized");
    return -1;
  }

  // 2. Verify destination chain is supported
  uint32_t dest_chain_id;
  memcpy(&dest_chain_id, bridge->source_chain_id, sizeof(uint32_t));
  if (dest_chain_id != 56 && dest_chain_id != 97) {
    MXD_LOG_ERROR("transaction", "Unsupported destination chain ID: %u", dest_chain_id);
    return -1;
  }

  // 3. Verify amount is positive
  if (bridge->amount == 0) {
    MXD_LOG_ERROR("transaction", "Bridge burn amount must be positive");
    return -1;
  }

  // 4. Verify recipient address is valid (not zero)
  uint8_t zero_addr[20] = {0};
  if (memcmp(bridge->recipient_addr, zero_addr, 20) == 0) {
    MXD_LOG_ERROR("transaction", "Bridge burn recipient cannot be zero address");
    return -1;
  }

  // 5. Verify transaction has exactly one output to burn address
  if (tx->output_count != 1) {
    MXD_LOG_ERROR("transaction", "Bridge burn must have exactly one output");
    return -1;
  }

  if (memcmp(tx->outputs[0].recipient_addr, zero_addr, 20) != 0) {
    MXD_LOG_ERROR("transaction", "Bridge burn output must be to zero address");
    return -1;
  }

  if (tx->outputs[0].amount != bridge->amount) {
    MXD_LOG_ERROR("transaction", "Output amount mismatch");
    return -1;
  }

  // 6. Verify inputs exist and are valid
  if (tx->input_count == 0) {
    MXD_LOG_ERROR("transaction", "Bridge burn must have inputs");
    return -1;
  }

  // 7. Validate inputs against UTXO database
  mxd_amount_t total_input = 0;
  for (uint32_t i = 0; i < tx->input_count; i++) {
    mxd_amount_t amount = 0;
    if (mxd_verify_tx_input_utxo(&tx->inputs[i], &amount) != 0) {
      MXD_LOG_ERROR("transaction", "Invalid UTXO for burn input %u", i);
      return -1;
    }

    // Check for overflow
    if (total_input > UINT64_MAX - amount) {
      MXD_LOG_ERROR("transaction", "Input sum overflow in bridge burn");
      return -1;
    }
    total_input += amount;
  }

  // 8. Verify total input >= burn amount + fee
  mxd_amount_t required = bridge->amount + tx->voluntary_tip;
  if (total_input < required) {
    MXD_LOG_ERROR("transaction", "Insufficient input for bridge burn: have %lu, need %lu",
                  (unsigned long)total_input, (unsigned long)required);
    return -1;
  }

  return 0;
}

// Check if bridge transaction already processed (replay protection)
int mxd_is_bridge_tx_processed(const uint8_t source_tx_hash[32]) {
  if (!source_tx_hash) {
    return 0;
  }

  rocksdb_t *db = mxd_get_rocksdb_db();
  if (!db) {
    MXD_LOG_ERROR("transaction", "Database not initialized");
    return 0;
  }

  // Create key: "bridge_tx:" + source_tx_hash
  uint8_t key[42];
  memcpy(key, "bridge_tx:", 10);
  memcpy(key + 10, source_tx_hash, 32);

  rocksdb_readoptions_t *readopts = rocksdb_readoptions_create();
  char *err = NULL;
  size_t val_len;

  char *value = rocksdb_get(db, readopts, (const char *)key, 42, &val_len, &err);

  rocksdb_readoptions_destroy(readopts);

  if (err) {
    MXD_LOG_ERROR("transaction", "Database error checking bridge tx: %s", err);
    free(err);
    return 0;
  }

  if (value) {
    free(value);
    return 1;  // Already processed
  }

  return 0;  // Not processed
}

// Mark bridge transaction as processed
int mxd_mark_bridge_tx_processed(const mxd_bridge_payload_t *payload,
                                  const uint8_t mxd_tx_hash[64],
                                  uint32_t block_index) {
  if (!payload || !mxd_tx_hash) {
    return -1;
  }

  rocksdb_t *db = mxd_get_rocksdb_db();
  if (!db) {
    MXD_LOG_ERROR("transaction", "Database not initialized");
    return -1;
  }

  // Create key: "bridge_tx:" + source_tx_hash
  uint8_t key[42];
  memcpy(key, "bridge_tx:", 10);
  memcpy(key + 10, payload->source_tx_hash, 32);

  // Create value: mxd_tx_hash (64 bytes) + block_index (4 bytes)
  uint8_t value[68];
  memcpy(value, mxd_tx_hash, 64);
  memcpy(value + 64, &block_index, 4);

  rocksdb_writeoptions_t *writeopts = rocksdb_writeoptions_create();
  char *err = NULL;

  rocksdb_put(db, writeopts, (const char *)key, 42, (const char *)value, 68, &err);

  rocksdb_writeoptions_destroy(writeopts);

  if (err) {
    MXD_LOG_ERROR("transaction", "Failed to mark bridge tx as processed: %s", err);
    free(err);
    return -1;
  }

  MXD_LOG_INFO("transaction", "Marked bridge transaction as processed at block %u", block_index);
  return 0;
}

// Verify bridge contract is authorized
int mxd_is_bridge_contract_authorized(const uint8_t contract_hash[64]) {
  if (!contract_hash) {
    return 0;
  }

  rocksdb_t *db = mxd_get_rocksdb_db();
  if (!db) {
    MXD_LOG_ERROR("transaction", "Database not initialized");
    return 0;
  }

  // Create key: "bridge_auth:" + contract_hash
  uint8_t key[76];
  memcpy(key, "bridge_auth:", 12);
  memcpy(key + 12, contract_hash, 64);

  rocksdb_readoptions_t *readopts = rocksdb_readoptions_create();
  char *err = NULL;
  size_t val_len;

  char *value = rocksdb_get(db, readopts, (const char *)key, 76, &val_len, &err);

  rocksdb_readoptions_destroy(readopts);

  if (err) {
    MXD_LOG_ERROR("transaction", "Database error checking bridge auth: %s", err);
    free(err);
    return 0;
  }

  if (value) {
    // Check if not revoked (value should be "1" for authorized, "0" for revoked)
    int authorized = (val_len > 0 && value[0] == '1');
    free(value);
    return authorized;
  }

  return 0;  // Not authorized
}

// Calculate v3 transaction hash
int mxd_calculate_tx_hash_v3(const mxd_transaction_v3_t *tx, uint8_t hash[64]) {
  if (!tx || !hash) {
    return -1;
  }

  // Calculate buffer size
  size_t buffer_size =
      4 +                                               // version (u32)
      4 +                                               // type (u32)
      4 +                                               // input_count (u32)
      4 +                                               // output_count (u32)
      8 +                                               // voluntary_tip (u64)
      8;                                                // timestamp (u64)

  // Add input sizes
  for (uint32_t i = 0; i < tx->input_count; i++) {
    buffer_size += 64 + 4 + 1 + 2 + tx->inputs[i].public_key_length;
  }

  // Add output sizes
  buffer_size += tx->output_count * (20 + 8);

  // Add bridge payload size if applicable
  if (tx->type == MXD_TX_TYPE_BRIDGE_MINT || tx->type == MXD_TX_TYPE_BRIDGE_BURN) {
    if (!tx->payload.bridge) {
      return -1;
    }
    buffer_size += sizeof(mxd_bridge_payload_t);
  }

  uint8_t *buffer = malloc(buffer_size);
  if (!buffer) {
    return -1;
  }

  // Serialize transaction data
  uint8_t *ptr = buffer;

  mxd_write_u32_be(&ptr, tx->version);
  mxd_write_u32_be(&ptr, (uint32_t)tx->type);
  mxd_write_u32_be(&ptr, tx->input_count);
  mxd_write_u32_be(&ptr, tx->output_count);
  mxd_write_u64_be(&ptr, tx->voluntary_tip);
  mxd_write_u64_be(&ptr, tx->timestamp);

  // Serialize inputs
  for (uint32_t i = 0; i < tx->input_count; i++) {
    mxd_write_bytes(&ptr, tx->inputs[i].prev_tx_hash, 64);
    mxd_write_u32_be(&ptr, tx->inputs[i].output_index);
    mxd_write_u8(&ptr, tx->inputs[i].algo_id);
    mxd_write_u16_be(&ptr, tx->inputs[i].public_key_length);
    mxd_write_bytes(&ptr, tx->inputs[i].public_key, tx->inputs[i].public_key_length);
  }

  // Serialize outputs
  for (uint32_t i = 0; i < tx->output_count; i++) {
    mxd_write_bytes(&ptr, tx->outputs[i].recipient_addr, 20);
    mxd_write_u64_be(&ptr, tx->outputs[i].amount);
  }

  // Serialize bridge payload
  if (tx->type == MXD_TX_TYPE_BRIDGE_MINT || tx->type == MXD_TX_TYPE_BRIDGE_BURN) {
    mxd_bridge_payload_t *bridge = tx->payload.bridge;
    mxd_write_bytes(&ptr, bridge->bridge_contract, 64);
    mxd_write_bytes(&ptr, bridge->source_chain_id, 32);
    mxd_write_bytes(&ptr, bridge->source_tx_hash, 32);
    mxd_write_u64_be(&ptr, bridge->source_block_number);
    mxd_write_bytes(&ptr, bridge->recipient_addr, 20);
    mxd_write_u64_be(&ptr, bridge->amount);
    mxd_write_u16_be(&ptr, bridge->proof_length);
    mxd_write_bytes(&ptr, bridge->proof, bridge->proof_length);
  }

  // Calculate double SHA-512 hash
  uint8_t temp_hash[64];
  int result = -1;
  if (mxd_sha512(buffer, buffer_size, temp_hash) == 0 &&
      mxd_sha512(temp_hash, 64, hash) == 0) {
    result = 0;
  }

  free(buffer);
  return result;
}

// Validate v3 transaction
int mxd_validate_transaction_v3(const mxd_transaction_v3_t *tx) {
  if (!tx || tx->version != 3) {
    return -1;
  }

  // Dispatch to type-specific validation
  switch (tx->type) {
    case MXD_TX_TYPE_BRIDGE_MINT:
      return mxd_validate_bridge_mint_tx(tx);

    case MXD_TX_TYPE_BRIDGE_BURN:
      return mxd_validate_bridge_burn_tx(tx);

    case MXD_TX_TYPE_REGULAR:
    case MXD_TX_TYPE_COINBASE:
      // Regular/coinbase transactions use v2 validation logic
      // (would need to convert to v2 structure or adapt validation)
      MXD_LOG_ERROR("transaction", "Regular/coinbase should use v2 transactions");
      return -1;

    case MXD_TX_TYPE_CONTRACT_DEPLOY:
    case MXD_TX_TYPE_CONTRACT_CALL:
      MXD_LOG_ERROR("transaction", "Contract transactions not yet implemented");
      return -1;

    default:
      MXD_LOG_ERROR("transaction", "Unknown transaction type: %d", tx->type);
      return -1;
  }
}

// Free v3 transaction resources
void mxd_free_transaction_v3(mxd_transaction_v3_t *tx) {
  if (tx) {
    if (tx->inputs) {
      for (uint32_t i = 0; i < tx->input_count; i++) {
        if (tx->inputs[i].public_key) {
          free(tx->inputs[i].public_key);
        }
        if (tx->inputs[i].signature) {
          free(tx->inputs[i].signature);
        }
      }
      free(tx->inputs);
    }
    if (tx->outputs) {
      free(tx->outputs);
    }
    if (tx->type == MXD_TX_TYPE_BRIDGE_MINT || tx->type == MXD_TX_TYPE_BRIDGE_BURN) {
      if (tx->payload.bridge) {
        free(tx->payload.bridge);
      }
    }
    memset(tx, 0, sizeof(mxd_transaction_v3_t));
  }
}

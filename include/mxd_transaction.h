#ifndef MXD_TRANSACTION_H
#define MXD_TRANSACTION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "mxd_types.h"

// Transaction types
typedef enum {
    MXD_TX_TYPE_REGULAR = 0,
    MXD_TX_TYPE_COINBASE = 1,
    MXD_TX_TYPE_CONTRACT_DEPLOY = 2,
    MXD_TX_TYPE_CONTRACT_CALL = 3,
    MXD_TX_TYPE_BRIDGE_MINT = 4,      // Bridge minting (BNB → MXD)
    MXD_TX_TYPE_BRIDGE_BURN = 5       // Bridge burning (MXD → BNB)
} mxd_tx_type_t;

// Bridge transaction payload
typedef struct {
    uint8_t bridge_contract[64];      // Bridge contract hash
    uint8_t source_chain_id[32];      // BNB Chain ID (56 mainnet, 97 testnet)
    uint8_t source_tx_hash[32];       // BNB transaction hash
    uint64_t source_block_number;     // BNB block number
    uint8_t recipient_addr[20];       // MXD recipient address
    mxd_amount_t amount;              // Amount to mint/burn
    uint8_t proof[1024];              // Merkle proof or signature
    uint16_t proof_length;
} mxd_bridge_payload_t;

// Initialize transaction validation system
int mxd_init_transaction_validation(void);

// Reset transaction validation state
void mxd_reset_transaction_validation(void);

// Maximum number of inputs/outputs per transaction
#define MXD_MAX_TX_INPUTS 256
#define MXD_MAX_TX_OUTPUTS 256

// Transaction input structure (v2 - algo-aware)
typedef struct {
  uint8_t prev_tx_hash[64];     // Previous transaction hash (SHA-512)
  uint32_t output_index;        // Index of the output in previous transaction
  uint8_t algo_id;              // Algorithm ID (Ed25519=1, Dilithium5=2)
  uint16_t public_key_length;   // Length of public key
  uint8_t *public_key;          // Signer's public key (variable length)
  uint16_t signature_length;    // Length of signature
  uint8_t *signature;           // Signature (variable length)
  mxd_amount_t amount;          // Amount from the UTXO (cached for validation, in base units)
} mxd_tx_input_t;

// Transaction output structure (v2 - uses address20)
typedef struct {
  uint8_t recipient_addr[20];   // Recipient's address (HASH160(algo_id || pubkey))
  mxd_amount_t amount;          // Amount to transfer (in base units)
} mxd_tx_output_t;

// Transaction structure (v2)
typedef struct {
  uint32_t version;         // Transaction version (v2 for hybrid crypto)
  uint32_t input_count;     // Number of inputs
  uint32_t output_count;    // Number of outputs
  mxd_amount_t voluntary_tip; // Optional tip for node operators (in base units)
  uint64_t timestamp;       // Transaction timestamp (NTP synchronized, Unix seconds)
  mxd_tx_input_t *inputs;   // Array of inputs (variable-length keys/sigs)
  mxd_tx_output_t *outputs; // Array of outputs (address20 format)
  uint8_t tx_hash[64];      // Transaction hash (SHA-512)
  uint8_t is_coinbase;      // Flag indicating if this is a coinbase transaction
} mxd_transaction_t;

// Extended transaction structure (v3 - bridge support)
typedef struct {
  uint32_t version;           // Transaction version (v3 for bridge support)
  mxd_tx_type_t type;         // Transaction type
  uint32_t input_count;       // Number of inputs
  uint32_t output_count;      // Number of outputs
  mxd_amount_t voluntary_tip; // Optional tip for node operators (in base units)
  uint64_t timestamp;         // Transaction timestamp (NTP synchronized, Unix seconds)
  mxd_tx_input_t *inputs;     // Array of inputs (variable-length keys/sigs)
  mxd_tx_output_t *outputs;   // Array of outputs (address20 format)

  // Type-specific payload (only one is active based on 'type' field)
  union {
    mxd_bridge_payload_t *bridge;  // For BRIDGE_MINT and BRIDGE_BURN
    // Future: add contract_deploy_t, contract_call_t
  } payload;

  uint8_t tx_hash[64];        // Transaction hash (SHA-512)
} mxd_transaction_v3_t;

// Create a new transaction
int mxd_create_transaction(mxd_transaction_t *tx);

// Add input to transaction (v2 - algo-aware)
int mxd_add_tx_input(mxd_transaction_t *tx, const uint8_t prev_tx_hash[64],
                     uint32_t output_index, uint8_t algo_id, 
                     const uint8_t *public_key, size_t pubkey_len);

// Add output to transaction (v2 - uses address20)
int mxd_add_tx_output(mxd_transaction_t *tx, const uint8_t recipient_addr[20],
                      mxd_amount_t amount);

// Sign transaction input (v2 - algo-aware)
int mxd_sign_tx_input(mxd_transaction_t *tx, uint32_t input_index,
                      uint8_t algo_id, const uint8_t *private_key);

// Verify transaction input signature
int mxd_verify_tx_input(const mxd_transaction_t *tx, uint32_t input_index);

// Calculate transaction hash
int mxd_calculate_tx_hash(const mxd_transaction_t *tx, uint8_t hash[64]);

// Validate entire transaction
int mxd_validate_transaction(const mxd_transaction_t *tx);

// Validate transaction inputs against UTXO database
int mxd_validate_transaction_inputs(const mxd_transaction_t *tx);

// Verify transaction input UTXO exists and has sufficient funds
int mxd_verify_tx_input_utxo(const mxd_tx_input_t *input, mxd_amount_t *amount);

// Apply transaction to UTXO database (create outputs, mark inputs as spent)
int mxd_apply_transaction_to_utxo(const mxd_transaction_t *tx);

// Create UTXOs from transaction outputs
int mxd_create_utxos_from_tx(const mxd_transaction_t *tx, const uint8_t tx_hash[64]);

// Mark transaction inputs as spent in UTXO database
int mxd_mark_tx_inputs_spent(const mxd_transaction_t *tx);

// Set voluntary tip for transaction
int mxd_set_voluntary_tip(mxd_transaction_t *tx, mxd_amount_t tip_amount);

// Get voluntary tip amount
mxd_amount_t mxd_get_voluntary_tip(const mxd_transaction_t *tx);

// Peek voluntary tip from serialized transaction bytes (lightweight extraction)
int mxd_peek_voluntary_tip_from_bytes(const uint8_t *data, size_t length, mxd_amount_t *tip_out);

// Create a coinbase transaction (for block rewards, v2 - uses address20)
int mxd_create_coinbase_transaction(mxd_transaction_t *tx, const uint8_t recipient_addr[20],
                                   mxd_amount_t reward_amount);

// Deep copy transaction (including pointer fields)
int mxd_tx_deep_copy(mxd_transaction_t *dst, const mxd_transaction_t *src);

// Free transaction resources
void mxd_free_transaction(mxd_transaction_t *tx);

// ========== Bridge Transaction Functions (v3) ==========

// Create a bridge mint transaction (BNB → MXD)
int mxd_create_bridge_mint_tx(mxd_transaction_v3_t *tx,
                               const mxd_bridge_payload_t *payload);

// Create a bridge burn transaction (MXD → BNB)
int mxd_create_bridge_burn_tx(mxd_transaction_v3_t *tx,
                               const uint8_t sender_addr[20],
                               mxd_amount_t burn_amount,
                               const uint8_t bridge_contract[64],
                               uint32_t dest_chain_id,
                               const uint8_t dest_recipient[20]);

// Validate bridge mint transaction
int mxd_validate_bridge_mint_tx(const mxd_transaction_v3_t *tx);

// Validate bridge burn transaction
int mxd_validate_bridge_burn_tx(const mxd_transaction_v3_t *tx);

// Check if bridge transaction already processed (replay protection)
int mxd_is_bridge_tx_processed(const uint8_t source_tx_hash[32]);

// Mark bridge transaction as processed
int mxd_mark_bridge_tx_processed(const mxd_bridge_payload_t *payload,
                                  const uint8_t mxd_tx_hash[64],
                                  uint32_t block_index);

// Verify bridge contract is authorized
int mxd_is_bridge_contract_authorized(const uint8_t contract_hash[64]);

// Calculate v3 transaction hash
int mxd_calculate_tx_hash_v3(const mxd_transaction_v3_t *tx, uint8_t hash[64]);

// Validate v3 transaction
int mxd_validate_transaction_v3(const mxd_transaction_v3_t *tx);

// Free v3 transaction resources
void mxd_free_transaction_v3(mxd_transaction_v3_t *tx);

#ifdef __cplusplus
}
#endif

#endif // MXD_TRANSACTION_H

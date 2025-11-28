#include "../../include/mxd_blockchain.h"
#include "../../include/mxd_crypto.h"
#include "../../include/mxd_rsc.h"
#include "../../include/mxd_utxo.h"
#include "../../include/mxd_transaction.h"
#include "../../include/mxd_logging.h"
#include "../../include/mxd_ntp.h"
#include "../../include/mxd_serialize.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Initialize a new block
int mxd_init_block(mxd_block_t *block, const uint8_t prev_hash[64]) {
  if (!block || !prev_hash) {
    return -1;
  }

  // Initialize block structure
  memset(block, 0, sizeof(mxd_block_t));
  block->version = 1; // Current version
  memcpy(block->prev_block_hash, prev_hash, 64);
  block->timestamp = mxd_now_ms() / 1000; // NTP-synchronized time in seconds
  block->difficulty = 1; // Initial difficulty
  block->nonce = 0;
  block->rapid_membership_entries = NULL;
  block->rapid_membership_count = 0;
  block->rapid_membership_capacity = 0;
  block->total_supply = 0;
  block->transaction_set_frozen = 0;
  block->transactions = NULL;
  block->transaction_count = 0;
  block->transaction_capacity = 0;

  return 0;
}

// Add transaction to block
int mxd_add_transaction(mxd_block_t *block, const uint8_t *transaction_data,
                        size_t transaction_length) {
  if (!block || !transaction_data || transaction_length == 0) {
    return -1;
  }

  if (block->transaction_set_frozen) {
    return -1; // Cannot add transactions to frozen block
  }

  // Allocate or reallocate transaction array
  if (block->transaction_count >= block->transaction_capacity) {
    uint32_t new_capacity = block->transaction_capacity == 0 ? 10 : block->transaction_capacity * 2;
    mxd_block_transaction_t *new_transactions =
        realloc(block->transactions, new_capacity * sizeof(mxd_block_transaction_t));
    if (!new_transactions) {
      return -1;
    }
    block->transactions = new_transactions;
    block->transaction_capacity = new_capacity;
  }

  // Allocate memory for transaction data
  block->transactions[block->transaction_count].data = malloc(transaction_length);
  if (!block->transactions[block->transaction_count].data) {
    return -1;
  }

  // Copy transaction data
  memcpy(block->transactions[block->transaction_count].data, transaction_data,
         transaction_length);
  block->transactions[block->transaction_count].length = transaction_length;
  block->transaction_count++;

  // Merkle root will be calculated when transaction set is frozen
  return 0;
}

// Calculate block hash
// MINOR FIX: Document merkle root simplification
// NOTE: The merkle_root field currently contains a simplified hash of all transactions
// rather than a full merkle tree structure. This is acceptable for the current implementation
// but should be upgraded to a proper merkle tree for production use to enable efficient
// transaction verification and SPV (Simplified Payment Verification) support.
int mxd_calculate_block_hash(const mxd_block_t *block, uint8_t hash[64]) {
  if (!block || !hash) {
    return -1;
  }

  // Create buffer for block header with fixed-size fields
  uint8_t header[sizeof(uint32_t) + 64 + 64 + sizeof(uint64_t) +
                 sizeof(uint32_t) + sizeof(uint64_t)];
  size_t offset = 0;

  // Serialize block header with big-endian byte order for deterministic hashing
  uint32_t version_be = htonl(block->version);
  memcpy(header + offset, &version_be, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  
  memcpy(header + offset, block->prev_block_hash, 64);
  offset += 64;
  
  memcpy(header + offset, block->merkle_root, 64);
  offset += 64;
  
  uint64_t timestamp_be = mxd_htonll(block->timestamp);
  memcpy(header + offset, &timestamp_be, sizeof(uint64_t));
  offset += sizeof(uint64_t);
  
  uint32_t difficulty_be = htonl(block->difficulty);
  memcpy(header + offset, &difficulty_be, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  
  uint64_t nonce_be = mxd_htonll(block->nonce);
  memcpy(header + offset, &nonce_be, sizeof(uint64_t));

  // Calculate double SHA-512 hash
  uint8_t temp_hash[64];
  if (mxd_sha512(header, sizeof(header), temp_hash) != 0) {
    return -1;
  }
  return mxd_sha512(temp_hash, 64, hash);
}

// Validate block structure and contents
int mxd_validate_block(const mxd_block_t *block) {
  if (!block) {
    return -1;
  }

  // Verify block version
  if (block->version != 1) {
    return -1;
  }

  // Verify timestamp using NTP-synchronized time
  uint64_t current_time = mxd_now_ms() / 1000;
  if (block->timestamp > current_time + 7200 ||  // Max 2 hours in future
      block->timestamp < current_time - 86400) { // Max 24 hours in past
    return -1;
  }

  // Verify block hash is computable
  uint8_t hash[64];
  if (mxd_calculate_block_hash(block, hash) != 0) {
    return -1;
  }

  if (block->difficulty <= 1) {
    return 0;
  }

  return hash[0] >= block->difficulty ? 0 : -1;
}

// Freeze transaction set and calculate final merkle root
// MINOR FIX: Document block closing time enforcement
// NOTE: Blocks should close after 5 seconds if they contain transactions.
// This enforcement is currently handled at the node/application level rather than
// in this library function. The 5-second timeout should be implemented in the
// block proposal and validation logic in the node application.
int mxd_freeze_transaction_set(mxd_block_t *block) {
  if (!block) {
    return -1;
  }
  
  if (block->transaction_set_frozen) {
    return 0; // Already frozen
  }
  
  // Calculate merkle root over all transactions using a proper binary merkle tree
  // This enables SPV (Simplified Payment Verification) proofs
  if (block->transaction_count == 0) {
    // No transactions - use zero hash
    memset(block->merkle_root, 0, 64);
  } else if (block->transaction_count == 1) {
    // Single transaction - hash it directly
    if (mxd_sha512(block->transactions[0].data, block->transactions[0].length, block->merkle_root) != 0) {
      return -1;
    }
  } else {
    // Multiple transactions - build proper binary merkle tree for SPV support
    // Each level pairs adjacent hashes; odd nodes are duplicated
    
    // Calculate number of leaf nodes (round up to power of 2 for balanced tree)
    uint32_t leaf_count = block->transaction_count;
    
    // Allocate buffer for current level hashes
    uint8_t *current_level = malloc(leaf_count * 64);
    if (!current_level) {
      return -1;
    }
    
    // Hash each transaction to create leaf nodes
    for (uint32_t i = 0; i < leaf_count; i++) {
      if (mxd_sha512(block->transactions[i].data, block->transactions[i].length, 
                     current_level + (i * 64)) != 0) {
        free(current_level);
        return -1;
      }
    }
    
    // Build tree level by level until we reach the root
    uint32_t level_size = leaf_count;
    while (level_size > 1) {
      // Calculate next level size (ceiling division by 2)
      uint32_t next_level_size = (level_size + 1) / 2;
      uint8_t *next_level = malloc(next_level_size * 64);
      if (!next_level) {
        free(current_level);
        return -1;
      }
      
      // Pair adjacent hashes and hash them together
      for (uint32_t i = 0; i < next_level_size; i++) {
        uint32_t left_idx = i * 2;
        uint32_t right_idx = left_idx + 1;
        
        // Concatenate left and right hashes (duplicate left if odd)
        uint8_t pair_buffer[128];
        memcpy(pair_buffer, current_level + (left_idx * 64), 64);
        
        if (right_idx < level_size) {
          memcpy(pair_buffer + 64, current_level + (right_idx * 64), 64);
        } else {
          // Odd number of nodes - duplicate the last one
          memcpy(pair_buffer + 64, current_level + (left_idx * 64), 64);
        }
        
        // Hash the pair to create parent node
        if (mxd_sha512(pair_buffer, 128, next_level + (i * 64)) != 0) {
          free(current_level);
          free(next_level);
          return -1;
        }
      }
      
      free(current_level);
      current_level = next_level;
      level_size = next_level_size;
    }
    
    // Copy root hash
    memcpy(block->merkle_root, current_level, 64);
    free(current_level);
  }
  
  // Mark as frozen - merkle_root is now immutable
  block->transaction_set_frozen = 1;
  return 0;
}

// Calculate total tip from frozen transaction set
mxd_amount_t mxd_calculate_total_tip_from_frozen_set(const mxd_block_t *block) {
  if (!block) {
    return 0;
  }
  
  if (!block->transaction_set_frozen) {
    return 0;
  }
  
  mxd_amount_t total_tip = 0;
  
  for (uint32_t i = 0; i < block->transaction_count; i++) {
    mxd_amount_t tip = 0;
    if (mxd_peek_voluntary_tip_from_bytes(block->transactions[i].data, block->transactions[i].length, &tip) == 0) {
      total_tip += tip;
    }
  }
  
  return total_tip;
}

// Calculate membership digest over frozen transaction set
// Digest = hash(version || prev_block_hash || merkle_root || proposer_id || height || difficulty)
// Explicitly excludes: validation_chain, rapid_membership_entries, timestamp, nonce, block_hash
int mxd_calculate_membership_digest(const mxd_block_t *block, uint8_t digest[64]) {
  if (!block || !digest) {
    return -1;
  }
  
  if (!block->transaction_set_frozen) {
    return -1; // Transaction set must be frozen before calculating digest
  }
  
  // Create buffer for digest calculation
  size_t buffer_size = sizeof(uint32_t) + 64 + 64 + 20 + sizeof(uint32_t) + sizeof(uint32_t);
  uint8_t *buffer = malloc(buffer_size);
  if (!buffer) {
    return -1;
  }
  
  size_t offset = 0;
  
  // Serialize immutable fields
  memcpy(buffer + offset, &block->version, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  
  memcpy(buffer + offset, block->prev_block_hash, 64);
  offset += 64;
  
  memcpy(buffer + offset, block->merkle_root, 64);
  offset += 64;
  
  memcpy(buffer + offset, block->proposer_id, 20);
  offset += 20;
  
  memcpy(buffer + offset, &block->height, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  
  memcpy(buffer + offset, &block->difficulty, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  
  // Calculate SHA-512 hash
  int result = mxd_sha512(buffer, buffer_size, digest);
  free(buffer);
  
  return result;
}

// Append membership entry to block with validation
int mxd_append_membership_entry(mxd_block_t *block, const uint8_t node_address[20],
                                uint8_t algo_id, const uint8_t *public_key, uint16_t public_key_length,
                                const uint8_t *signature, uint16_t signature_length,
                                uint64_t timestamp) {
  if (!block || !node_address || !public_key || !signature || signature_length == 0 || public_key_length == 0) {
    return -1;
  }
  
  if (!block->transaction_set_frozen) {
    return -1; // Transaction set must be frozen before accepting membership entries
  }
  
  // Validate algo_id
  if (algo_id != MXD_SIGALG_ED25519 && algo_id != MXD_SIGALG_DILITHIUM5) {
    return -1; // Invalid algorithm ID
  }
  
  // Validate public_key_length matches algo_id
  size_t expected_pubkey_len = mxd_sig_pubkey_len(algo_id);
  if (public_key_length != expected_pubkey_len) {
    return -1; // Invalid public key length for algorithm
  }
  
  // Validate signature_length matches algo_id
  size_t expected_sig_len = mxd_sig_signature_len(algo_id);
  if (signature_length != expected_sig_len) {
    return -1; // Invalid signature length for algorithm
  }
  
  // Check for duplicate address
  for (uint32_t i = 0; i < block->rapid_membership_count; i++) {
    if (memcmp(block->rapid_membership_entries[i].node_address, node_address, 20) == 0) {
      return -1; // Duplicate entry
    }
  }
  
  // Verify signature over membership digest
  uint8_t digest[64];
  if (mxd_calculate_membership_digest(block, digest) != 0) {
    return -1;
  }
  
  // Verify signature using algorithm-aware verification with provided public key
  if (mxd_sig_verify(algo_id, signature, signature_length, digest, 64, public_key) != 0) {
    return -1; // Invalid signature
  }
  
  // Verify node_address matches derived address from public key
  uint8_t derived_addr[20];
  if (mxd_derive_address(algo_id, public_key, public_key_length, derived_addr) != 0) {
    return -1;
  }
  
  if (memcmp(node_address, derived_addr, 20) != 0) {
    MXD_LOG_ERROR("blockchain", "Membership node_address doesn't match derived address");
    return -1;
  }
  
  // Verify stake requirement (1% of total supply, or genesis mode)
  if (block->total_supply > 0) {
    uint8_t addr20[20];
    if (mxd_derive_address(algo_id, public_key, public_key_length, addr20) != 0) {
      return -1; // Failed to derive address
    }
    mxd_amount_t balance = mxd_get_balance(addr20);
    // Check if balance >= 1% of total supply (balance * 100 >= total_supply)
    if (balance < block->total_supply / 100) {
      return -1; // Insufficient stake
    }
  }
  // In genesis mode (total_supply == 0), any address can join
  
  // Allocate or reallocate membership entries array
  if (block->rapid_membership_count >= block->rapid_membership_capacity) {
    uint32_t new_capacity = block->rapid_membership_capacity == 0 ? 10 : block->rapid_membership_capacity * 2;
    mxd_rapid_membership_entry_t *new_entries = realloc(block->rapid_membership_entries,
                                                         new_capacity * sizeof(mxd_rapid_membership_entry_t));
    if (!new_entries) {
      return -1;
    }
    block->rapid_membership_entries = new_entries;
    block->rapid_membership_capacity = new_capacity;
  }
  
  // Add entry with algo_id and public_key
  mxd_rapid_membership_entry_t *entry = &block->rapid_membership_entries[block->rapid_membership_count];
  memcpy(entry->node_address, node_address, 20);
  entry->timestamp = timestamp;
  entry->algo_id = algo_id;
  entry->public_key_length = public_key_length;
  memcpy(entry->public_key, public_key, public_key_length);
  entry->signature_length = signature_length;
  if (signature_length > MXD_SIGNATURE_MAX) {
    return -1; // Signature too large
  }
  memcpy(entry->signature, signature, signature_length);
  
  block->rapid_membership_count++;
  
  return 0;
}

// Check if block has membership quorum (2/3 of rapid table size)
int mxd_block_has_membership_quorum(const mxd_block_t *block, size_t rapid_table_size) {
  if (!block) {
    return 0;
  }
  
  if (rapid_table_size == 0) {
    return block->rapid_membership_count >= 3 ? 1 : 0;
  }
  
  // Calculate 2/3 threshold
  size_t required = (rapid_table_size * 2 + 2) / 3; // Ceiling division
  
  return block->rapid_membership_count >= required ? 1 : 0;
}

// Check if block is in pre-signed state (has membership entries but no validation chain)
int mxd_block_is_presigned(const mxd_block_t *block) {
  if (!block) {
    return 0;
  }
  
  return block->transaction_set_frozen && 
         block->rapid_membership_count > 0 && 
         block->validation_count == 0;
}

// Check if block is ready for validation chain (has membership quorum)
int mxd_block_is_ready(const mxd_block_t *block, size_t rapid_table_size) {
  if (!block) {
    return 0;
  }
  
  return block->transaction_set_frozen && 
         mxd_block_has_membership_quorum(block, rapid_table_size) &&
         block->validation_count == 0;
}

// Check if block is finalized (validation chain complete)
int mxd_block_is_finalized(const mxd_block_t *block) {
  if (!block) {
    return 0;
  }
  
  // Block is finalized if it has validation chain signatures
  // The exact quorum check is done by mxd_block_has_validation_quorum in mxd_rsc.c
  return block->validation_count > 0;
}

// Free all dynamically allocated memory in a block
void mxd_free_block(mxd_block_t *block) {
  if (!block) {
    return;
  }

  // Free transaction data buffers
  for (uint32_t i = 0; i < block->transaction_count; i++) {
    if (block->transactions[i].data) {
      free(block->transactions[i].data);
      block->transactions[i].data = NULL;
    }
    block->transactions[i].length = 0;
  }

  // Free transactions array
  if (block->transactions) {
    free(block->transactions);
    block->transactions = NULL;
  }
  block->transaction_count = 0;
  block->transaction_capacity = 0;

  // Reuse existing cleanup for validation chain + membership entries
  mxd_free_validation_chain(block);
}

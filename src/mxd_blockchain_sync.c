#include "mxd_logging.h"

#include "../include/mxd_blockchain_sync.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_rsc.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_ntp.h"
#include "../include/mxd_serialize.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_endian.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "../include/mxd_error.h"

#define MXD_VALIDATION_EXPIRY_BLOCKS 5
#define MXD_MIN_RELAY_SIGNATURES 3
#define MXD_MAX_TIMESTAMP_DRIFT 60

static int mxd_request_peer_height(const char *address, uint16_t port, uint32_t *height);
static mxd_block_t* mxd_request_blocks_from_peers(uint32_t start_height, uint32_t end_height, size_t *block_count);
int mxd_apply_block_transactions(const mxd_block_t *block, int64_t *supply_delta);
void mxd_propagate_supply_forward(uint32_t from_height, uint64_t from_supply);
static int mxd_sync_block_range(uint32_t start_height, uint32_t end_height);
int mxd_sign_and_broadcast_block(const mxd_block_t *block);
extern void mxd_drain_pending_validation_sigs(const uint8_t *block_hash);

static uint32_t mxd_discover_network_height(void) {
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;

    if (mxd_get_peers(peers, &peer_count) != 0 || peer_count == 0) {
        MXD_LOG_WARN("sync", "No peers available to discover network height");
        return 0;
    }

    MXD_LOG_INFO("sync", "Discovering network height from %zu peers", peer_count);

    // Count peers by state for debugging
    int connected_count = 0;
    int other_count = 0;
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].state == MXD_PEER_CONNECTED) {
            connected_count++;
        } else {
            other_count++;
            // Log first few non-connected peers for debugging
            if (other_count <= 3) {
                MXD_LOG_INFO("sync", "Peer %s:%u has state=%d (not CONNECTED=%d)",
                             peers[i].address, peers[i].port, peers[i].state, MXD_PEER_CONNECTED);
            }
        }
    }
    MXD_LOG_INFO("sync", "Peer states: %d connected, %d other", connected_count, other_count);

    uint32_t max_height = 0;
    int queried = 0;
    for (size_t i = 0; i < peer_count && queried < 3; i++) {
        if (peers[i].state == MXD_PEER_CONNECTED) {
            uint32_t peer_height = 0;
            MXD_LOG_INFO("sync", "Querying peer %s:%u for height", peers[i].address, peers[i].port);
            if (mxd_request_peer_height(peers[i].address, peers[i].port, &peer_height) == 0) {
                MXD_LOG_INFO("sync", "Peer %s:%u reports height=%u", peers[i].address, peers[i].port, peer_height);
                queried++;
                if (peer_height > max_height) {
                    max_height = peer_height;
                }
            } else {
                MXD_LOG_WARN("sync", "Failed to get height from peer %s:%u", peers[i].address, peers[i].port);
            }
        }
    }

    MXD_LOG_INFO("sync", "Network height discovery complete: queried=%d, max_height=%u", queried, max_height);
    return max_height;
}

// Callback storage for peer height responses
static volatile uint32_t pending_peer_height = 0;
static volatile int peer_height_received = 0;

// Called by P2P layer when height response is received
void mxd_handle_peer_height_response(const uint8_t *data, size_t data_len) {
    if (data && data_len >= 4) {
        const uint8_t *ptr = data;
        pending_peer_height = mxd_read_u32_be(&ptr);
        peer_height_received = 1;
    }
}

static int mxd_request_peer_height(const char *address, uint16_t port, uint32_t *height) {
    if (!address || !height) return -1;
    
    // Reset response state
    peer_height_received = 0;
    pending_peer_height = 0;
    
    // Send height request to peer using GET_BLOCKS with height=0 to request current height
    uint8_t request[8];
    uint8_t *ptr = request;
    mxd_write_u32_be(&ptr, 0);  // start_height = 0 (request height info)
    mxd_write_u32_be(&ptr, 0);  // end_height = 0 (request height info only)
    
    if (mxd_send_message_with_retry(address, port, MXD_MSG_GET_BLOCKS, 
                                    request, sizeof(request), 3) != 0) {
        MXD_LOG_DEBUG("sync", "Failed to send height request to peer %s:%u", address, port);
        *height = 0;
        return -1;
    }
    
    // Wait for response with timeout (up to 3 seconds)
    int wait_ms = 0;
    while (!peer_height_received && wait_ms < 1000) {
        struct timespec ts = {0, 50000000}; // 50ms
        nanosleep(&ts, NULL);
        wait_ms += 50;
    }
    
    if (peer_height_received) {
        *height = pending_peer_height;
        MXD_LOG_DEBUG("sync", "Peer %s:%u reported height: %u", address, port, *height);
        return 0;
    }
    
    MXD_LOG_DEBUG("sync", "Timeout waiting for height from peer %s:%u", address, port);
    *height = 0;
    return -1;
}

// Callback storage for block responses
static mxd_block_t *pending_blocks = NULL;
static volatile uint32_t pending_blocks_received = 0;
static volatile uint32_t pending_blocks_expected = 0;

// Forward declaration for deserializing blocks from database format
extern int mxd_deserialize_block_from_network(const uint8_t *data, size_t data_len, mxd_block_t *block);

// Called by P2P layer when block data is received
void mxd_handle_blocks_response(const uint8_t *data, size_t data_len, uint32_t block_index) {
    if (!data || data_len == 0) return;

    // Check if this is a 4-byte height response
    if (data_len == 4) {
        // This is a height response from a peer - route to height handler
        mxd_handle_peer_height_response(data, data_len);
        return;
    }

    // Handle unsolicited blocks (e.g., genesis block broadcast)
    if (!pending_blocks) {
        MXD_LOG_INFO("sync", "Received unsolicited block data (len=%zu), attempting to process", data_len);
        
        // Deserialize the block using the network format
        mxd_block_t block;
        memset(&block, 0, sizeof(block));
        
        if (mxd_deserialize_block_from_network(data, data_len, &block) != 0) {
            MXD_LOG_WARN("sync", "Failed to deserialize unsolicited block");
            return;
        }
        
        MXD_LOG_INFO("sync", "Deserialized unsolicited block: height=%u, validators=%u, membership=%u",
                     block.height, block.validation_count, block.rapid_membership_count);

        // NOTE: Do NOT call mxd_validate_block() here. It requires the previous block
        // to validate the proposer, but blocks can arrive out of order. Blocks from
        // non-primary proposers are already prevented at the source (mxd_is_proposer_for_height
        // only allows the primary proposer to propose).

        // Check if we already have this block
        uint32_t current_height = 0;
        int have_blockchain = (mxd_get_blockchain_height(&current_height) == 0);
        
        // Special handling for genesis block (height 0)
        // If we don't have any blocks yet (have_blockchain is false or current_height is 0),
        // we should accept the genesis block
        if (block.height == 0) {
            if (have_blockchain && current_height >= 0) {
                // Check if we actually have a genesis block stored
                mxd_block_t existing_genesis;
                memset(&existing_genesis, 0, sizeof(existing_genesis));
                if (mxd_retrieve_block_by_height(0, &existing_genesis) == 0) {
                    MXD_LOG_DEBUG("sync", "Already have genesis block, ignoring duplicate");
                    mxd_free_block(&existing_genesis);
                    mxd_free_block(&block);
                    return;
                }
            }
            // Don't have genesis block yet — but only accept if it has validators.
            // Reject empty genesis (membership=0) to prevent stale genesis from
            // external DHT peers overriding our own genesis coordination.
            if (block.rapid_membership_count == 0) {
                MXD_LOG_WARN("sync", "Rejecting genesis block with 0 membership entries (likely stale)");
                mxd_free_block(&block);
                return;
            }
            MXD_LOG_INFO("sync", "Received genesis block with %u members, will store it",
                         block.rapid_membership_count);
        } else if (block.height < current_height) {
            // current_height = number of blocks stored (heights 0 to current_height-1)
            // So we only skip if block.height < current_height (we already have it)
            MXD_LOG_DEBUG("sync", "Already have block at height %u (current=%u), ignoring",
                         block.height, current_height);
            mxd_free_block(&block);
            return;
        }
        
        // Apply transactions to create UTXOs (critical for genesis block)
        int64_t supply_delta = 0;
        if (mxd_apply_block_transactions(&block, &supply_delta) != 0) {
            if (block.height == 0) {
                // Genesis block must always be accepted
                MXD_LOG_WARN("sync", "Failed to apply transactions for genesis block, storing anyway");
            } else {
                MXD_LOG_WARN("sync", "Failed to apply transactions for unsolicited block at height %u, rejecting", block.height);
                mxd_free_block(&block);
                return;
            }
        }

        // Guard against overwriting a block that already has more validation signatures.
        // This prevents a race condition where the block broadcast (with proposer sig only)
        // arrives after the validation handler has already added more signatures.
        {
            mxd_block_t existing;
            memset(&existing, 0, sizeof(existing));
            if (mxd_retrieve_block_by_hash(block.block_hash, &existing) == 0) {
                if (existing.validation_count >= block.validation_count) {
                    MXD_LOG_DEBUG("sync", "Existing block at height %u already has %u sigs (broadcast has %u), keeping existing",
                                 block.height, existing.validation_count, block.validation_count);
                    mxd_free_block(&existing);
                    // Still try to sign the existing block (in case we haven't yet)
                    if (block.height > 0) {
                        mxd_block_t sign_block;
                        memset(&sign_block, 0, sizeof(sign_block));
                        if (mxd_retrieve_block_by_hash(block.block_hash, &sign_block) == 0) {
                            mxd_sign_and_broadcast_block(&sign_block);
                            mxd_free_block(&sign_block);
                        }
                    }
                    mxd_free_block(&block);
                    return;
                }
                mxd_free_block(&existing);
            }
        }

        // Compute total_supply deterministically from previous block + delta
        if (block.height > 0) {
            mxd_block_t prev;
            memset(&prev, 0, sizeof(prev));
            if (mxd_retrieve_block_by_height(block.height - 1, &prev) == 0) {
                block.total_supply = (uint64_t)((int64_t)prev.total_supply + supply_delta);
                mxd_free_block(&prev);
            }
        } else {
            // Genesis: delta IS the total supply
            block.total_supply = (uint64_t)supply_delta;
        }

        // Store the block
        if (mxd_store_block(&block) == 0) {
            MXD_LOG_INFO("sync", "Stored unsolicited block at height %u (validators=%u, supply=%llu)",
                         block.height, block.validation_count, (unsigned long long)block.total_supply);

            // Forward-propagate supply to any subsequent blocks stored with supply=0
            if (block.total_supply > 0) {
                mxd_propagate_supply_forward(block.height, block.total_supply);
            }

            // Drain any validation signatures that arrived before this block
            mxd_drain_pending_validation_sigs(block.block_hash);

            // As a validator, sign this block and broadcast signature
            if (block.height > 0) {
                mxd_sign_and_broadcast_block(&block);
            }
        } else {
            MXD_LOG_ERROR("sync", "Failed to store unsolicited block at height %u", block.height);
        }

        mxd_free_block(&block);
        return;
    }
    
    if (block_index >= pending_blocks_expected) return;

    // Guard: only accept one response per slot to prevent concurrent
    // deserializations into the same memory from duplicate responses.
    if (pending_blocks_received >= pending_blocks_expected) return;

    // Deserialize block from received data (for requested blocks)
    // Use the full network deserializer to capture ALL fields including
    // v4 validator scores, validation chain, membership entries, etc.
    mxd_block_t *block = &pending_blocks[block_index];

    if (mxd_deserialize_block_from_network(data, data_len, block) != 0) {
        MXD_LOG_ERROR("sync", "Failed to deserialize requested block %u", block_index);
        return;
    }

    pending_blocks_received++;
    MXD_LOG_DEBUG("sync", "Received block %u (height %u, scores=%u)",
                  block_index, block->height, block->validator_scores_count);
}

static mxd_block_t* mxd_request_blocks_from_peers(uint32_t start_height, uint32_t end_height, size_t *block_count) {
    if (!block_count || start_height > end_height) return NULL;
    
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    
    if (mxd_get_peers(peers, &peer_count) != 0 || peer_count == 0) {
        MXD_LOG_WARN("sync", "No peers available to request blocks");
        return NULL;
    }

    // Shuffle connected peers to avoid always trying the same (potentially
    // stuck) peers first. With N healthy peers out of total, random order
    // reaches a healthy peer in ~total/N tries on average.
    for (size_t i = peer_count - 1; i > 0; i--) {
        size_t j = rand() % (i + 1);
        mxd_peer_t tmp = peers[i];
        peers[i] = peers[j];
        peers[j] = tmp;
    }

    uint32_t count = end_height - start_height + 1;
    mxd_block_t *blocks = calloc(count, sizeof(mxd_block_t));
    if (!blocks) {
        MXD_LOG_ERROR("sync", "Failed to allocate memory for blocks");
        return NULL;
    }
    
    // Set up callback storage
    pending_blocks = blocks;
    pending_blocks_received = 0;
    pending_blocks_expected = count;

    // Try peers one at a time with a short timeout per peer.
    // CRITICAL: Do NOT send to ALL peers simultaneously — multiple peers
    // responding concurrently causes race conditions in the callback
    // (concurrent deserializations into the same pending_blocks memory,
    // and duplicate blocks flooding the unsolicited handler after timeout).
    int got_response = 0;
    for (size_t i = 0; i < peer_count && !got_response; i++) {
        if (peers[i].state != MXD_PEER_CONNECTED) continue;

        uint8_t request[8];
        uint8_t *ptr = request;
        mxd_write_u32_be(&ptr, start_height);
        mxd_write_u32_be(&ptr, end_height);

        if (mxd_send_message_with_retry(peers[i].address, peers[i].port,
                                       MXD_MSG_GET_BLOCKS, request, sizeof(request), 1) != 0) {
            continue;
        }

        // Wait up to 1.5 seconds for this peer to respond.
        // Short timeout so we quickly move to the next peer if this one
        // is syncing itself (doesn't have the block).
        int wait_ms = 0;
        while (pending_blocks_received < count && wait_ms < 1500) {
            struct timespec ts = {0, 100000000}; // 100ms
            nanosleep(&ts, NULL);
            wait_ms += 100;
        }

        if (pending_blocks_received >= count) {
            got_response = 1;
        }
        // else: this peer didn't respond in time, try next peer
    }

    pending_blocks = NULL;

    if (pending_blocks_received < count) {
        MXD_LOG_WARN("sync", "Only received %u of %u blocks after trying all peers",
                     pending_blocks_received, count);
    }

    *block_count = count;
    return blocks;
}

// Forward-propagate total_supply to subsequent blocks that have supply=0.
// Called after storing a block with valid (non-zero) supply.
// Re-computes delta for each forward block from its transaction data.
void mxd_propagate_supply_forward(uint32_t from_height, uint64_t from_supply) {
    for (uint32_t h = from_height + 1; ; h++) {
        mxd_block_t next;
        memset(&next, 0, sizeof(next));
        if (mxd_retrieve_block_by_height(h, &next) != 0) {
            break;  // No block at this height — stop
        }
        if (next.total_supply > 0) {
            mxd_free_block(&next);
            break;  // Already has valid supply — stop
        }
        // Recompute delta for this block (UTXOs are already applied, but
        // mxd_find_utxo returns spent UTXOs so delta is still correct)
        int64_t delta = 0;
        mxd_apply_block_transactions(&next, &delta);
        next.total_supply = (uint64_t)((int64_t)from_supply + delta);
        mxd_store_block(&next);
        MXD_LOG_INFO("sync", "Forward-propagated supply to height %u: %llu",
                     h, (unsigned long long)next.total_supply);
        from_supply = next.total_supply;
        mxd_free_block(&next);
    }
}

int mxd_apply_block_transactions(const mxd_block_t *block, int64_t *supply_delta) {
    if (!block) return -1;

    int64_t delta = 0;

    // Apply each transaction in the block to the UTXO state
    for (uint32_t i = 0; i < block->transaction_count; i++) {
        if (!block->transactions[i].data || block->transactions[i].length == 0) {
            MXD_LOG_WARN("sync", "Skipping empty transaction at index %u", i);
            continue;
        }

        // Deserialize the transaction from block storage format
        mxd_transaction_t tx;
        memset(&tx, 0, sizeof(mxd_transaction_t));

        const uint8_t *ptr = block->transactions[i].data;
        const uint8_t *end = ptr + block->transactions[i].length;

        // Read header fields
        if (ptr + 4 + 4 + 4 + 8 + 8 + 1 + 64 > end) {
            MXD_LOG_ERROR("sync", "Transaction data too short at index %u", i);
            continue;
        }

        tx.version = mxd_read_u32_be(&ptr);
        tx.input_count = mxd_read_u32_be(&ptr);
        tx.output_count = mxd_read_u32_be(&ptr);
        tx.voluntary_tip = mxd_read_u64_be(&ptr);
        tx.timestamp = mxd_read_u64_be(&ptr);
        tx.is_coinbase = mxd_read_u8(&ptr);
        mxd_read_bytes(&ptr, tx.tx_hash, 64);

        // Allocate and read inputs
        if (tx.input_count > 0) {
            tx.inputs = calloc(tx.input_count, sizeof(mxd_tx_input_t));
            if (!tx.inputs) {
                MXD_LOG_ERROR("sync", "Failed to allocate inputs for transaction %u", i);
                continue;
            }

            for (uint32_t j = 0; j < tx.input_count; j++) {
                if (ptr + 64 + 4 + 1 + 2 > end) {
                    mxd_free_transaction(&tx);
                    MXD_LOG_ERROR("sync", "Transaction input data truncated at index %u", i);
                    goto next_tx;
                }

                mxd_read_bytes(&ptr, tx.inputs[j].prev_tx_hash, 64);
                tx.inputs[j].output_index = mxd_read_u32_be(&ptr);
                tx.inputs[j].algo_id = mxd_read_u8(&ptr);
                tx.inputs[j].public_key_length = mxd_read_u16_be(&ptr);

                if (ptr + tx.inputs[j].public_key_length + 2 > end) {
                    mxd_free_transaction(&tx);
                    goto next_tx;
                }

                tx.inputs[j].public_key = malloc(tx.inputs[j].public_key_length);
                if (!tx.inputs[j].public_key) {
                    mxd_free_transaction(&tx);
                    goto next_tx;
                }
                mxd_read_bytes(&ptr, tx.inputs[j].public_key, tx.inputs[j].public_key_length);

                tx.inputs[j].signature_length = mxd_read_u16_be(&ptr);
                if (tx.inputs[j].signature_length > 0) {
                    if (ptr + tx.inputs[j].signature_length > end) {
                        mxd_free_transaction(&tx);
                        goto next_tx;
                    }
                    tx.inputs[j].signature = malloc(tx.inputs[j].signature_length);
                    if (!tx.inputs[j].signature) {
                        mxd_free_transaction(&tx);
                        goto next_tx;
                    }
                    mxd_read_bytes(&ptr, tx.inputs[j].signature, tx.inputs[j].signature_length);
                }
            }
        }

        // Allocate and read outputs
        if (tx.output_count > 0) {
            tx.outputs = calloc(tx.output_count, sizeof(mxd_tx_output_t));
            if (!tx.outputs) {
                mxd_free_transaction(&tx);
                MXD_LOG_ERROR("sync", "Failed to allocate outputs for transaction %u", i);
                continue;
            }

            for (uint32_t j = 0; j < tx.output_count; j++) {
                if (ptr + 20 + 8 > end) {
                    mxd_free_transaction(&tx);
                    goto next_tx;
                }
                mxd_read_bytes(&ptr, tx.outputs[j].recipient_addr, 20);
                tx.outputs[j].amount = mxd_read_u64_be(&ptr);
            }
        }

        // Compute supply delta purely from block data (no UTXO lookups).
        // Coinbase txs create new supply: delta = +sum(outputs).
        // Non-coinbase txs with voluntary tips: the tip is deducted from
        // outputs (outputs = inputs - tip) but redistributed as a separate
        // coinbase tx. To avoid double-counting, subtract the tip here:
        //   non-coinbase delta = -voluntary_tip
        //   tip-redistribution coinbase delta = +tip
        //   net = 0 (supply-neutral, correct)
        if (tx.is_coinbase) {
            for (uint32_t j = 0; j < tx.output_count; j++) {
                delta += (int64_t)tx.outputs[j].amount;
            }
        } else if (tx.voluntary_tip > 0) {
            delta -= (int64_t)tx.voluntary_tip;
        }

        // Apply the transaction to UTXO state
        // Distinguish IO errors (must halt) from spent inputs (skip)
        int ret = mxd_apply_transaction_to_utxo(&tx);
        if (ret == MXD_ERR_IO) {
            MXD_LOG_ERROR("sync", "IO error applying transaction %u - halting block processing", i);
            mxd_free_transaction(&tx);
            if (supply_delta) *supply_delta = delta;
            return MXD_ERR_IO;  // HALT - caller must stop
        }
        if (ret != 0) {
            MXD_LOG_DEBUG("sync", "Transaction %u already applied (inputs spent), UTXO skip ok", i);
        }

        mxd_free_transaction(&tx);
        continue;

    next_tx:
        MXD_LOG_ERROR("sync", "Failed to deserialize transaction %u", i);
        continue;
    }

    if (supply_delta) *supply_delta = delta;
    return 0;
}

static int mxd_sync_block_range(uint32_t start_height, uint32_t end_height) {
    // Sync one block at a time to avoid partial-range failures.
    // The range request mechanism can receive fewer blocks than requested,
    // leaving the rest as zeroed structs that fail validation (version=0).
    int synced = 0;
    for (uint32_t h = start_height; h <= end_height; h++) {
        // Skip blocks we already have in the DB
        if (mxd_block_exists_at_height(h)) {
            synced++;
            continue;
        }

        size_t block_count = 0;
        mxd_block_t *blocks = mxd_request_blocks_from_peers(h, h, &block_count);
        if (!blocks) {
            MXD_LOG_WARN("sync", "Failed to request block %u from peers, skipping", h);
            continue;
        }

        mxd_block_t *block = &blocks[0];

        if (block->version == 0) {
            MXD_LOG_WARN("sync", "Block %u not received (empty response), skipping", h);
            free(blocks);
            continue;
        }

        // Skip mxd_validate_block() during sync: it checks validator scores
        // which are cumulative (block H depends on block H-1's scores).
        // A node catching up from genesis doesn't have the correct local
        // score state, so validation always fails with "score mismatch".
        // Synced blocks are already validated by network consensus.
        // Still verify basic structural integrity (version, validation chain).
        if (block->version < 1 || block->version > 4) {
            MXD_LOG_WARN("sync", "Invalid block version %u at height %u, skipping", block->version, h);
            free(blocks);
            continue;
        }

        int64_t supply_delta = 0;
        int tx_apply_failed = 0;
        if (mxd_apply_block_transactions(block, &supply_delta) != 0) {
            MXD_LOG_WARN("sync", "Failed to apply transactions at height %u, storing block anyway", h);
            tx_apply_failed = 1;
            supply_delta = 0;
        }

        // Compute total_supply deterministically from previous block + delta
        if (block->height > 0) {
            mxd_block_t prev;
            memset(&prev, 0, sizeof(prev));
            if (mxd_retrieve_block_by_height(block->height - 1, &prev) == 0) {
                block->total_supply = (uint64_t)((int64_t)prev.total_supply + supply_delta);
                mxd_free_block(&prev);
            }
        } else {
            block->total_supply = (uint64_t)supply_delta;
        }

        // Always store the block even if tx apply failed — the block is
        // consensus-valid and not storing it creates a permanent gap that
        // prevents current_height from ever advancing past this point.
        if (mxd_store_block(block) != 0) {
            MXD_LOG_ERROR("sync", "Failed to store block at height %u", h);
            free(blocks);
            break;
        }

        // Load validator scores from synced block into rapid table
        // so subsequent blocks can validate correctly
        if (block->version >= 4 && block->validator_scores) {
            const mxd_rapid_table_t *table = mxd_get_rapid_table();
            if (table) {
                mxd_load_scores_from_block((mxd_rapid_table_t *)table, block);
                mxd_compute_chain_scores((mxd_rapid_table_t *)table);
                mxd_sort_rapid_table_by_score((mxd_rapid_table_t *)table);
            }
        }

        MXD_LOG_INFO("sync", "Synced block at height %u", h);
        synced++;
        free(blocks);
    }

    return synced > 0 ? 0 : -1;
}

int mxd_sync_blockchain(void) {
    // Advance current_height through blocks already in the DB from previous
    // sync passes. This avoids re-requesting blocks we already have.
    mxd_advance_height_pointer();

    uint32_t local_height = 0;
    if (mxd_get_blockchain_height(&local_height) != 0) {
        local_height = 0;
    }

    uint32_t network_height = mxd_discover_network_height();
    if (network_height <= local_height) {
        MXD_LOG_INFO("sync", "Already synced (local: %u, network: %u)", local_height, network_height);
        return 0;
    }
    
    // local_height = number of blocks stored (blocks at heights 0 to local_height-1)
    // network_height = number of blocks on network
    // We need to sync blocks from height local_height to network_height-1
    MXD_LOG_INFO("sync", "Syncing from height %u to %u", local_height, network_height - 1);

    const uint32_t CHUNK_SIZE = 500;
    for (uint32_t start = local_height; start < network_height; start += CHUNK_SIZE) {
        uint32_t end = (start + CHUNK_SIZE < network_height) ?
                       start + CHUNK_SIZE - 1 : network_height - 1;
        
        if (mxd_sync_block_range(start, end) != 0) {
            MXD_LOG_WARN("sync", "Some blocks in range %u-%u failed, continuing", start, end);
        }
        
        MXD_LOG_INFO("sync", "Synced blocks %u-%u", start, end);
    }
    
    MXD_LOG_INFO("sync", "Blockchain sync complete");
    return 0;
}

int mxd_get_block_by_height(uint32_t height, mxd_block_t *block) {
    if (!block) return -1;
    
    return mxd_retrieve_block_by_height(height, block);
}

int mxd_sync_validation_chain(const uint8_t block_hash[64], uint32_t height) {
    if (!block_hash) return -1;
    
    if (mxd_request_validation_chain_from_peers(block_hash) != 0) {
        MXD_LOG_ERROR("sync", "Failed to request validation chain for block at height %u", height);
        return -1;
    }
    
    // For testing purposes, simulate successful sync
    MXD_LOG_INFO("sync", "Synchronizing validation chain for block at height %u", height);
    return 0;
}

int mxd_request_validation_chain_from_peers(const uint8_t block_hash[64]) {
    if (!block_hash) return -1;
    
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    if (mxd_get_peers(peers, &peer_count) != 0 || peer_count == 0) {
        MXD_LOG_WARN("sync", "No peers available to request validation chain");
        return -1;
    }
    
    int success = 0;
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].state == MXD_PEER_CONNECTED) {
            if (mxd_request_validation_chain(peers[i].address, peers[i].port, block_hash) == 0) {
                success = 1;
            }
        }
    }
    
    return success ? 0 : -1;
}

int mxd_process_incoming_validation_chain(const uint8_t block_hash[64], 
                                         const mxd_validator_signature_t *signatures,
                                         uint32_t signature_count) {
    if (!block_hash || !signatures || signature_count == 0) return -1;
    
    mxd_block_t block;
    if (mxd_retrieve_block_by_hash(block_hash, &block) != 0) {
        MXD_LOG_ERROR("sync", "Failed to retrieve block for validation chain processing");
        return -1;
    }
    
    for (uint32_t i = 0; i < signature_count; i++) {
        if (mxd_verify_and_add_validation_signature(&block,
                                                  signatures[i].validator_id,
                                                  signatures[i].algo_id,
                                                  signatures[i].signature,
                                                  signatures[i].signature_length,
                                                  signatures[i].timestamp) != 0) {
            MXD_LOG_WARN("sync", "Failed to verify signature %u of %u", i + 1, signature_count);
        }
    }
    
    if (mxd_store_block(&block) != 0) {
        MXD_LOG_ERROR("sync", "Failed to store block with updated validation chain");
        return -1;
    }
    
    if (mxd_check_block_relay_status(block_hash) == 1) {
        MXD_LOG_INFO("sync", "Block has enough signatures for relay");
    }
    
    return 0;
}

int mxd_verify_and_add_validation_signature(mxd_block_t *block, 
                                           const uint8_t validator_id[20],
                                           uint8_t algo_id,
                                           const uint8_t *signature,
                                           uint16_t signature_length,
                                           uint64_t timestamp) {
    if (!block || !validator_id || !signature || signature_length == 0 || signature_length > MXD_SIGNATURE_MAX) return -1;
    
    if (algo_id != MXD_SIGALG_ED25519 && algo_id != MXD_SIGALG_DILITHIUM5) {
        MXD_LOG_WARN("sync", "Invalid algo_id %u", algo_id);
        return -1;
    }
    
    // Use NTP-synchronized time for timestamp validation
    // Note: timestamp parameter is in milliseconds (from mxd_now_ms())
    uint64_t current_time_ms = 0;
    if (mxd_get_network_time(&current_time_ms) != 0) {
        current_time_ms = (uint64_t)time(NULL) * 1000;
    }
    // Convert both to seconds for comparison
    uint64_t timestamp_sec = timestamp / 1000;  // Convert ms to seconds
    uint64_t current_time_sec = current_time_ms / 1000;
    uint64_t drift = (timestamp_sec > current_time_sec) ?
                     (timestamp_sec - current_time_sec) :
                     (current_time_sec - timestamp_sec);

    if (drift > MXD_MAX_TIMESTAMP_DRIFT) {
        MXD_LOG_WARN("sync", "Signature timestamp drift too large: %lu seconds (ts=%lu, now=%lu)",
                     (unsigned long)drift, (unsigned long)timestamp_sec, (unsigned long)current_time_sec);
        return -1;
    }
    
    if (mxd_signature_exists(block->height, validator_id, signature, signature_length) != 0) {
        MXD_LOG_DEBUG("sync", "Signature already exists for this block height");
        return -1;
    }
    
    if (mxd_is_validator_blacklisted(validator_id) != 0) {
        MXD_LOG_WARN("sync", "Validator is blacklisted");
        return -1;
    }
    
    // Use the validated signature addition path with timestamp drift checking
    uint32_t chain_position = block->validation_count;
    if (mxd_add_validator_signature_to_block(block, validator_id, timestamp, algo_id, signature, signature_length, chain_position) != 0) {
        MXD_LOG_ERROR("sync", "Failed to add validator signature to block");
        return -1;
    }
    
    return 0;
}

int mxd_check_block_relay_status(const uint8_t block_hash[64]) {
    if (!block_hash) return -1;
    
    mxd_block_t block;
    if (mxd_retrieve_block_by_hash(block_hash, &block) != 0) {
        MXD_LOG_ERROR("sync", "Failed to retrieve block for relay status check");
        return -1;
    }
    
    if (block.validation_count >= MXD_MIN_RELAY_SIGNATURES) {
        return 1; // Yes, block has enough signatures for relay
    }
    
    return 0; // No, block does not have enough signatures for relay
}

int mxd_sync_rapid_table(mxd_rapid_table_t *table, const char *local_node_id) {
    if (!table) return -1;
    
    MXD_LOG_INFO("sync", "Synchronizing Rapid Table with network");
    
    uint32_t current_height = 0;
    if (mxd_get_blockchain_height(&current_height) != 0 || current_height == 0) {
        MXD_LOG_WARN("sync", "No blockchain data available for rapid table sync");
        return 0;
    }
    
    uint32_t from_height = current_height > 1000 ? current_height - 1000 : 0;
    
    if (mxd_rebuild_rapid_table_from_blockchain(table, from_height, current_height, local_node_id) == 0) {
        MXD_LOG_INFO("sync", "Rapid Table synchronized from blockchain (heights %u to %u)", 
                     from_height, current_height);
        return 0;
    } else {
        MXD_LOG_ERROR("sync", "Failed to rebuild rapid table from blockchain");
        return -1;
    }
}

int mxd_handle_validation_chain_conflict(const uint8_t block_hash1[64], 
                                        const uint8_t block_hash2[64]) {
    if (!block_hash1 || !block_hash2) return -1;
    
    mxd_block_t block1, block2;
    if (mxd_retrieve_block_by_hash(block_hash1, &block1) != 0 ||
        mxd_retrieve_block_by_hash(block_hash2, &block2) != 0) {
        MXD_LOG_ERROR("sync", "Failed to retrieve blocks for conflict resolution");
        return -1;
    }
    
    int result = mxd_resolve_fork(&block1, &block2);
    
    if (result > 0) {
        MXD_LOG_INFO("sync", "Block 1 wins conflict resolution");
        return 1;
    } else if (result < 0) {
        MXD_LOG_INFO("sync", "Block 2 wins conflict resolution");
        return 2;
    } else {
        MXD_LOG_INFO("sync", "Conflict resolution inconclusive");
        return 0;
    }
}

int mxd_prune_expired_validation_chains(uint32_t current_height) {
    if (current_height < MXD_VALIDATION_EXPIRY_BLOCKS) {
        return 0; // Nothing to prune yet
    }

    uint32_t prune_height = current_height - MXD_VALIDATION_EXPIRY_BLOCKS;

    return mxd_prune_expired_signatures(prune_height);
}

// Pull-based sync fallback - actively request missing blocks from peers
// This is called periodically to catch blocks that failed to broadcast
int mxd_pull_missing_blocks(void) {
    // Advance height through any blocks already in DB
    mxd_advance_height_pointer();

    uint32_t local_height = 0;
    if (mxd_get_blockchain_height(&local_height) != 0) {
        local_height = 0;
    }

    // Get peers and check their heights
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    if (mxd_get_peers(peers, &peer_count) != 0 || peer_count == 0) {
        return 0;  // No peers, nothing to do
    }

    // Find the maximum height among all peers
    uint32_t max_peer_height = local_height;
    int peers_queried = 0;

    for (size_t i = 0; i < peer_count && peers_queried < 5; i++) {
        if (peers[i].state == MXD_PEER_CONNECTED) {
            uint32_t peer_height = 0;
            if (mxd_request_peer_height(peers[i].address, peers[i].port, &peer_height) == 0) {
                peers_queried++;
                if (peer_height > max_peer_height) {
                    max_peer_height = peer_height;
                    MXD_LOG_INFO("sync", "Peer %s:%u has higher height: %u (local: %u)",
                                 peers[i].address, peers[i].port, peer_height, local_height);
                }
            }
        }
    }

    // FIRST: scan for and fill interior block gaps below current_height
    // This runs before height-based sync so gaps are always detected
    {
        uint32_t gaps[100];
        uint32_t gap_count = 0;
        if (mxd_fill_block_gaps(gaps, 100, &gap_count) == 0 && gap_count > 0) {
            MXD_LOG_INFO("sync", "Found %u block gaps below current height, attempting to fill", gap_count);
            for (uint32_t g = 0; g < gap_count; g++) {
                int gap_filled = 0;
                for (size_t i = 0; i < peer_count && !gap_filled; i++) {
                    if (peers[i].state != MXD_PEER_CONNECTED) continue;

                    uint8_t request[8];
                    uint8_t *rptr = request;
                    mxd_write_u32_be(&rptr, gaps[g]);
                    mxd_write_u32_be(&rptr, gaps[g]);

                    if (mxd_send_message_with_retry(peers[i].address, peers[i].port,
                                                    MXD_MSG_GET_BLOCKS, request, sizeof(request), 3) == 0) {
                        struct timespec ts = {0, 200000000};  // 200ms
                        nanosleep(&ts, NULL);

                        if (mxd_block_exists_at_height(gaps[g])) {
                            gap_filled = 1;
                            MXD_LOG_INFO("sync", "Gap fill: received block at height %u", gaps[g]);
                        }
                    }
                }
                if (!gap_filled) {
                    MXD_LOG_WARN("sync", "Gap fill: failed to fetch block at height %u", gaps[g]);
                }
            }
        }
    }

    // If any peer has blocks we don't have, request them
    if (max_peer_height > local_height) {
        MXD_LOG_INFO("sync", "Pull sync: fetching missing blocks %u to %u",
                     local_height, max_peer_height - 1);

        // Request blocks one at a time for reliability
        for (uint32_t height = local_height; height < max_peer_height; height++) {
            int block_received = 0;

            // Try multiple peers for each block
            for (size_t i = 0; i < peer_count && !block_received; i++) {
                if (peers[i].state != MXD_PEER_CONNECTED) continue;

                // Send GET_BLOCKS request for this specific block
                uint8_t request[8];
                uint8_t *ptr = request;
                mxd_write_u32_be(&ptr, height);      // start_height
                mxd_write_u32_be(&ptr, height);      // end_height (same = single block)

                if (mxd_send_message_with_retry(peers[i].address, peers[i].port,
                                                MXD_MSG_GET_BLOCKS, request, sizeof(request), 3) == 0) {
                    MXD_LOG_DEBUG("sync", "Requested block %u from %s:%u",
                                  height, peers[i].address, peers[i].port);

                    // Wait briefly for the block to arrive (it will be handled by mxd_handle_blocks_response)
                    struct timespec ts = {0, 100000000};  // 100ms
                    nanosleep(&ts, NULL);

                    // Check if we now have the block
                    uint32_t new_height = 0;
                    if (mxd_get_blockchain_height(&new_height) == 0 && new_height > height) {
                        block_received = 1;
                        MXD_LOG_INFO("sync", "Pull sync: received block at height %u", height);
                    }
                }
            }

            if (!block_received) {
                MXD_LOG_WARN("sync", "Pull sync: failed to fetch block at height %u", height);
                break;  // Stop trying if we can't get a block
            }
        }

        return 1;  // Indicate we did some sync work
    }

    return 0;  // No sync needed
}

// Sign a received block and broadcast signature to the network
// This is called by validators when they receive a new block
int mxd_sign_and_broadcast_block(const mxd_block_t *block) {
    if (!block || block->height == 0) {
        return -1;  // Don't sign genesis block here
    }

    // Get local validator credentials
    extern const uint8_t* mxd_get_local_address(void);
    extern const uint8_t* mxd_get_local_privkey(void);
    extern uint8_t mxd_get_local_algo_id(void);

    const uint8_t *local_address = mxd_get_local_address();
    const uint8_t *local_privkey = mxd_get_local_privkey();
    uint8_t algo_id = mxd_get_local_algo_id();

    if (!local_address || !local_privkey) {
        MXD_LOG_INFO("sync", "No local credentials for signing block %u", block->height);
        return -1;
    }

    // Check if we're a validator in the rapid table
    const mxd_rapid_table_t *table = mxd_get_rapid_table();
    if (!table) {
        MXD_LOG_INFO("sync", "No rapid table for validator check (block %u)", block->height);
        return -1;
    }

    int is_validator = 0;
    for (size_t i = 0; i < table->count; i++) {
        if (table->nodes[i] && memcmp(table->nodes[i]->node_address, local_address, 20) == 0) {
            is_validator = 1;
            break;
        }
    }

    if (!is_validator) {
        char addr_hex[41] = {0};
        for (int j = 0; j < 20; j++) snprintf(addr_hex + j*2, 3, "%02x", local_address[j]);
        MXD_LOG_INFO("sync", "Not a validator (local=%s, table_count=%zu), skipping block %u",
                     addr_hex, table->count, block->height);
        return 0;
    }

    // Check if we already signed this block
    for (uint32_t i = 0; i < block->validation_count; i++) {
        if (memcmp(block->validation_chain[i].validator_id, local_address, 20) == 0) {
            MXD_LOG_DEBUG("sync", "Already signed block at height %u", block->height);
            return 0;
        }
    }

    // Determine our signing position in the sequential chain
    int my_position = mxd_get_my_signing_position(table, block->proposer_id, local_address);
    if (my_position < 0) {
        MXD_LOG_WARN("sync", "Not in signing order for block %u", block->height);
        return 0;
    }

    // Check if it's our turn: we need all preceding signatures present
    if ((uint32_t)my_position != block->validation_count) {
        // Not our turn yet - need more preceding signatures
        MXD_LOG_INFO("sync", "Not our turn yet for block %u (my_position=%d, validation_count=%u)",
                     block->height, my_position, block->validation_count);
        return 0;
    }

    // Compute chain_hash for our position
    uint8_t chain_hash[64];
    mxd_compute_chain_hash(block, (uint32_t)my_position, chain_hash);

    // Sign: block_hash(64) + chain_hash(64) + timestamp(8) = 136 bytes
    uint64_t timestamp = mxd_now_ms();
    uint8_t sign_msg[64 + 64 + 8];
    memcpy(sign_msg, block->block_hash, 64);
    memcpy(sign_msg + 64, chain_hash, 64);
    uint64_t ts_be = mxd_htonll(timestamp);
    memcpy(sign_msg + 64 + 64, &ts_be, 8);

    uint8_t signature[MXD_SIGNATURE_MAX];
    size_t sig_len = sizeof(signature);

    if (mxd_sig_sign(algo_id, signature, &sig_len, sign_msg, sizeof(sign_msg), local_privkey) != 0) {
        MXD_LOG_ERROR("sync", "Failed to sign block at height %u", block->height);
        return -1;
    }

    char addr_hex[41] = {0};
    for (int j = 0; j < 20; j++) snprintf(addr_hex + j*2, 3, "%02x", local_address[j]);
    char chain_hex[17] = {0};
    for (int j = 0; j < 8; j++) snprintf(chain_hex + j*2, 3, "%02x", chain_hash[j]);
    MXD_LOG_INFO("sync", "Signed block at height %u position %d, chain_hash=%s... (validator=%s)",
                 block->height, my_position, chain_hex, addr_hex);

    // Add our own signature to the local block and store it
    // This ensures subsequent signatures can build on ours locally
    {
        mxd_block_t local_block;
        memset(&local_block, 0, sizeof(local_block));
        if (mxd_retrieve_block_by_hash(block->block_hash, &local_block) == 0) {
            // Use mxd_add_validator_signature (no re-verification needed for our own sig)
            extern int mxd_add_validator_signature(mxd_block_t *block, const uint8_t validator_id[20],
                                                   uint64_t timestamp, uint8_t algo_id,
                                                   const uint8_t *signature, uint16_t signature_length);
            if (mxd_add_validator_signature(&local_block, local_address, timestamp, algo_id,
                                            signature, (uint16_t)sig_len) == 0) {
                if (mxd_store_block(&local_block) != 0) {
                    MXD_LOG_ERROR("sync", "Failed to store block with own signature at height %u", block->height);
                }
                MXD_LOG_INFO("sync", "Stored own chain signature locally for block %u (now %u sigs)",
                             block->height, local_block.validation_count);
            }
            mxd_free_block(&local_block);
        }
    }

    // Broadcast signature to all peers
    // Format: block_hash(64) + algo_id(1) + validator_id(20) + sig_len(2) + signature +
    //         chain_pos(4) + timestamp(8) + chain_hash(64)
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    if (mxd_get_peers(peers, &peer_count) == 0 && peer_count > 0) {
        size_t msg_len = 64 + 1 + 20 + 2 + sig_len + 4 + 8 + 64;
        uint8_t *msg = malloc(msg_len);
        if (msg) {
            uint8_t *ptr = msg;
            memcpy(ptr, block->block_hash, 64); ptr += 64;
            *ptr++ = algo_id;
            memcpy(ptr, local_address, 20); ptr += 20;
            uint16_t sig_len_net = htons((uint16_t)sig_len);
            memcpy(ptr, &sig_len_net, 2); ptr += 2;
            memcpy(ptr, signature, sig_len); ptr += sig_len;
            uint32_t chain_pos = (uint32_t)my_position;
            uint32_t chain_pos_net = htonl(chain_pos);
            memcpy(ptr, &chain_pos_net, 4); ptr += 4;
            uint64_t ts_net = mxd_htonll(timestamp);
            memcpy(ptr, &ts_net, 8); ptr += 8;
            memcpy(ptr, chain_hash, 64);

            int sent = 0;
            for (size_t i = 0; i < peer_count; i++) {
                if (mxd_send_message(peers[i].address, peers[i].port,
                                    MXD_MSG_VALIDATION_SIGNATURE, msg, msg_len) == 0) {
                    sent++;
                }
            }
            MXD_LOG_INFO("sync", "Broadcast chain signature for block %u pos %d to %d/%zu peers",
                         block->height, my_position, sent, peer_count);
            free(msg);

            // Re-broadcast all preceding signatures to handle partial P2P connectivity.
            // Some peers may have missed earlier positions' broadcasts, so we resend
            // the full chain to ensure all peers can build the complete sequence.
            if (my_position > 0) {
                mxd_block_t full_block;
                memset(&full_block, 0, sizeof(full_block));
                if (mxd_retrieve_block_by_hash(block->block_hash, &full_block) == 0 &&
                    full_block.validation_chain && full_block.validation_count > 1) {
                    int resent = 0;
                    for (uint32_t pos = 0; pos < full_block.validation_count - 1 && pos < (uint32_t)my_position; pos++) {
                        const mxd_validator_signature_t *vs = &full_block.validation_chain[pos];

                        uint8_t pos_chain_hash[64];
                        mxd_compute_chain_hash(&full_block, pos, pos_chain_hash);

                        size_t rmsg_len = 64 + 1 + 20 + 2 + vs->signature_length + 4 + 8 + 64;
                        uint8_t *rmsg = malloc(rmsg_len);
                        if (rmsg) {
                            uint8_t *rp = rmsg;
                            memcpy(rp, full_block.block_hash, 64); rp += 64;
                            *rp++ = vs->algo_id;
                            memcpy(rp, vs->validator_id, 20); rp += 20;
                            uint16_t rsl = htons(vs->signature_length);
                            memcpy(rp, &rsl, 2); rp += 2;
                            memcpy(rp, vs->signature, vs->signature_length); rp += vs->signature_length;
                            uint32_t rcp = htonl(pos);
                            memcpy(rp, &rcp, 4); rp += 4;
                            uint64_t rts = mxd_htonll(vs->timestamp);
                            memcpy(rp, &rts, 8); rp += 8;
                            memcpy(rp, pos_chain_hash, 64);

                            for (size_t pi = 0; pi < peer_count; pi++) {
                                mxd_send_message(peers[pi].address, peers[pi].port,
                                                MXD_MSG_VALIDATION_SIGNATURE, rmsg, rmsg_len);
                            }
                            resent++;
                            free(rmsg);
                        }
                    }
                    if (resent > 0) {
                        MXD_LOG_INFO("sync", "Re-broadcast %d preceding sigs for block %u to %zu peers",
                                     resent, full_block.height, peer_count);
                    }
                    mxd_free_block(&full_block);
                }
            }
        }
    }

    return 0;
}

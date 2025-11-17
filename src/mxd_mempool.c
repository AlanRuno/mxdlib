#include "../include/mxd_mempool.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_config.h"
#include "../metrics/mxd_prometheus.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MXD_MAX_PEER_TX_COUNT 100
#define MXD_MAX_PEER_TX_SIZE (10 * 1024 * 1024)
#define MXD_MAX_PEER_TX_RATE 10

typedef struct {
  char peer_id[64];
  size_t tx_count;
  size_t total_size;
  time_t last_tx_time;
  size_t tx_in_last_second;
  time_t rate_window_start;
} mxd_peer_quota_t;

static mxd_mempool_entry_t *mempool = NULL;
static size_t mempool_size = 0;
static mxd_peer_quota_t *peer_quotas = NULL;
static size_t peer_quota_count = 0;
static size_t peer_quota_capacity = 0;

static mxd_peer_quota_t* get_or_create_peer_quota(const char* peer_id) {
  if (!peer_id) {
    return NULL;
  }
  
  for (size_t i = 0; i < peer_quota_count; i++) {
    if (strcmp(peer_quotas[i].peer_id, peer_id) == 0) {
      return &peer_quotas[i];
    }
  }
  
  if (peer_quota_count >= peer_quota_capacity) {
    size_t new_capacity = peer_quota_capacity == 0 ? 16 : peer_quota_capacity * 2;
    mxd_peer_quota_t* new_quotas = realloc(peer_quotas, new_capacity * sizeof(mxd_peer_quota_t));
    if (!new_quotas) {
      return NULL;
    }
    peer_quotas = new_quotas;
    peer_quota_capacity = new_capacity;
  }
  
  mxd_peer_quota_t* quota = &peer_quotas[peer_quota_count++];
  memset(quota, 0, sizeof(mxd_peer_quota_t));
  strncpy(quota->peer_id, peer_id, sizeof(quota->peer_id) - 1);
  quota->rate_window_start = time(NULL);
  return quota;
}

static int check_peer_quota(const char* peer_id, size_t tx_size) {
  mxd_peer_quota_t* quota = get_or_create_peer_quota(peer_id);
  if (!quota) {
    return -1;
  }
  
  time_t now = time(NULL);
  
  if (now - quota->rate_window_start >= 1) {
    quota->tx_in_last_second = 0;
    quota->rate_window_start = now;
  }
  
  if (quota->tx_in_last_second >= MXD_MAX_PEER_TX_RATE) {
    mxd_metrics_increment("mempool_peer_rate_limited_total");
    return -1;
  }
  
  if (quota->tx_count >= MXD_MAX_PEER_TX_COUNT) {
    mxd_metrics_increment("mempool_peer_quota_exceeded_total");
    return -1;
  }
  
  if (quota->total_size + tx_size > MXD_MAX_PEER_TX_SIZE) {
    mxd_metrics_increment("mempool_peer_size_exceeded_total");
    return -1;
  }
  
  return 0;
}

static void update_peer_quota(const char* peer_id, size_t tx_size) {
  mxd_peer_quota_t* quota = get_or_create_peer_quota(peer_id);
  if (!quota) {
    return;
  }
  
  quota->tx_count++;
  quota->total_size += tx_size;
  quota->last_tx_time = time(NULL);
  quota->tx_in_last_second++;
}

int mxd_init_mempool(void) {
  if (mempool) {
    for (size_t i = 0; i < mempool_size; i++) {
      free(mempool[i].tx.inputs);
      free(mempool[i].tx.outputs);
    }
    free(mempool);
  }
  
  if (peer_quotas) {
    free(peer_quotas);
  }
  
  mempool = malloc(MXD_MAX_MEMPOOL_SIZE * sizeof(mxd_mempool_entry_t));
  if (!mempool) {
    return -1;
  }
  memset(mempool, 0, MXD_MAX_MEMPOOL_SIZE * sizeof(mxd_mempool_entry_t));
  mempool_size = 0;
  
  peer_quotas = NULL;
  peer_quota_count = 0;
  peer_quota_capacity = 0;
  
  return 0;
}

// Compare function for transaction sorting
static int compare_tx_entries(const void *a, const void *b) {
  const mxd_mempool_entry_t *entry_a = (const mxd_mempool_entry_t *)a;
  const mxd_mempool_entry_t *entry_b = (const mxd_mempool_entry_t *)b;

  // First compare by priority
  if (entry_a->priority != entry_b->priority) {
    return entry_b->priority - entry_a->priority;
  }

  // Then by fee (higher fee first)
  if (entry_a->fee > entry_b->fee)
    return -1;
  if (entry_a->fee < entry_b->fee)
    return 1;

  // Finally by timestamp (older first)
  if (entry_a->timestamp < entry_b->timestamp)
    return -1;
  if (entry_a->timestamp > entry_b->timestamp)
    return 1;

  return 0;
}

static size_t calculate_tx_size(const mxd_transaction_t *tx) {
  if (!tx) {
    return 0;
  }
  
  size_t size = sizeof(mxd_transaction_t);
  size += tx->input_count * sizeof(mxd_tx_input_t);
  size += tx->output_count * sizeof(mxd_tx_output_t);
  return size;
}

static int evict_lowest_priority_tx(void) {
  if (mempool_size == 0) {
    return -1;
  }
  
  size_t lowest_idx = mempool_size - 1;
  
  free(mempool[lowest_idx].tx.inputs);
  free(mempool[lowest_idx].tx.outputs);
  
  mempool_size--;
  mxd_metrics_increment("mempool_evictions_total");
  
  return 0;
}

int mxd_add_to_mempool_with_peer(const mxd_transaction_t *tx,
                                  mxd_tx_priority_t priority,
                                  const char *peer_id) {
  if (!tx || !mempool || priority < MXD_PRIORITY_LOW ||
      priority > MXD_PRIORITY_HIGH) {
    return -1;
  }

  size_t tx_size = calculate_tx_size(tx);
  
  if (peer_id && check_peer_quota(peer_id, tx_size) != 0) {
    return -1;
  }

  if (mempool_size >= MXD_MAX_MEMPOOL_SIZE) {
    if (evict_lowest_priority_tx() != 0) {
      return -1;
    }
  }

  // Calculate transaction hash
  uint8_t tx_hash[64];
  if (mxd_calculate_tx_hash(tx, tx_hash) != 0) {
    return -1;
  }

  // Check if transaction already exists
  for (size_t i = 0; i < mempool_size; i++) {
    uint8_t existing_hash[64];
    if (mxd_calculate_tx_hash(&mempool[i].tx, existing_hash) == 0 &&
        memcmp(existing_hash, tx_hash, 64) == 0) {
      return -1;
    }
  }

  // Initialize new entry
  memset(&mempool[mempool_size], 0, sizeof(mxd_mempool_entry_t));

  // Copy basic transaction fields
  memcpy(&mempool[mempool_size].tx, tx, sizeof(mxd_transaction_t));
  mempool[mempool_size].tx.inputs = NULL;
  mempool[mempool_size].tx.outputs = NULL;

  // Copy inputs if present
  if (tx->inputs && tx->input_count > 0) {
    mempool[mempool_size].tx.inputs =
        malloc(tx->input_count * sizeof(mxd_tx_input_t));
    if (!mempool[mempool_size].tx.inputs) {
      return -1;
    }
    memcpy(mempool[mempool_size].tx.inputs, tx->inputs,
           tx->input_count * sizeof(mxd_tx_input_t));
  }

  // Copy outputs if present
  if (tx->outputs && tx->output_count > 0) {
    mempool[mempool_size].tx.outputs =
        malloc(tx->output_count * sizeof(mxd_tx_output_t));
    if (!mempool[mempool_size].tx.outputs) {
      free(mempool[mempool_size].tx.inputs);
      return -1;
    }
    memcpy(mempool[mempool_size].tx.outputs, tx->outputs,
           tx->output_count * sizeof(mxd_tx_output_t));
  }

  mempool[mempool_size].priority = priority;
  mempool[mempool_size].timestamp = time(NULL);
  mempool[mempool_size].fee = mxd_get_voluntary_tip(tx);

  mempool_size++;

  if (peer_id) {
    update_peer_quota(peer_id, tx_size);
  }

  qsort(mempool, mempool_size, sizeof(mxd_mempool_entry_t), compare_tx_entries);

  mxd_metrics_increment("mempool_transactions_added_total");

  return 0;
}

int mxd_add_to_mempool(const mxd_transaction_t *tx, mxd_tx_priority_t priority) {
  return mxd_add_to_mempool_with_peer(tx, priority, NULL);
}

// Remove transaction from mempool
int mxd_remove_from_mempool(const uint8_t tx_hash[64]) {
  if (!tx_hash || !mempool) {
    return -1;
  }

  for (size_t i = 0; i < mempool_size; i++) {
    uint8_t current_hash[64];
    if (mxd_calculate_tx_hash(&mempool[i].tx, current_hash) == 0 &&
        memcmp(current_hash, tx_hash, 64) == 0) {
      // Free transaction resources
      free(mempool[i].tx.inputs);
      free(mempool[i].tx.outputs);

      // Remove by shifting remaining entries
      if (i < mempool_size - 1) {
        memmove(&mempool[i], &mempool[i + 1],
                (mempool_size - i - 1) * sizeof(mxd_mempool_entry_t));
      }
      mempool_size--;
      return 0;
    }
  }

  return -1; // Transaction not found
}

// Get transaction from mempool
int mxd_get_from_mempool(const uint8_t tx_hash[64], mxd_transaction_t *tx) {
  if (!tx_hash || !tx || !mempool) {
    return -1;
  }

  for (size_t i = 0; i < mempool_size; i++) {
    uint8_t current_hash[64];
    if (mxd_calculate_tx_hash(&mempool[i].tx, current_hash) == 0 &&
        memcmp(current_hash, tx_hash, 64) == 0) {
      // Copy basic fields
      memcpy(tx, &mempool[i].tx, sizeof(mxd_transaction_t));
      tx->inputs = NULL;
      tx->outputs = NULL;

      // Copy inputs if present
      if (mempool[i].tx.inputs && tx->input_count > 0) {
        tx->inputs = malloc(tx->input_count * sizeof(mxd_tx_input_t));
        if (!tx->inputs) {
          return -1;
        }
        memcpy(tx->inputs, mempool[i].tx.inputs,
               tx->input_count * sizeof(mxd_tx_input_t));
      }

      // Copy outputs if present
      if (mempool[i].tx.outputs && tx->output_count > 0) {
        tx->outputs = malloc(tx->output_count * sizeof(mxd_tx_output_t));
        if (!tx->outputs) {
          free(tx->inputs);
          return -1;
        }
        memcpy(tx->outputs, mempool[i].tx.outputs,
               tx->output_count * sizeof(mxd_tx_output_t));
      }

      return 0;
    }
  }

  return -1; // Transaction not found
}

// Get highest priority transactions
int mxd_get_priority_transactions(mxd_transaction_t *txs, size_t *tx_count,
                                  mxd_tx_priority_t min_priority) {
  if (!txs || !tx_count || !mempool || *tx_count == 0 ||
      min_priority < MXD_PRIORITY_LOW || min_priority > MXD_PRIORITY_HIGH) {
    return -1;
  }

  size_t count = 0;
  for (size_t i = 0; i < mempool_size && count < *tx_count; i++) {
    if (mempool[i].priority >= min_priority) {
      // Copy basic fields
      memcpy(&txs[count], &mempool[i].tx, sizeof(mxd_transaction_t));
      txs[count].inputs = NULL;
      txs[count].outputs = NULL;

      // Copy inputs if present
      if (mempool[i].tx.inputs && txs[count].input_count > 0) {
        txs[count].inputs =
            malloc(txs[count].input_count * sizeof(mxd_tx_input_t));
        if (!txs[count].inputs) {
          // Clean up previous transactions
          for (size_t j = 0; j < count; j++) {
            free(txs[j].inputs);
            free(txs[j].outputs);
          }
          return -1;
        }
        memcpy(txs[count].inputs, mempool[i].tx.inputs,
               txs[count].input_count * sizeof(mxd_tx_input_t));
      }

      // Copy outputs if present
      if (mempool[i].tx.outputs && txs[count].output_count > 0) {
        txs[count].outputs =
            malloc(txs[count].output_count * sizeof(mxd_tx_output_t));
        if (!txs[count].outputs) {
          free(txs[count].inputs);
          // Clean up previous transactions
          for (size_t j = 0; j < count; j++) {
            free(txs[j].inputs);
            free(txs[j].outputs);
          }
          return -1;
        }
        memcpy(txs[count].outputs, mempool[i].tx.outputs,
               txs[count].output_count * sizeof(mxd_tx_output_t));
      }

      count++;
    }
  }

  *tx_count = count;
  return 0;
}

// Clean expired transactions
int mxd_clean_mempool(uint64_t max_age) {
  if (!mempool) {
    return -1;
  }

  uint64_t current_time = time(NULL);
  size_t write_index = 0;

  for (size_t i = 0; i < mempool_size; i++) {
    if (current_time - mempool[i].timestamp <= max_age) {
      if (i != write_index) {
        // Free destination transaction resources
        free(mempool[write_index].tx.inputs);
        free(mempool[write_index].tx.outputs);

        // Copy entry
        memcpy(&mempool[write_index], &mempool[i], sizeof(mxd_mempool_entry_t));

        // Clear source pointers to prevent double free
        mempool[i].tx.inputs = NULL;
        mempool[i].tx.outputs = NULL;
      }
      write_index++;
    } else {
      // Free expired transaction resources
      free(mempool[i].tx.inputs);
      free(mempool[i].tx.outputs);
      mempool[i].tx.inputs = NULL;
      mempool[i].tx.outputs = NULL;
    }
  }

  mempool_size = write_index;
  return 0;
}

// Get current mempool size
size_t mxd_get_mempool_size(void) { return mempool_size; }

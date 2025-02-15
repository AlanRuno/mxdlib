#ifndef MXD_RSC_H
#define MXD_RSC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Node stake information
typedef struct {
  char node_id[64];
  double stake_amount;
  uint32_t response_time;
  uint8_t public_key[256];
} mxd_node_stake_t;

// Validate if a node meets Rapid Stake requirements
int mxd_validate_node_stake(const mxd_node_stake_t *node, double total_stake);

// Update node response metrics
int mxd_update_node_metrics(mxd_node_stake_t *node, uint32_t response_time);

// Calculate node ranking based on stake and speed
int mxd_calculate_node_rank(const mxd_node_stake_t *node);

// Manage rapid table entries
int mxd_update_rapid_table(mxd_node_stake_t *nodes, size_t node_count);

#ifdef __cplusplus
}
#endif

#endif // MXD_RSC_H

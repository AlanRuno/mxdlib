#include "../../include/mxd_rsc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Validate if a node meets Rapid Stake requirements
int mxd_validate_node_stake(const mxd_node_stake_t *node, double total_stake) {
  if (!node || total_stake <= 0) {
    return -1;
  }

  // Calculate stake percentage
  double stake_percent = (node->stake_amount / total_stake) * 100.0;

  // Check minimum stake requirement (0.1%)
  return stake_percent >= 0.1 ? 0 : -1;
}

// Update node response metrics
int mxd_update_node_metrics(mxd_node_stake_t *node, uint32_t response_time) {
  if (!node) {
    return -1;
  }

  // Update response time
  node->response_time = response_time;

  return 0;
}

// Calculate node ranking based on stake and speed
int mxd_calculate_node_rank(const mxd_node_stake_t *node) {
  if (!node) {
    return -1;
  }

  // For now, just return a simple score based on stake and response time
  // Lower response time and higher stake = better score
  if (node->response_time == 0) {
    return -1; // Invalid response time
  }

  // Score = stake_amount * 1000 / response_time
  // Higher score = better rank
  // Multiply by 1000 to maintain precision with integer division
  return (int)((node->stake_amount * 1000.0) / node->response_time);
}

// Compare function for node ranking
static int compare_nodes(const void *a, const void *b) {
  const mxd_node_stake_t *node_a = (const mxd_node_stake_t *)a;
  const mxd_node_stake_t *node_b = (const mxd_node_stake_t *)b;

  // Sort by response time (lower is better)
  if (node_a->response_time != node_b->response_time) {
    return (node_a->response_time > node_b->response_time) ? 1 : -1;
  }

  // If response times are equal, sort by stake (higher is better)
  if (node_a->stake_amount != node_b->stake_amount) {
    return (node_a->stake_amount < node_b->stake_amount) ? 1 : -1;
  }

  return 0;
}

// Manage rapid table entries
int mxd_update_rapid_table(mxd_node_stake_t *nodes, size_t node_count) {
  if (!nodes || node_count == 0) {
    return -1;
  }

  // Sort nodes by rank
  qsort(nodes, node_count, sizeof(mxd_node_stake_t), compare_nodes);

  return 0;
}

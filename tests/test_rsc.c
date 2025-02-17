#include "../include/mxd_rsc.h"
#include "../include/mxd_ntp.h"
#include "../src/blockchain/mxd_rsc_internal.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

static void test_node_validation(void) {
  mxd_node_stake_t node;
  memset(&node, 0, sizeof(node));
  node.stake_amount = 1.0;
  node.active = 1;
  assert(mxd_init_node_metrics(&node.metrics) == 0);

  // Test valid stake (1% of 100)
  assert(mxd_validate_node_stake(&node, 100.0) == 0);

  // Test invalid stake (0.05% of 100)
  node.stake_amount = 0.05;
  assert(mxd_validate_node_stake(&node, 100.0) == -1);

  printf("Node validation test passed\n");
}

static void test_node_metrics(void) {
  mxd_node_stake_t node;
  memset(&node, 0, sizeof(node));
  node.stake_amount = 1.0;
  node.active = 1;
  assert(mxd_init_node_metrics(&node.metrics) == 0);

  uint64_t timestamp;
  assert(mxd_get_network_time(&timestamp) == 0);

  // Update metrics
  assert(mxd_update_node_metrics(&node, 100, timestamp) == 0);
  assert(node.metrics.avg_response_time == 100);

  assert(mxd_update_node_metrics(&node, 200, timestamp + 1000) == 0);
  assert(node.metrics.avg_response_time == 150); // (100 + 200) / 2

  printf("Node metrics test passed\n");
}

static void test_node_ranking(void) {
  mxd_node_stake_t node;
  memset(&node, 0, sizeof(node));
  node.stake_amount = 1.0;
  node.active = 1;
  assert(mxd_init_node_metrics(&node.metrics) == 0);

  uint64_t timestamp;
  assert(mxd_get_network_time(&timestamp) == 0);

  // Add enough responses to meet minimum requirement
  for (int i = 0; i < MXD_MIN_RESPONSE_COUNT; i++) {
    assert(mxd_update_node_metrics(&node, 100, timestamp + i * 1000) == 0);
  }

  // Test valid ranking
  int rank = mxd_calculate_node_rank(&node, 1000.0);
  assert(rank >= 0);
  assert(rank <= 1000);

  // Test inactive node
  node.active = 0;
  assert(mxd_calculate_node_rank(&node, 1000.0) == -1);

  printf("Node ranking test passed\n");
}

static void test_rapid_table(void) {
  const size_t node_count = 3;
  mxd_node_stake_t nodes[node_count];
  memset(nodes, 0, sizeof(nodes));

  uint64_t timestamp;
  assert(mxd_get_network_time(&timestamp) == 0);

  // Initialize nodes with different performance profiles
  for (size_t i = 0; i < node_count; i++) {
    nodes[i].stake_amount = 1000.0 * (i + 1);
    nodes[i].active = 1;
    assert(mxd_init_node_metrics(&nodes[i].metrics) == 0);

    // Add responses with varying performance
    for (int j = 0; j < MXD_MIN_RESPONSE_COUNT; j++) {
      assert(mxd_update_node_metrics(&nodes[i], 100 * (i + 1), timestamp + j * 1000) == 0);
    }
  }

  // Update rapid table
  double total_stake = 6000.0; // Sum of all stake amounts
  assert(mxd_update_rapid_table(nodes, node_count, total_stake) == 0);

  // Verify nodes are sorted by rank (higher rank first)
  for (size_t i = 1; i < node_count; i++) {
    assert(nodes[i-1].rank >= nodes[i].rank);
  }

  printf("Rapid table test passed\n");
}

int main(void) {
  printf("Starting RSC tests...\n");

  // Initialize NTP synchronization
  assert(mxd_init_ntp() == 0);

  test_node_validation();
  test_node_metrics();
  test_node_ranking();
  test_rapid_table();

  printf("All RSC tests passed\n");
  return 0;
}

#include "../include/mxd_rsc.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_node_validation(void) {
  mxd_node_stake_t node = {.stake_amount = 1.0, .response_time = 100};

  // Test valid stake (1% of 100)
  assert(mxd_validate_node_stake(&node, 100.0) == 0);

  // Test invalid stake (0.05% of 100)
  node.stake_amount = 0.05;
  assert(mxd_validate_node_stake(&node, 100.0) == -1);

  printf("Node validation test passed\n");
}

static void test_node_metrics(void) {
  mxd_node_stake_t node = {.stake_amount = 1.0, .response_time = 100};

  // Update metrics
  assert(mxd_update_node_metrics(&node, 200) == 0);
  assert(node.response_time == 200);

  printf("Node metrics test passed\n");
}

static void test_node_ranking(void) {
  mxd_node_stake_t node = {.stake_amount = 1.0, .response_time = 100};

  // Test ranking calculation
  int rank = mxd_calculate_node_rank(&node);
  assert(rank >= 0);

  // Test invalid response time
  node.response_time = 0;
  assert(mxd_calculate_node_rank(&node) == -1);

  printf("Node ranking test passed\n");
}

static void test_rapid_table(void) {
  mxd_node_stake_t nodes[3] = {{.stake_amount = 1.0, .response_time = 300},
                               {.stake_amount = 2.0, .response_time = 200},
                               {.stake_amount = 1.5, .response_time = 100}};

  // Update rapid table
  assert(mxd_update_rapid_table(nodes, 3) == 0);

  // Verify nodes are sorted by rank
  assert(nodes[0].response_time < nodes[1].response_time);
  assert(nodes[1].response_time < nodes[2].response_time);

  printf("Rapid table test passed\n");
}

int main(void) {
  printf("Starting RSC tests...\n");

  test_node_validation();
  test_node_metrics();
  test_node_ranking();
  test_rapid_table();

  printf("All RSC tests passed\n");
  return 0;
}

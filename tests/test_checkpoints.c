#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../include/mxd_checkpoints.h"

static void test_checkpoint_initialization(void) {
    mxd_checkpoint_manager_t manager;
    assert(mxd_init_checkpoints(&manager, 10) == 0);
    assert(manager.capacity == 10);
    assert(manager.count == 0);
    assert(manager.last_height == 0);
    mxd_free_checkpoints(&manager);
    printf("Checkpoint initialization test passed\n");
}

static void test_checkpoint_creation(void) {
    mxd_checkpoint_manager_t manager;
    assert(mxd_init_checkpoints(&manager, 2) == 0);

    // Create test state
    uint8_t state[64] = {1, 2, 3, 4};
    uint64_t height = 100;
    uint64_t timestamp = 1234567890;

    // Create checkpoint
    assert(mxd_create_checkpoint(&manager, state, sizeof(state),
                               height, timestamp) == 0);
    assert(manager.count == 1);
    assert(manager.last_height == height);

    // Verify checkpoint data
    mxd_checkpoint_t *checkpoint = &manager.checkpoints[0];
    assert(checkpoint->block_height == height);
    assert(checkpoint->timestamp == timestamp);

    // Create second checkpoint
    height = 200;
    timestamp = 1234567891;
    assert(mxd_create_checkpoint(&manager, state, sizeof(state),
                               height, timestamp) == 0);
    assert(manager.count == 2);
    assert(manager.last_height == height);

    mxd_free_checkpoints(&manager);
    printf("Checkpoint creation test passed\n");
}

static void test_checkpoint_validation(void) {
    mxd_checkpoint_manager_t manager;
    assert(mxd_init_checkpoints(&manager, 2) == 0);

    // Create initial checkpoint
    uint8_t state[64] = {1, 2, 3, 4};
    assert(mxd_create_checkpoint(&manager, state, sizeof(state),
                               100, 1234567890) == 0);

    // Create and validate second checkpoint
    mxd_checkpoint_t checkpoint = {0};
    checkpoint.block_height = 200;
    checkpoint.timestamp = 1234567891;
    memcpy(checkpoint.prev_hash, manager.checkpoints[0].state_hash, 64);
    memcpy(checkpoint.state_hash, state, 64);
    mxd_sha512(checkpoint.state_hash, 64, checkpoint.mmr_root);

    assert(mxd_validate_checkpoint(&manager, &checkpoint) == 0);

    mxd_free_checkpoints(&manager);
    printf("Checkpoint validation test passed\n");
}

static void test_checkpoint_pruning(void) {
    mxd_checkpoint_manager_t manager;
    assert(mxd_init_checkpoints(&manager, 4) == 0);

    // Create test checkpoints
    uint8_t state[64] = {1, 2, 3, 4};
    assert(mxd_create_checkpoint(&manager, state, sizeof(state),
                               100, 1234567890) == 0);
    assert(mxd_create_checkpoint(&manager, state, sizeof(state),
                               200, 1234567891) == 0);
    assert(mxd_create_checkpoint(&manager, state, sizeof(state),
                               300, 1234567892) == 0);

    // Prune checkpoints
    assert(mxd_prune_checkpoints(&manager, 200) == 0);
    assert(manager.count == 2);
    assert(manager.checkpoints[0].block_height == 200);

    mxd_free_checkpoints(&manager);
    printf("Checkpoint pruning test passed\n");
}

static void test_checkpoint_recovery(void) {
    mxd_checkpoint_manager_t manager;
    assert(mxd_init_checkpoints(&manager, 2) == 0);

    // Create test checkpoint
    uint8_t state[64] = {1, 2, 3, 4};
    assert(mxd_create_checkpoint(&manager, state, sizeof(state),
                               100, 1234567890) == 0);

    // Recover state
    uint8_t recovered_state[64];
    size_t recovered_size = sizeof(recovered_state);
    assert(mxd_recover_from_checkpoint(&manager, 150,
                                     recovered_state,
                                     &recovered_size) == 0);
    assert(recovered_size == 64);

    mxd_free_checkpoints(&manager);
    printf("Checkpoint recovery test passed\n");
}

int main(void) {
    printf("Starting checkpoint tests...\n");
    
    test_checkpoint_initialization();
    test_checkpoint_creation();
    test_checkpoint_validation();
    test_checkpoint_pruning();
    test_checkpoint_recovery();
    
    printf("All checkpoint tests passed\n");
    return 0;
}

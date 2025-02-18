#include <stdio.h>
#include <string.h>
#include "mxd_config.h"

int mxd_load_config(const char* config_file, mxd_config_t* config) {
    // Basic config loading for testing
    strncpy(config->node_id, "test_node", sizeof(config->node_id) - 1);
    config->port = 8000;
    strncpy(config->data_dir, "data", sizeof(config->data_dir) - 1);
    config->bootstrap_count = 0;
    return 0;
}

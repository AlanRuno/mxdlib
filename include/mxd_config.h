#ifndef MXD_CONFIG_H
#define MXD_CONFIG_H

#include <stdint.h>

typedef struct {
    char node_id[64];
    uint16_t port;
    char data_dir[256];
    char node_name[64];    // Added for node naming
    char node_data[1024];  // Added for custom data
    char bootstrap_nodes[10][256];
    int bootstrap_count;
} mxd_config_t;

int mxd_load_config(const char* config_file, mxd_config_t* config);

#endif // MXD_CONFIG_H

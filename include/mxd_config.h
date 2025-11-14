#ifndef MXD_CONFIG_H
#define MXD_CONFIG_H

#include <stdint.h>

// Bootstrap node metadata for hybrid cryptography support
typedef struct {
    char address[256];         // IP address or hostname
    uint16_t port;             // Port number
    uint8_t algo_id;           // Algorithm ID (1=Ed25519, 2=Dilithium5, 0=unknown)
    uint8_t public_key[2592];  // Public key (max size for Dilithium5)
    uint16_t public_key_length; // Actual public key length
    uint8_t address20[20];     // Cryptographic address (HASH160 of algo_id || pubkey)
    uint8_t has_crypto_info;   // 1 if algo_id and public_key are available, 0 otherwise
} mxd_bootstrap_node_t;

typedef struct {
    char node_id[64];
    uint16_t port;
    uint16_t metrics_port;     // Metrics/health endpoint port
    char data_dir[256];
    char network_type[32];     // mainnet, testnet
    char node_name[64];        // Node display name
    double initial_stake;      // Initial stake amount
    uint32_t metrics_interval; // Display refresh interval (ms)
    char bootstrap_nodes[10][256];  // Legacy format: "address:port" strings
    mxd_bootstrap_node_t bootstrap_nodes_v2[10];  // Enhanced format with crypto metadata
    int bootstrap_count;
    char node_data[1024];      // Custom node data
    int enable_upnp;           // Enable UPnP port mapping (1=enabled, 0=disabled)
    int bootstrap_refresh_interval;  // Seconds between bootstrap list refreshes (from network_info.update_interval)
    uint8_t preferred_sign_algo;     // Preferred signature algorithm (1=Ed25519, 2=Dilithium5)
} mxd_config_t;

// Load configuration from file or use built-in defaults.
// If config_file is NULL or file cannot be opened, default configuration will be used.
// Returns 0 on success, -1 on validation failure.
int mxd_load_config(const char* config_file, mxd_config_t* config);

// Fetch bootstrap nodes from network
// Returns 0 on success (including fallback), -1 on critical failure
int mxd_fetch_bootstrap_nodes(mxd_config_t* config);

#endif // MXD_CONFIG_H

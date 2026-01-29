#include "../include/mxd_protocol_version.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_config.h"
#include <string.h>

// Static network type (can be overridden for testing)
static mxd_network_type_t current_network = MXD_NETWORK_MAINNET;

// Activation heights for each network
static const mxd_activation_heights_t MAINNET_HEIGHTS = {
    .v2_activation_height = 10000,   // v2 activated at height 10,000 (historical)
    .v3_activation_height = 100000   // v3 will activate at height 100,000 (future)
};

static const mxd_activation_heights_t TESTNET_HEIGHTS = {
    .v2_activation_height = 1000,    // v2 activated at height 1,000 (historical)
    .v3_activation_height = 5000     // v3 will activate at height 5,000 (near future)
};

static const mxd_activation_heights_t DEVNET_HEIGHTS = {
    .v2_activation_height = 0,       // v2 from genesis
    .v3_activation_height = 0        // v3 from genesis (for development)
};

// Get activation heights for a specific network
mxd_activation_heights_t mxd_get_activation_heights(mxd_network_type_t network) {
    switch (network) {
        case MXD_NETWORK_MAINNET:
            return MAINNET_HEIGHTS;
        case MXD_NETWORK_TESTNET:
            return TESTNET_HEIGHTS;
        case MXD_NETWORK_DEVNET:
            return DEVNET_HEIGHTS;
        default:
            MXD_LOG_WARN("protocol", "Unknown network type %d, defaulting to mainnet", network);
            return MAINNET_HEIGHTS;
    }
}

// Get the required protocol version for a given block height
uint32_t mxd_get_required_protocol_version(uint32_t height, mxd_network_type_t network) {
    mxd_activation_heights_t heights = mxd_get_activation_heights(network);

    // Determine version based on activation heights
    if (height >= heights.v3_activation_height) {
        return MXD_PROTOCOL_VERSION_3;
    } else if (height >= heights.v2_activation_height) {
        return MXD_PROTOCOL_VERSION_2;
    } else {
        return MXD_PROTOCOL_VERSION_1;
    }
}

// Check if a block version is valid for its height
int mxd_is_valid_block_version(uint32_t block_version, uint32_t height,
                                mxd_network_type_t network) {
    uint32_t required_version = mxd_get_required_protocol_version(height, network);

    // Block must use the required version for its height
    // We allow exact match only (no forward/backward compatibility during migration)
    if (block_version != required_version) {
        MXD_LOG_WARN("protocol",
                     "Block version mismatch: height=%u requires v%u, but block has v%u",
                     height, required_version, block_version);
        return 0;
    }

    return 1;
}

// Get network type from configuration
mxd_network_type_t mxd_get_network_type(void) {
    const mxd_config_t* config = mxd_get_config();

    if (!config) {
        MXD_LOG_WARN("protocol", "No config available, using static network type");
        return current_network;
    }

    // Check if network type is configured
    // This assumes the config has a network field (may need to be added)
    // For now, return the static value
    return current_network;
}

// Set network type (for testing purposes)
void mxd_set_network_type(mxd_network_type_t network) {
    if (network > MXD_NETWORK_DEVNET) {
        MXD_LOG_ERROR("protocol", "Invalid network type: %d", network);
        return;
    }

    MXD_LOG_INFO("protocol", "Setting network type to %d", network);
    current_network = network;
}

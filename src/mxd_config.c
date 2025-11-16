#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <cjson/cJSON.h>
#include "mxd_config.h"
#include "utils/mxd_http.h"
#include "mxd_logging.h"

static mxd_config_t* global_config = NULL;

mxd_config_t* mxd_get_config(void) {
    return global_config;
}

void mxd_set_global_config(mxd_config_t* config) {
    global_config = config;
}

static char* trim(char* str) {
    char* end;
    while(isspace((unsigned char)*str)) str++;
    if(*str == 0) return str;
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static char* strip_quotes(char* str) {
    size_t len = strlen(str);
    if (len >= 2 && str[0] == '"' && str[len-1] == '"') {
        str[len-1] = '\0';
        return str + 1;
    }
    return str;
}

static int mxd_validate_config(mxd_config_t* config) {
    if (!config) return -1;
    
    // Validate port range
    if (config->port < 1024 || config->port > 65535) return -1;
    
    // Validate stake amount
    if (config->initial_stake < 0.0) return -1;
    
    // Validate intervals
    if (config->metrics_interval < 100) return -1;
    
    // Validate network type
    if (strcmp(config->network_type, "mainnet") != 0 && 
        strcmp(config->network_type, "testnet") != 0) return -1;
    
    // Validate bootstrap nodes
    if (config->bootstrap_count > 10) return -1;
    
    return 0;
}

static void mxd_set_default_config(mxd_config_t* config) {
    memset(config, 0, sizeof(mxd_config_t));
    
    // Node identification
    snprintf(config->node_id, sizeof(config->node_id), "node_%lu", (unsigned long)time(NULL));
    strncpy(config->node_name, "MXD Default Node", sizeof(config->node_name) - 1);
    strncpy(config->network_type, "testnet", sizeof(config->network_type) - 1);
    
    // Basic settings
    config->port = 8000;
    config->metrics_port = 8080;
    config->initial_stake = 100.0;
    config->metrics_interval = 1000;
    strncpy(config->data_dir, "data", sizeof(config->data_dir) - 1);
    
    // Default bootstrap nodes - will be fetched from API, this is fallback
    config->bootstrap_count = 0;
    
    // Node data (empty by default)
    strncpy(config->node_data, "", sizeof(config->node_data) - 1);
    
    config->enable_upnp = 1;
    config->bootstrap_refresh_interval = 300;
    config->preferred_sign_algo = 1;
    config->protocol_version = 3;
    
    strncpy(config->http.bind_address, "127.0.0.1", sizeof(config->http.bind_address) - 1);
    config->http.port = 8080;
    config->http.require_auth = 1;
    config->http.api_token[0] = '\0';
    config->http.wallet_enabled = 0;
    config->http.rate_limit_per_minute = 60;
    config->http.timeout_seconds = 30;
    
    strncpy(config->bootstrap.endpoint, "https://mxd.network/bootstrap/test", sizeof(config->bootstrap.endpoint) - 1);
    config->bootstrap.verify_tls = 1;
    config->bootstrap.pinned_keys_count = 0;
    config->bootstrap.fallback_count = 3;
    strncpy(config->bootstrap.fallback_nodes[0], "bootstrap1.mxd.network:8000", sizeof(config->bootstrap.fallback_nodes[0]) - 1);
    strncpy(config->bootstrap.fallback_nodes[1], "bootstrap2.mxd.network:8000", sizeof(config->bootstrap.fallback_nodes[1]) - 1);
    strncpy(config->bootstrap.fallback_nodes[2], "bootstrap3.mxd.network:8000", sizeof(config->bootstrap.fallback_nodes[2]) - 1);
    config->bootstrap.min_subnet_diversity = 2;
    
    config->mempool.max_size = 50000;
    config->mempool.max_tx_per_peer = 100;
    config->mempool.max_bytes_per_peer = 10485760;
    config->mempool.min_fee_per_byte = 1;
    config->mempool.max_tx_per_sec_per_peer = 10;
    
    config->contracts.gas_limit_default = 1000000;
    config->contracts.timeout_seconds = 5;
    config->contracts.metering_enabled = 1;
    config->contracts.max_memory_pages = 256;
    
    config->consensus.blacklist_duration_blocks = 1000;
    config->consensus.min_unique_validators = 3;
    config->consensus.signature_cache_size = 10000;
    
    config->p2p_security.challenge_cache_size = 10000;
    config->p2p_security.challenge_ttl_seconds = 300;
    config->p2p_security.session_timeout_seconds = 3600;
    config->p2p_security.timestamp_tolerance_seconds = 60;
}

int mxd_load_config(const char* config_file, mxd_config_t* config) {
    // Set default configuration first
    mxd_set_default_config(config);
    
    // If no config file specified, try default locations
    const char* config_paths[3] = {NULL, NULL, NULL};
    int path_count = 0;
    
    if (config_file != NULL) {
        // User-specified config file
        config_paths[path_count++] = config_file;
    } else {
        config_paths[path_count++] = "default_config.json";  // Same directory as executable
        config_paths[path_count++] = "config/default_node.json";  // Config subdirectory
    }
    
    FILE* fp = NULL;
    const char* loaded_path = NULL;
    for (int i = 0; i < path_count; i++) {
        if (config_paths[i] == NULL) continue;
        
        fp = fopen(config_paths[i], "r");
        if (fp) {
            loaded_path = config_paths[i];
            MXD_LOG_INFO("config", "Loading configuration from: %s", loaded_path);
            break;
        } else {
            MXD_LOG_DEBUG("config", "Config file not found: %s", config_paths[i]);
        }
    }
    
    // If no config file found, use defaults
    if (!fp) {
        MXD_LOG_INFO("config", "No config file found, using default configuration");
        if (mxd_fetch_bootstrap_nodes(config) != 0) {
            MXD_LOG_WARN("config", "Failed to fetch bootstrap nodes from network API with defaults");
        } else {
            MXD_LOG_INFO("config", "Successfully fetched %d bootstrap nodes from network API (%s)", 
                         config->bootstrap_count, config->network_type);
        }
        return mxd_validate_config(config);
    }
    
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char* file_contents = malloc(fsize + 1);
    if (!file_contents) {
        fclose(fp);
        MXD_LOG_ERROR("config", "Failed to allocate memory for config file");
        return -1;
    }
    
    size_t read_size = fread(file_contents, 1, fsize, fp);
    file_contents[read_size] = '\0';
    fclose(fp);
    
    cJSON* root = cJSON_Parse(file_contents);
    free(file_contents);
    
    if (!root) {
        MXD_LOG_WARN("config", "Failed to parse config file as JSON, using defaults");
        return mxd_validate_config(config);
    }
    
    cJSON* item;
    
    if ((item = cJSON_GetObjectItem(root, "node_id")) && cJSON_IsString(item)) {
        strncpy(config->node_id, item->valuestring, sizeof(config->node_id) - 1);
    }
    if ((item = cJSON_GetObjectItem(root, "data_dir")) && cJSON_IsString(item)) {
        strncpy(config->data_dir, item->valuestring, sizeof(config->data_dir) - 1);
    }
    if ((item = cJSON_GetObjectItem(root, "port")) && cJSON_IsNumber(item)) {
        config->port = (uint16_t)item->valueint;
    }
    if ((item = cJSON_GetObjectItem(root, "node_name")) && cJSON_IsString(item)) {
        strncpy(config->node_name, item->valuestring, sizeof(config->node_name) - 1);
    }
    if ((item = cJSON_GetObjectItem(root, "node_data")) && cJSON_IsString(item)) {
        strncpy(config->node_data, item->valuestring, sizeof(config->node_data) - 1);
    }
    if ((item = cJSON_GetObjectItem(root, "initial_stake")) && cJSON_IsNumber(item)) {
        config->initial_stake = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "network_type")) && cJSON_IsString(item)) {
        strncpy(config->network_type, item->valuestring, sizeof(config->network_type) - 1);
    }
    
    cJSON* metrics = cJSON_GetObjectItem(root, "metrics");
    if (metrics && cJSON_IsObject(metrics)) {
        if ((item = cJSON_GetObjectItem(metrics, "update_interval")) && cJSON_IsNumber(item)) {
            config->metrics_interval = (uint32_t)item->valueint;
        }
    }
    
    // Try to get metrics_port from root first, then from metrics object
    if ((item = cJSON_GetObjectItem(root, "metrics_port")) && cJSON_IsNumber(item)) {
        config->metrics_port = (uint16_t)item->valueint;
    } else if (metrics && (item = cJSON_GetObjectItem(metrics, "port")) && cJSON_IsNumber(item)) {
        config->metrics_port = (uint16_t)item->valueint;
    }
    
    // Parse bootstrap_nodes array
    cJSON* bootstrap_nodes = cJSON_GetObjectItem(root, "bootstrap_nodes");
    if (bootstrap_nodes && cJSON_IsArray(bootstrap_nodes)) {
        config->bootstrap_count = 0;
        cJSON* node;
        cJSON_ArrayForEach(node, bootstrap_nodes) {
            if (cJSON_IsString(node) && config->bootstrap_count < 10) {
                strncpy(config->bootstrap_nodes[config->bootstrap_count], 
                       node->valuestring, sizeof(config->bootstrap_nodes[0]) - 1);
                config->bootstrap_count++;
            }
        }
    }
    
    if ((item = cJSON_GetObjectItem(root, "enable_upnp")) && cJSON_IsBool(item)) {
        config->enable_upnp = cJSON_IsTrue(item);
    }
    
    if ((item = cJSON_GetObjectItem(root, "preferred_sign_algo")) && cJSON_IsNumber(item)) {
        uint8_t algo = (uint8_t)item->valueint;
        if (algo == 1 || algo == 2) {
            config->preferred_sign_algo = algo;
        }
    }
    
    // Parse HTTP security configuration
    cJSON* http = cJSON_GetObjectItem(root, "http");
    if (http && cJSON_IsObject(http)) {
        if ((item = cJSON_GetObjectItem(http, "bind_address")) && cJSON_IsString(item)) {
            strncpy(config->http.bind_address, item->valuestring, sizeof(config->http.bind_address) - 1);
        }
        if ((item = cJSON_GetObjectItem(http, "port")) && cJSON_IsNumber(item)) {
            config->http.port = (uint16_t)item->valueint;
        }
        if ((item = cJSON_GetObjectItem(http, "require_auth")) && cJSON_IsBool(item)) {
            config->http.require_auth = cJSON_IsTrue(item);
        }
        if ((item = cJSON_GetObjectItem(http, "api_token")) && cJSON_IsString(item)) {
            strncpy(config->http.api_token, item->valuestring, sizeof(config->http.api_token) - 1);
        }
        if ((item = cJSON_GetObjectItem(http, "wallet_enabled")) && cJSON_IsBool(item)) {
            config->http.wallet_enabled = cJSON_IsTrue(item);
        }
        if ((item = cJSON_GetObjectItem(http, "rate_limit_per_minute")) && cJSON_IsNumber(item)) {
            config->http.rate_limit_per_minute = (uint32_t)item->valueint;
        }
        if ((item = cJSON_GetObjectItem(http, "timeout_seconds")) && cJSON_IsNumber(item)) {
            config->http.timeout_seconds = (uint32_t)item->valueint;
        }
    }
    
    // Parse bootstrap security configuration
    cJSON* bootstrap = cJSON_GetObjectItem(root, "bootstrap");
    if (bootstrap && cJSON_IsObject(bootstrap)) {
        if ((item = cJSON_GetObjectItem(bootstrap, "endpoint")) && cJSON_IsString(item)) {
            strncpy(config->bootstrap.endpoint, item->valuestring, sizeof(config->bootstrap.endpoint) - 1);
        }
        if ((item = cJSON_GetObjectItem(bootstrap, "verify_tls")) && cJSON_IsBool(item)) {
            config->bootstrap.verify_tls = cJSON_IsTrue(item);
        }
        if ((item = cJSON_GetObjectItem(bootstrap, "min_subnet_diversity")) && cJSON_IsNumber(item)) {
            config->bootstrap.min_subnet_diversity = (uint32_t)item->valueint;
        }
        
        cJSON* fallback_nodes = cJSON_GetObjectItem(bootstrap, "fallback_nodes");
        if (fallback_nodes && cJSON_IsArray(fallback_nodes)) {
            config->bootstrap.fallback_count = 0;
            cJSON* node;
            cJSON_ArrayForEach(node, fallback_nodes) {
                if (cJSON_IsString(node) && config->bootstrap.fallback_count < 10) {
                    strncpy(config->bootstrap.fallback_nodes[config->bootstrap.fallback_count],
                           node->valuestring, sizeof(config->bootstrap.fallback_nodes[0]) - 1);
                    config->bootstrap.fallback_count++;
                }
            }
        }
    }
    
    // Parse mempool security configuration
    cJSON* mempool = cJSON_GetObjectItem(root, "mempool");
    if (mempool && cJSON_IsObject(mempool)) {
        if ((item = cJSON_GetObjectItem(mempool, "max_size")) && cJSON_IsNumber(item)) {
            config->mempool.max_size = (uint32_t)item->valueint;
        }
        if ((item = cJSON_GetObjectItem(mempool, "max_tx_per_peer")) && cJSON_IsNumber(item)) {
            config->mempool.max_tx_per_peer = (uint32_t)item->valueint;
        }
        if ((item = cJSON_GetObjectItem(mempool, "max_bytes_per_peer")) && cJSON_IsNumber(item)) {
            config->mempool.max_bytes_per_peer = (uint64_t)item->valuedouble;
        }
        if ((item = cJSON_GetObjectItem(mempool, "min_fee_per_byte")) && cJSON_IsNumber(item)) {
            config->mempool.min_fee_per_byte = (uint32_t)item->valueint;
        }
        if ((item = cJSON_GetObjectItem(mempool, "max_tx_per_sec_per_peer")) && cJSON_IsNumber(item)) {
            config->mempool.max_tx_per_sec_per_peer = (uint32_t)item->valueint;
        }
    }
    
    // Parse smart contract security configuration
    cJSON* contracts = cJSON_GetObjectItem(root, "contracts");
    if (contracts && cJSON_IsObject(contracts)) {
        if ((item = cJSON_GetObjectItem(contracts, "gas_limit_default")) && cJSON_IsNumber(item)) {
            config->contracts.gas_limit_default = (uint64_t)item->valuedouble;
        }
        if ((item = cJSON_GetObjectItem(contracts, "timeout_seconds")) && cJSON_IsNumber(item)) {
            config->contracts.timeout_seconds = (uint32_t)item->valueint;
        }
        if ((item = cJSON_GetObjectItem(contracts, "metering_enabled")) && cJSON_IsBool(item)) {
            config->contracts.metering_enabled = cJSON_IsTrue(item);
        }
        if ((item = cJSON_GetObjectItem(contracts, "max_memory_pages")) && cJSON_IsNumber(item)) {
            config->contracts.max_memory_pages = (uint32_t)item->valueint;
        }
    }
    
    // Parse consensus security configuration
    cJSON* consensus = cJSON_GetObjectItem(root, "consensus");
    if (consensus && cJSON_IsObject(consensus)) {
        if ((item = cJSON_GetObjectItem(consensus, "blacklist_duration_blocks")) && cJSON_IsNumber(item)) {
            config->consensus.blacklist_duration_blocks = (uint32_t)item->valueint;
        }
        if ((item = cJSON_GetObjectItem(consensus, "min_unique_validators")) && cJSON_IsNumber(item)) {
            config->consensus.min_unique_validators = (uint32_t)item->valueint;
        }
        if ((item = cJSON_GetObjectItem(consensus, "signature_cache_size")) && cJSON_IsNumber(item)) {
            config->consensus.signature_cache_size = (uint32_t)item->valueint;
        }
    }
    
    // Parse P2P security configuration
    cJSON* p2p_security = cJSON_GetObjectItem(root, "p2p_security");
    if (p2p_security && cJSON_IsObject(p2p_security)) {
        if ((item = cJSON_GetObjectItem(p2p_security, "challenge_cache_size")) && cJSON_IsNumber(item)) {
            config->p2p_security.challenge_cache_size = (uint32_t)item->valueint;
        }
        if ((item = cJSON_GetObjectItem(p2p_security, "challenge_ttl_seconds")) && cJSON_IsNumber(item)) {
            config->p2p_security.challenge_ttl_seconds = (uint32_t)item->valueint;
        }
        if ((item = cJSON_GetObjectItem(p2p_security, "session_timeout_seconds")) && cJSON_IsNumber(item)) {
            config->p2p_security.session_timeout_seconds = (uint32_t)item->valueint;
        }
        if ((item = cJSON_GetObjectItem(p2p_security, "timestamp_tolerance_seconds")) && cJSON_IsNumber(item)) {
            config->p2p_security.timestamp_tolerance_seconds = (uint32_t)item->valueint;
        }
    }
    
    const char* env_api_token = getenv("MXD_API_TOKEN");
    if (env_api_token) {
        strncpy(config->http.api_token, env_api_token, sizeof(config->http.api_token) - 1);
        MXD_LOG_INFO("config", "API token loaded from environment variable");
    }
    
    const char* env_bind_address = getenv("MXD_BIND_ADDRESS");
    if (env_bind_address) {
        strncpy(config->http.bind_address, env_bind_address, sizeof(config->http.bind_address) - 1);
        MXD_LOG_INFO("config", "HTTP bind address overridden from environment: %s", env_bind_address);
    }
    
    cJSON_Delete(root);
    
    // Validate final configuration
    if (mxd_validate_config(config) != 0) {
        MXD_LOG_WARN("config", "Invalid configuration values, using defaults");
        mxd_set_default_config(config);
        return mxd_validate_config(config);
    }
    
    const char* env_metrics_port = getenv("MXD_METRICS_PORT");
    if (env_metrics_port) {
        int port = atoi(env_metrics_port);
        if (port >= 1024 && port <= 65535) {
            config->metrics_port = (uint16_t)port;
            MXD_LOG_INFO("config", "Metrics port overridden from environment: %d", port);
        }
    }
    
    MXD_LOG_INFO("config", "Loaded config: node_id=%s, port=%d, metrics_port=%d, data_dir=%s, node_name=%s",
           config->node_id, config->port, config->metrics_port, config->data_dir, config->node_name);
    
    if (mxd_fetch_bootstrap_nodes(config) != 0) {
        MXD_LOG_WARN("config", "Failed to fetch bootstrap nodes from network API, will use existing/default nodes and retry later");
    } else {
        MXD_LOG_INFO("config", "Successfully fetched %d bootstrap nodes from network API (%s)", 
                     config->bootstrap_count, config->network_type);
    }
    
    return 0;
}

int mxd_fetch_bootstrap_nodes(mxd_config_t* config) {
    if (!config) return -1;
    
    const char* endpoint = strcmp(config->network_type, "testnet") == 0 
        ? "https://mxd.network/bootstrap/test"
        : "https://mxd.network/bootstrap/main";
    
    MXD_LOG_INFO("config", "Fetching bootstrap nodes from %s", endpoint);

    mxd_http_response_t* response = mxd_http_get(endpoint);
    if (!response || response->status_code != 200) {
        MXD_LOG_ERROR("config", "Failed to fetch bootstrap nodes from %s (status: %d)", 
                      endpoint, response ? response->status_code : 0);
        mxd_http_free_response(response);
        return -1;
    }
    
    cJSON* root = cJSON_Parse(response->data);
    if (!root) {
        MXD_LOG_ERROR("config", "Failed to parse bootstrap nodes JSON response from %s", endpoint);
        mxd_http_free_response(response);
        return -1;
    }
    
    cJSON* nodes = cJSON_GetObjectItem(root, "bootstrap_nodes");
    if (!nodes || !cJSON_IsArray(nodes)) {
        MXD_LOG_ERROR("config", "Invalid bootstrap nodes format in response from %s", endpoint);
        cJSON_Delete(root);
        mxd_http_free_response(response);
        return -1;
    }
    
    // Start with fresh node list
    config->bootstrap_count = 0;
    
    cJSON* node;
    cJSON_ArrayForEach(node, nodes) {
        if (!cJSON_IsObject(node)) continue;
        
        cJSON* ip = cJSON_GetObjectItem(node, "ip");
        cJSON* hostname = cJSON_GetObjectItem(node, "hostname");
        cJSON* port = cJSON_GetObjectItem(node, "port");
        
        const char* address = NULL;
        if (ip && cJSON_IsString(ip)) {
            address = ip->valuestring;
        } else if (hostname && cJSON_IsString(hostname)) {
            address = hostname->valuestring;
        }
        
        int port_num = 0;
        if (port) {
            if (cJSON_IsNumber(port)) {
                port_num = port->valueint;
            } else if (cJSON_IsString(port)) {
                port_num = atoi(port->valuestring);
            }
        }
        
        if (address && port_num > 0) {
            const char* public_ip = getenv("MXD_PUBLIC_IP");
            if (public_ip && strcmp(address, public_ip) == 0 && port_num == config->port) {
                MXD_LOG_DEBUG("config", "Skipping bootstrap node %s:%d (matches our public IP and port)", 
                            address, port_num);
                continue;
            }
            
            snprintf(config->bootstrap_nodes[config->bootstrap_count],
                    sizeof(config->bootstrap_nodes[0]),
                    "%s:%d",
                    address,
                    port_num);
            
            mxd_bootstrap_node_t* node_v2 = &config->bootstrap_nodes_v2[config->bootstrap_count];
            memset(node_v2, 0, sizeof(mxd_bootstrap_node_t));
            
            snprintf(node_v2->address, sizeof(node_v2->address), "%s", address);
            node_v2->port = (uint16_t)port_num;
            
            cJSON* algo_id_json = cJSON_GetObjectItem(node, "algo_id");
            cJSON* public_key_json = cJSON_GetObjectItem(node, "public_key");
            cJSON* address20_json = cJSON_GetObjectItem(node, "address");
            
            if (algo_id_json && cJSON_IsNumber(algo_id_json)) {
                node_v2->algo_id = (uint8_t)algo_id_json->valueint;
                
                // Validate algo_id
                if (node_v2->algo_id != 1 && node_v2->algo_id != 2) {
                    MXD_LOG_WARN("config", "Bootstrap node %s:%d has invalid algo_id %u, ignoring crypto metadata",
                                address, port_num, node_v2->algo_id);
                    node_v2->algo_id = 0;
                    node_v2->has_crypto_info = 0;
                } else if (public_key_json && cJSON_IsString(public_key_json)) {
                    const char* pubkey_b64 = public_key_json->valuestring;
                    size_t decoded_len = 0;
                    
                    MXD_LOG_INFO("config", "Bootstrap node %s:%d has algo_id=%u and public_key (crypto metadata available)",
                                address, port_num, node_v2->algo_id);
                    node_v2->has_crypto_info = 1;
                    
                    if (address20_json && cJSON_IsString(address20_json)) {
                        MXD_LOG_DEBUG("config", "Bootstrap node %s:%d has address20 for validation",
                                    address, port_num);
                    }
                } else {
                    MXD_LOG_DEBUG("config", "Bootstrap node %s:%d has algo_id but no public_key",
                                address, port_num);
                    node_v2->has_crypto_info = 0;
                }
            } else {
                node_v2->algo_id = 0;
                node_v2->has_crypto_info = 0;
                MXD_LOG_DEBUG("config", "Bootstrap node %s:%d has no crypto metadata (will authenticate via P2P handshake)",
                            address, port_num);
            }
            
            config->bootstrap_count++;
            MXD_LOG_INFO("config", "Added bootstrap node %s:%d%s", address, port_num,
                        node_v2->has_crypto_info ? " (with crypto metadata)" : "");
            if (config->bootstrap_count >= 10) break;
        }
    }
    
    // If no valid nodes found, return error
    if (config->bootstrap_count == 0) {
        MXD_LOG_ERROR("config", "No valid bootstrap nodes found in API response from %s", endpoint);
        cJSON_Delete(root);
        mxd_http_free_response(response);
        return -1;
    }
    
    cJSON* network_info = cJSON_GetObjectItem(root, "network_info");
    if (network_info && cJSON_IsObject(network_info)) {
        cJSON* update_interval = cJSON_GetObjectItem(network_info, "update_interval");
        if (update_interval && cJSON_IsNumber(update_interval)) {
            config->bootstrap_refresh_interval = update_interval->valueint;
            MXD_LOG_INFO("config", "Bootstrap refresh interval: %d seconds", config->bootstrap_refresh_interval);
        }
    }
    
    if (config->bootstrap_refresh_interval == 0) {
        config->bootstrap_refresh_interval = 300;
    }
    
    MXD_LOG_INFO("config", "Loaded %d bootstrap nodes from network", config->bootstrap_count);
    
    cJSON_Delete(root);
    mxd_http_free_response(response);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "mxd_config.h"

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

int mxd_load_config(const char* config_file, mxd_config_t* config) {
    FILE* fp = fopen(config_file, "r");
    if (!fp) {
        printf("Failed to open config file: %s\n", config_file);
        return 1;
    }
    
    // Initialize config with defaults
    memset(config, 0, sizeof(mxd_config_t));
    config->port = 8000;           // Default port
    config->initial_stake = 0.0;   // No default stake - must be set in config
    config->metrics_interval = 1000;// Default refresh interval (1s)
    strncpy(config->network_type, "testnet", sizeof(config->network_type) - 1);
    strncpy(config->node_name, "unnamed_node", sizeof(config->node_name) - 1);
    strncpy(config->node_data, "", sizeof(config->node_data) - 1);
    strncpy(config->data_dir, "data", sizeof(config->data_dir) - 1);
    
    char line[1024];
    char key[256], value[768];
    
    while (fgets(line, sizeof(line), fp)) {
        char* trimmed = trim(line);
        if (strlen(trimmed) == 0 || trimmed[0] == '{' || trimmed[0] == '}' || trimmed[0] == ',') {
            continue;
        }
        
        if (sscanf(trimmed, "\"%[^\"]\" : \"%[^\"]\"", key, value) == 2 ||
            sscanf(trimmed, "\"%[^\"]\":%[^,\n]", key, value) == 2) {
            
            char* trimmed_value = trim(value);
            trimmed_value = strip_quotes(trimmed_value);
            
            if (strcmp(key, "node_id") == 0) {
                strncpy(config->node_id, trimmed_value, sizeof(config->node_id) - 1);
            } else if (strcmp(key, "data_dir") == 0) {
                strncpy(config->data_dir, trimmed_value, sizeof(config->data_dir) - 1);
            } else if (strcmp(key, "port") == 0) {
                config->port = (uint16_t)atoi(trimmed_value);
            } else if (strcmp(key, "node_name") == 0) {
                strncpy(config->node_name, trimmed_value, sizeof(config->node_name) - 1);
            } else if (strcmp(key, "node_data") == 0) {
                strncpy(config->node_data, trimmed_value, sizeof(config->node_data) - 1);
            } else if (strcmp(key, "initial_stake") == 0) {
                config->initial_stake = atof(trimmed_value);
            } else if (strcmp(key, "network_type") == 0) {
                strncpy(config->network_type, trimmed_value, sizeof(config->network_type) - 1);
            } else if (strcmp(key, "metrics_interval") == 0) {
                config->metrics_interval = (uint32_t)atoi(trimmed_value);
            } else if (strcmp(key, "bootstrap_nodes") == 0) {
                // Parse bootstrap nodes array
                char* node = strtok(trimmed_value, "[], ");
                config->bootstrap_count = 0;
                while (node != NULL && config->bootstrap_count < 10) {
                    // Remove quotes if present
                    if (node[0] == '"') {
                        node++;
                        node[strlen(node)-1] = '\0';
                    }
                    strncpy(config->bootstrap_nodes[config->bootstrap_count], 
                           node, sizeof(config->bootstrap_nodes[0]) - 1);
                    config->bootstrap_count++;
                    node = strtok(NULL, "[], ");
                }
            }
        }
    }
    
    fclose(fp);
    
    printf("Loaded config: node_id=%s, port=%d, data_dir=%s, node_name=%s\n",
           config->node_id, config->port, config->data_dir, config->node_name);
    return 0;
}

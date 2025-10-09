#include "../include/mxd_logging.h"
#include "../include/mxd_config.h"
#include <time.h>
#include <string.h>
#include <stdio.h>
#include "metrics_display.h"

void clear_console(void) {
    MXD_LOG_DEBUG("metrics_display", "Clear console");
}

void display_node_metrics(const mxd_node_metrics_t* metrics, const mxd_node_stake_t* stake,
                         const mxd_config_t* config, const mxd_rapid_table_t* rapid_table,
                         uint32_t blockchain_height, const uint8_t* latest_block_hash) {
    if (!metrics || !stake) {
        MXD_LOG_ERROR("metrics_display", "Invalid metrics or stake data");
        return;
    }

    clear_console();
    
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S UTC", gmtime(&now));
    
    double tps = metrics->message_success;
    
    int is_active = metrics->reliability_score > 0.95 && tps >= 10.0;
    
    const char* network_type = config ? config->network_type : "unknown";
    int is_testnet = (config && strcmp(config->network_type, "testnet") == 0);
    
    MXD_LOG_INFO("metrics_display", "╔════════════════════════════════════════════════════════════════╗");
    if (is_testnet) {
        MXD_LOG_INFO("metrics_display", "║              MXD NODE - TESTNET MODE                          ║");
    } else {
        MXD_LOG_INFO("metrics_display", "║              MXD NODE - MAINNET MODE                          ║");
    }
    MXD_LOG_INFO("metrics_display", "╚════════════════════════════════════════════════════════════════╝");
    MXD_LOG_INFO("metrics_display", "Time: %s", time_str);
    MXD_LOG_INFO("metrics_display", "");
    
    MXD_LOG_INFO("metrics_display", "━━━ Blockchain State ━━━");
    MXD_LOG_INFO("metrics_display", "Height: %u", blockchain_height);
    if (latest_block_hash) {
        char hash_str[32];
        snprintf(hash_str, sizeof(hash_str), "%02x%02x%02x%02x...%02x%02x%02x%02x",
                latest_block_hash[0], latest_block_hash[1], latest_block_hash[2], latest_block_hash[3],
                latest_block_hash[60], latest_block_hash[61], latest_block_hash[62], latest_block_hash[63]);
        MXD_LOG_INFO("metrics_display", "Latest Block: %s", hash_str);
    } else {
        MXD_LOG_INFO("metrics_display", "Latest Block: (genesis)");
    }
    MXD_LOG_INFO("metrics_display", "");
    
    MXD_LOG_INFO("metrics_display", "━━━ Node Information ━━━");
    MXD_LOG_INFO("metrics_display", "Node ID: %s", stake->node_id);
    MXD_LOG_INFO("metrics_display", "Stake: %.2f MXD", stake->stake_amount);
    MXD_LOG_INFO("metrics_display", "Rank: %d", stake->rank);
    MXD_LOG_INFO("metrics_display", "Status: %s", is_active ? "✓ Active" : "✗ Inactive");
    MXD_LOG_INFO("metrics_display", "Connected Peers: %zu", metrics->peer_count);
    MXD_LOG_INFO("metrics_display", "");
    
    MXD_LOG_INFO("metrics_display", "━━━ Performance Metrics ━━━");
    MXD_LOG_INFO("metrics_display", "TPS: %.2f (target: ≥10.0)", tps);
    MXD_LOG_INFO("metrics_display", "Response Time: %lu ms (min: %lu, max: %lu)",
           metrics->avg_response_time, metrics->min_response_time, metrics->max_response_time);
    MXD_LOG_INFO("metrics_display", "Reliability: %.2f%%", metrics->reliability_score * 100.0);
    MXD_LOG_INFO("metrics_display", "Performance Score: %.2f", metrics->performance_score);
    MXD_LOG_INFO("metrics_display", "Messages: %u success / %u total", 
           metrics->message_success, metrics->message_total);
    MXD_LOG_INFO("metrics_display", "Earnings (Tips): %.6f MXD", metrics->tip_share);
    MXD_LOG_INFO("metrics_display", "");
    
    if (rapid_table && rapid_table->nodes && rapid_table->count > 0) {
        MXD_LOG_INFO("metrics_display", "━━━ Rapid Stake Table (Top Validators) ━━━");
        MXD_LOG_INFO("metrics_display", "┌────┬──────────────────┬───────────┬──────┬────────┐");
        MXD_LOG_INFO("metrics_display", "│Rank│ Node ID          │ Stake     │Active│ Score  │");
        MXD_LOG_INFO("metrics_display", "├────┼──────────────────┼───────────┼──────┼────────┤");
        
        size_t display_count = rapid_table->count > 10 ? 10 : rapid_table->count;
        for (size_t i = 0; i < display_count; i++) {
            mxd_node_stake_t* node = rapid_table->nodes[i];
            if (node) {
                char node_id_short[17];
                snprintf(node_id_short, sizeof(node_id_short), "%.16s", node->node_id);
                
                MXD_LOG_INFO("metrics_display", "│%4d│%-18s│%10.2f│  %s   │ %6.2f │",
                       node->rank, node_id_short, node->stake_amount,
                       node->active ? "✓" : "✗", node->metrics.performance_score);
            }
        }
        
        MXD_LOG_INFO("metrics_display", "└────┴──────────────────┴───────────┴──────┴────────┘");
        MXD_LOG_INFO("metrics_display", "Total Validators: %zu", rapid_table->count);
    } else {
        MXD_LOG_INFO("metrics_display", "━━━ Rapid Stake Table ━━━");
        MXD_LOG_INFO("metrics_display", "No validators in rapid table");
    }
    MXD_LOG_INFO("metrics_display", "");
    
    MXD_LOG_INFO("metrics_display", "━━━ Health Indicators ━━━");
    MXD_LOG_INFO("metrics_display", "Response Time: %s", 
           metrics->avg_response_time < 3000 ? "✓ Good" : "✗ High");
    MXD_LOG_INFO("metrics_display", "Transaction Rate: %s", 
           tps >= 10.0 ? "✓ Good" : "✗ Low");
    MXD_LOG_INFO("metrics_display", "Network: %s",
           stake->active ? "✓ Connected" : "✗ Disconnected");
    MXD_LOG_INFO("metrics_display", "");
    MXD_LOG_INFO("metrics_display", "Press Ctrl+C to exit");
}

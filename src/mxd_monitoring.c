#include "../include/mxd_monitoring.h"
#include "../include/mxd_logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>

static mxd_system_metrics_t current_metrics = {0};
static mxd_health_status_t current_health = {0};
static int monitoring_initialized = 0;
static uint16_t metrics_port = 0;
static char prometheus_buffer[4096];
static char health_buffer[1024];
static int server_socket = -1;
static pthread_t server_thread;
static volatile int server_running = 0;

int mxd_init_monitoring(uint16_t http_port) {
    if (monitoring_initialized) {
        return 0;
    }
    
    metrics_port = http_port;
    memset(&current_metrics, 0, sizeof(current_metrics));
    memset(&current_health, 0, sizeof(current_health));
    
    current_health.is_healthy = 1;
    current_health.database_connected = 1;
    current_health.p2p_active = 1;
    current_health.consensus_active = 1;
    strcpy(current_health.status_message, "System operational");
    current_health.last_check_timestamp = time(NULL);
    
    monitoring_initialized = 1;
    MXD_LOG_INFO("monitoring", "Monitoring system initialized on port %d", http_port);
    return 0;
}

void mxd_cleanup_monitoring(void) {
    if (monitoring_initialized) {
        monitoring_initialized = 0;
        MXD_LOG_INFO("monitoring", "Monitoring system cleaned up");
    }
}

int mxd_update_system_metrics(const mxd_system_metrics_t *metrics) {
    if (!monitoring_initialized || !metrics) {
        return -1;
    }
    
    current_metrics = *metrics;
    MXD_LOG_DEBUG("monitoring", "System metrics updated - TPS: %.2f, Peers: %d", 
                  metrics->current_tps, metrics->active_peers);
    return 0;
}

int mxd_get_health_status(mxd_health_status_t *status) {
    if (!monitoring_initialized || !status) {
        return -1;
    }
    
    current_health.last_check_timestamp = time(NULL);
    
    current_health.is_healthy = current_health.database_connected && 
                               current_health.p2p_active && 
                               current_health.consensus_active;
    
    *status = current_health;
    return 0;
}

const char* mxd_get_prometheus_metrics(void) {
    if (!monitoring_initialized) {
        return NULL;
    }
    
    snprintf(prometheus_buffer, sizeof(prometheus_buffer),
        "# HELP mxd_transactions_total Total number of transactions processed\n"
        "# TYPE mxd_transactions_total counter\n"
        "mxd_transactions_total %lu\n"
        "\n"
        "# HELP mxd_blocks_total Total number of blocks processed\n"
        "# TYPE mxd_blocks_total counter\n"
        "mxd_blocks_total %lu\n"
        "\n"
        "# HELP mxd_tps_current Current transactions per second\n"
        "# TYPE mxd_tps_current gauge\n"
        "mxd_tps_current %.2f\n"
        "\n"
        "# HELP mxd_network_latency_ms Network latency in milliseconds\n"
        "# TYPE mxd_network_latency_ms gauge\n"
        "mxd_network_latency_ms %lu\n"
        "\n"
        "# HELP mxd_peers_active Number of active peers\n"
        "# TYPE mxd_peers_active gauge\n"
        "mxd_peers_active %u\n"
        "\n"
        "# HELP mxd_blockchain_height Current blockchain height\n"
        "# TYPE mxd_blockchain_height gauge\n"
        "mxd_blockchain_height %lu\n"
        "\n"
        "# HELP mxd_consensus_efficiency Consensus efficiency percentage\n"
        "# TYPE mxd_consensus_efficiency gauge\n"
        "mxd_consensus_efficiency %.2f\n"
        "\n"
        "# HELP mxd_memory_usage_bytes Memory usage in bytes\n"
        "# TYPE mxd_memory_usage_bytes gauge\n"
        "mxd_memory_usage_bytes %lu\n"
        "\n"
        "# HELP mxd_disk_usage_bytes Disk usage in bytes\n"
        "# TYPE mxd_disk_usage_bytes gauge\n"
        "mxd_disk_usage_bytes %lu\n"
        "\n"
        "# HELP mxd_cpu_usage_percent CPU usage percentage\n"
        "# TYPE mxd_cpu_usage_percent gauge\n"
        "mxd_cpu_usage_percent %.2f\n",
        current_metrics.total_transactions,
        current_metrics.total_blocks,
        current_metrics.current_tps,
        current_metrics.network_latency_ms,
        current_metrics.active_peers,
        current_metrics.blockchain_height,
        current_metrics.consensus_efficiency,
        current_metrics.memory_usage_bytes,
        current_metrics.disk_usage_bytes,
        current_metrics.cpu_usage_percent
    );
    
    return prometheus_buffer;
}

const char* mxd_get_health_json(void) {
    if (!monitoring_initialized) {
        return NULL;
    }
    
    snprintf(health_buffer, sizeof(health_buffer),
        "{"
        "\"status\":\"%s\","
        "\"timestamp\":%lu,"
        "\"checks\":{"
        "\"database\":%s,"
        "\"p2p\":%s,"
        "\"consensus\":%s"
        "},"
        "\"message\":\"%s\""
        "}",
        current_health.is_healthy ? "healthy" : "unhealthy",
        current_health.last_check_timestamp,
        current_health.database_connected ? "true" : "false",
        current_health.p2p_active ? "true" : "false",
        current_health.consensus_active ? "true" : "false",
        current_health.status_message
    );
    
    return health_buffer;
}

static void handle_http_request(int client_socket) {
    char buffer[1024];
    ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        close(client_socket);
        return;
    }
    
    buffer[bytes_read] = '\0';
    
    char method[16], path[256], version[16];
    if (sscanf(buffer, "%15s %255s %15s", method, path, version) != 3) {
        close(client_socket);
        return;
    }
    
    const char* response_body = NULL;
    const char* content_type = "text/plain";
    int status_code = 404;
    
    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/health") == 0) {
            response_body = mxd_get_health_json();
            content_type = "application/json";
            status_code = 200;
        } else if (strcmp(path, "/metrics") == 0) {
            response_body = mxd_get_prometheus_metrics();
            content_type = "text/plain";
            status_code = 200;
        }
    }
    
    if (!response_body) {
        response_body = "Not Found";
        status_code = 404;
    }
    
    char response[4096];
    int response_len = snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        status_code,
        status_code == 200 ? "OK" : "Not Found",
        content_type,
        strlen(response_body),
        response_body);
    
    send(client_socket, response, response_len, 0);
    close(client_socket);
}

static void* server_thread_func(void* arg) {
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            if (server_running && errno != EINTR) {
                MXD_LOG_ERROR("monitoring", "Accept failed: %s", strerror(errno));
            }
            continue;
        }
        
        handle_http_request(client_socket);
    }
    return NULL;
}

int mxd_start_metrics_server(void) {
    if (!monitoring_initialized) {
        return -1;
    }
    
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        MXD_LOG_ERROR("monitoring", "Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        MXD_LOG_WARN("monitoring", "Failed to set SO_REUSEADDR: %s", strerror(errno));
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(metrics_port);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        MXD_LOG_ERROR("monitoring", "Failed to bind to port %d: %s", metrics_port, strerror(errno));
        close(server_socket);
        server_socket = -1;
        return -1;
    }
    
    if (listen(server_socket, 5) < 0) {
        MXD_LOG_ERROR("monitoring", "Failed to listen on socket: %s", strerror(errno));
        close(server_socket);
        server_socket = -1;
        return -1;
    }
    
    server_running = 1;
    if (pthread_create(&server_thread, NULL, server_thread_func, NULL) != 0) {
        MXD_LOG_ERROR("monitoring", "Failed to create server thread: %s", strerror(errno));
        close(server_socket);
        server_socket = -1;
        server_running = 0;
        return -1;
    }
    
    MXD_LOG_INFO("monitoring", "Metrics server started on port %d", metrics_port);
    MXD_LOG_INFO("monitoring", "Endpoints: /metrics (Prometheus), /health (JSON)");
    return 0;
}

int mxd_stop_metrics_server(void) {
    if (!monitoring_initialized || !server_running) {
        return -1;
    }
    
    server_running = 0;
    
    if (server_socket >= 0) {
        close(server_socket);
        server_socket = -1;
    }
    
    pthread_join(server_thread, NULL);
    
    MXD_LOG_INFO("monitoring", "Metrics server stopped");
    return 0;
}

#include "mxd_replay.h"
#include "../../include/mxd_logging.h"
#include "../../include/mxd_config.h"
#include "../metrics/mxd_prometheus.h"
#include <string.h>
#include <time.h>
#include <pthread.h>

static mxd_replay_entry_t replay_cache[MXD_REPLAY_CACHE_SIZE];
static size_t replay_cache_count = 0;
static pthread_mutex_t replay_mutex = PTHREAD_MUTEX_INITIALIZER;
static int replay_initialized = 0;

int mxd_replay_init(void) {
    pthread_mutex_lock(&replay_mutex);
    
    if (replay_initialized) {
        pthread_mutex_unlock(&replay_mutex);
        return 0;
    }
    
    memset(replay_cache, 0, sizeof(replay_cache));
    replay_cache_count = 0;
    replay_initialized = 1;
    
    pthread_mutex_unlock(&replay_mutex);
    
    MXD_LOG_INFO("replay", "Replay detection initialized (cache size: %d, TTL: %d seconds)", 
                 MXD_REPLAY_CACHE_SIZE, MXD_REPLAY_TTL_SECONDS);
    return 0;
}

void mxd_replay_cleanup(void) {
    pthread_mutex_lock(&replay_mutex);
    
    memset(replay_cache, 0, sizeof(replay_cache));
    replay_cache_count = 0;
    replay_initialized = 0;
    
    pthread_mutex_unlock(&replay_mutex);
    
    MXD_LOG_INFO("replay", "Replay detection cleaned up");
}

int mxd_replay_check(const uint8_t challenge[32], uint64_t timestamp) {
    if (!challenge) {
        return -1;
    }
    
    pthread_mutex_lock(&replay_mutex);
    
    if (!replay_initialized) {
        pthread_mutex_unlock(&replay_mutex);
        return -1;
    }
    
    uint64_t current_time = (uint64_t)time(NULL);
    mxd_config_t* config = mxd_get_config();
    uint32_t tolerance = 60;
    if (config && config->p2p_security.timestamp_tolerance_seconds > 0) {
        tolerance = config->p2p_security.timestamp_tolerance_seconds;
    }
    
    if (timestamp > current_time + tolerance || timestamp + tolerance < current_time) {
        pthread_mutex_unlock(&replay_mutex);
        MXD_LOG_WARN("replay", "Timestamp outside tolerance window: timestamp=%lu, current=%lu, tolerance=%u", 
                     timestamp, current_time, tolerance);
        mxd_metrics_increment("handshake_timestamp_rejected_total");
        return -1;
    }
    
    for (size_t i = 0; i < replay_cache_count; i++) {
        if (replay_cache[i].active && 
            memcmp(replay_cache[i].challenge, challenge, 32) == 0) {
            pthread_mutex_unlock(&replay_mutex);
            MXD_LOG_WARN("replay", "Replay attack detected: challenge already seen at timestamp %lu", 
                         replay_cache[i].timestamp);
            mxd_metrics_increment("handshake_replay_detected_total");
            return -1;
        }
    }
    
    pthread_mutex_unlock(&replay_mutex);
    return 0;
}

int mxd_replay_record(const uint8_t challenge[32], uint64_t timestamp) {
    if (!challenge) {
        return -1;
    }
    
    pthread_mutex_lock(&replay_mutex);
    
    if (!replay_initialized) {
        pthread_mutex_unlock(&replay_mutex);
        return -1;
    }
    
    int slot = -1;
    for (size_t i = 0; i < MXD_REPLAY_CACHE_SIZE; i++) {
        if (!replay_cache[i].active) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        uint64_t oldest_time = UINT64_MAX;
        for (size_t i = 0; i < MXD_REPLAY_CACHE_SIZE; i++) {
            if (replay_cache[i].seen_at < oldest_time) {
                oldest_time = replay_cache[i].seen_at;
                slot = i;
            }
        }
    }
    
    if (slot >= 0) {
        memcpy(replay_cache[slot].challenge, challenge, 32);
        replay_cache[slot].timestamp = timestamp;
        replay_cache[slot].seen_at = (uint64_t)time(NULL);
        replay_cache[slot].active = 1;
        
        if (slot >= (int)replay_cache_count) {
            replay_cache_count = slot + 1;
        }
    }
    
    pthread_mutex_unlock(&replay_mutex);
    return 0;
}

void mxd_replay_cleanup_expired(void) {
    pthread_mutex_lock(&replay_mutex);
    
    if (!replay_initialized) {
        pthread_mutex_unlock(&replay_mutex);
        return;
    }
    
    uint64_t current_time = (uint64_t)time(NULL);
    size_t cleaned = 0;
    
    for (size_t i = 0; i < replay_cache_count; i++) {
        if (replay_cache[i].active && 
            current_time - replay_cache[i].seen_at > MXD_REPLAY_TTL_SECONDS) {
            replay_cache[i].active = 0;
            cleaned++;
        }
    }
    
    pthread_mutex_unlock(&replay_mutex);
    
    if (cleaned > 0) {
        MXD_LOG_DEBUG("replay", "Cleaned %zu expired replay cache entries", cleaned);
    }
}

# MXD Library Production Readiness Documentation

**Document Version:** 1.0  
**Last Updated:** November 30, 2025  
**Based on Audit:** AUDIT_REPORT.md

## Overview

This document provides guidance for deploying the MXD blockchain library in production environments. It covers configuration recommendations, security considerations, monitoring requirements, and operational procedures.

## Readiness Assessment by Subsystem

### Production-Ready Components

| Component | Status | Notes |
|-----------|--------|-------|
| Cryptographic Primitives | Ready | SHA-512, RIPEMD-160, Argon2, Ed25519, Dilithium5 |
| Address Generation | Ready | Hybrid crypto with collision prevention |
| UTXO Management | Ready | RocksDB-backed, tested under load |
| Transaction Processing | Ready | 361 tx/s demonstrated |
| Mempool | Ready | Per-peer quotas, rate limiting |
| Basic Consensus (RSC) | Ready | Ranking, tip distribution verified |
| P2P Networking | Ready | With monitoring recommended |
| DHT Peer Discovery | Ready | K-bucket implementation tested |
| NTP Synchronization | Ready | Sub-100ms precision |
| Metrics System | Ready | Prometheus-compatible |

### Components Requiring Caution

| Component | Status | Recommendation |
|-----------|--------|----------------|
| Smart Contracts | Production-Ready | Recently upgraded with merkle patricia trie storage and bytecode gas metering; enable after testnet validation |
| Validation Chain Protocol | Ready (Test Maintenance Needed) | Implementation correct; network test has bug (wrong signature length) |
| HTTP Wallet API | Hardened | Use localhost binding + auth tokens |
| UPnP/NAT Traversal | Fragile | Use manual port forwarding |

## Configuration Recommendations

### Secure Production Configuration

Create a production configuration file based on `config/default_node.json` with the following security-focused settings:

```json
{
  "node_id": "unique-node-identifier",
  "port": 8000,
  "metrics_port": 8080,
  
  "http": {
    "enabled": true,
    "bind_address": "127.0.0.1",
    "wallet_enabled": false,
    "require_auth": true,
    "rate_limit_requests_per_minute": 60,
    "api_token": "GENERATE_STRONG_TOKEN_HERE"
  },
  
  "bootstrap": {
    "verify_tls": true,
    "min_subnet_diversity": 2,
    "use_fallback_nodes": true
  },
  
  "mempool": {
    "max_transactions": 10000,
    "max_bytes_per_peer": 10485760,
    "max_tx_per_peer": 100,
    "rate_limit_tx_per_second": 10,
    "min_fee_per_byte": 1
  },
  
  "contracts": {
    "enabled": false,
    "timeout_seconds": 5,
    "max_memory_bytes": 67108864
  },
  
  "consensus": {
    "blacklist_duration_blocks": 1000,
    "min_stake_percentage": 1
  },
  
  "p2p_security": {
    "timestamp_tolerance_seconds": 60,
    "replay_cache_size": 1000,
    "replay_cache_ttl_seconds": 300
  }
}
```

### Environment Variables

Set these environment variables for sensitive configuration:

```bash
export MXD_API_TOKEN="your-secure-api-token"
export MXD_BIND_ADDRESS="127.0.0.1"
export MXD_METRICS_PORT="8080"
export MXD_PUBLIC_IP="your.public.ip.address"
export MXD_ENABLE_PEER_CONNECTOR="1"
```

### Network Configuration

For production nodes behind NAT:

1. **Port Forwarding (Recommended)**
   - Forward external port 8000 to internal port 8000 (P2P)
   - Forward external port 8080 to internal port 8080 (Metrics/Health)

2. **Firewall Rules**
   ```bash
   # Allow P2P traffic
   ufw allow 8000/tcp
   
   # Allow metrics (restrict to monitoring systems)
   ufw allow from 10.0.0.0/8 to any port 8080
   ```

3. **UPnP (Not Recommended for Production)**
   - UPnP is fragile in virtualized environments
   - If used, monitor for discovery failures

## Security Checklist

### Pre-Deployment

- [ ] Generate unique, strong API tokens (minimum 32 characters)
- [ ] Configure TLS for any external-facing endpoints
- [ ] Verify bootstrap node connectivity
- [ ] Test wallet endpoints return 401 without valid token
- [ ] Verify rate limiting returns 429 after threshold
- [ ] Confirm contracts are disabled (if not needed)
- [ ] Set up log aggregation
- [ ] Configure metrics scraping

### Post-Deployment

- [ ] Monitor `mxd_http_auth_failures_total` for brute force attempts
- [ ] Monitor `mxd_double_sign_events_total` for Byzantine behavior
- [ ] Monitor `mxd_handshake_replay_detected_total` for replay attacks
- [ ] Monitor `mxd_mempool_evictions_total` for DoS attempts
- [ ] Set up alerts for consecutive network errors (threshold: 10)
- [ ] Verify transaction rate meets requirements (minimum 10 tx/s)
- [ ] Confirm P2P latency under 3 seconds

## Monitoring and Metrics

### Critical Metrics to Monitor

| Metric | Alert Threshold | Description |
|--------|-----------------|-------------|
| `mxd_http_auth_failures_total` | >10/minute | Potential brute force attack |
| `mxd_double_sign_events_total` | >0 | Byzantine validator detected |
| `mxd_handshake_replay_detected_total` | >5/minute | Replay attack attempt |
| `mxd_mempool_evictions_total` | >100/minute | Mempool pressure |
| `mxd_tls_verification_failures_total` | >0 | TLS/certificate issues |
| `mxd_contract_oom_or_oog_total` | >0 | Contract resource exhaustion |
| `mxd_tx_validation_rate` | <10/s | Performance degradation |
| `mxd_p2p_round_trip_seconds` | >3s | Network latency issues |

### Health Check Endpoint

The `/health` endpoint returns JSON with node status:

```json
{
  "status": "healthy",
  "blockchain_height": 12345,
  "peer_count": 8,
  "sync_status": "synced",
  "uptime_seconds": 86400
}
```

### Prometheus Scrape Configuration

```yaml
scrape_configs:
  - job_name: 'mxd_node'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

## Operational Procedures

### Starting a Node

```bash
# Using the letsgo script (recommended)
./letsgo mainnet

# Or directly
./build/bin/mxd_node --config config/production.json
```

### Graceful Shutdown

The node handles SIGINT and SIGTERM for graceful shutdown:

```bash
kill -SIGTERM $(pgrep mxd_node)
```

### Database Backup

RocksDB data should be backed up regularly:

```bash
# Stop the node first for consistent backup
systemctl stop mxd-node

# Backup the data directory
tar -czvf mxd_backup_$(date +%Y%m%d).tar.gz /var/lib/mxd/data

# Restart the node
systemctl start mxd-node
```

### Log Management

Logs are written with structured JSON format:

```bash
# View recent errors
journalctl -u mxd-node | grep '"level":"ERROR"' | tail -20

# Monitor in real-time
journalctl -u mxd-node -f
```

### Upgrading Nodes

For protocol upgrades (e.g., v2 to v3):

1. Announce upgrade window to network participants
2. Stop node gracefully
3. Backup database
4. Update binary
5. Update configuration if needed
6. Start node
7. Verify connectivity and sync status

**Note:** Protocol v3 nodes reject v2 connections. Coordinate upgrades across the network.

## Performance Requirements

### Minimum Hardware

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Storage | 50 GB SSD | 200+ GB NVMe |
| Network | 10 Mbps | 100+ Mbps |

### Performance Benchmarks

Based on audit testing:

| Metric | Achieved | Requirement |
|--------|----------|-------------|
| Transaction Rate | 361 tx/s | 10 tx/s minimum |
| P2P Connection Latency | 2 ms | <3000 ms |
| Peer Discovery Latency | 1 ms | <3000 ms |
| Metric Update Rate | 13.4M/s | N/A |
| Memory per 1000 nodes | 78 KB | N/A |

## Known Limitations

### Smart Contracts (Recently Upgraded)

The smart contract system has been significantly improved:

1. **Gas Metering:** Now uses `mxd_calculate_gas_from_bytecode()` for WASM instruction-level analysis, with wall-clock timeout (5 seconds) as additional protection.

2. **Storage:** Upgraded to Merkle Patricia Trie (`mxd_merkle_trie_t`) with O(log n) operations and cryptographic verification. State hash is automatically updated from trie root.

3. **Recommendation:** Enable contracts after thorough testnet validation. Consider additional fuzzing and stress testing.

### Validation Chain (Implementation Correct, Test Needs Fix)

The validation chain implementation is correct, but the network test has a bug:

1. Network mode tests (`--network` flag) fail due to **test bug**: test uses 128-byte signatures for Ed25519 (should be 64 bytes)
2. The implementation correctly validates and rejects invalid signature lengths
3. **Recommendation:** Fix test to use correct signature lengths, then run full network mode tests

### UPnP/NAT Traversal

UPnP discovery is fragile in virtualized environments:

1. May fail silently in some NAT configurations
2. No automated fallback in all scenarios
3. **Recommendation:** Use manual port forwarding for production nodes

## Testnet Deployment Guide

Before mainnet deployment, validate in a testnet environment:

### Using Docker Compose

```bash
# Start a 3-node test network
docker compose -f docker-compose.test.yml up -d

# Monitor logs
docker compose -f docker-compose.test.yml logs -f

# Run health checks
curl http://localhost:8080/health
curl http://localhost:8081/health
curl http://localhost:8082/health
```

### Using MXDTestSuite (GCP)

For larger-scale testing on Google Cloud Platform:

```bash
# Build the test suite
cd /path/to/MXDTestSuite
mkdir build && cd build
cmake .. && make

# Create a test network
./mxd_test_suite create --project your-gcp-project --nodes 5

# Monitor network health
./mxd_test_suite monitor

# Generate health report
./mxd_test_suite report

# Destroy when done
./mxd_test_suite destroy
```

### Validation Checklist for Testnet

- [ ] Genesis block created successfully
- [ ] All nodes discover each other via DHT
- [ ] Transactions propagate across all nodes
- [ ] Blocks are validated by multiple validators
- [ ] Tip distribution follows 50% geometric decay
- [ ] Node restart and recovery works correctly
- [ ] Network survives node failures (n-1 tolerance)
- [ ] No double-signing incidents
- [ ] Metrics are being collected correctly

## Support and Resources

### Documentation

- `docs/AUDIT_REPORT.md` - Security audit findings
- `SECURITY_IMPLEMENTATION.md` - Security implementation details
- `README.md` - General project information

### Reporting Issues

For security vulnerabilities, contact the maintainers directly. For general issues, use the GitHub issue tracker.

### Community

- Bootstrap API: https://mxd.network/bootstrap/main
- Testnet Bootstrap: https://mxd.network/bootstrap/test

---

**Document Maintained By:** MXD Development Team  
**Audit Reference:** AUDIT_REPORT.md (November 30, 2025)

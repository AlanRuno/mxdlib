Doc vs Implementation Matrix
- See docs/IMPLEMENTATION_MATRIX.md for a systematic comparison between documented design and actual implementation across consensus, P2P propagation, cryptography, configuration, and CI security features.

# 🌟 MXD Universal Dynamic Library

A cross-platform dynamic library implementing cryptographic, blockchain, and networking functionalities with ISO compliance and post-quantum security. This library serves as the foundation for the Mexican Denarius (MXD) cryptocurrency, designed to revolutionize digital financial transactions with a focus on efficiency, security, and scalability.

## 🌐 Cryptocurrency Overview

MXD (Mexican Denarius) represents a groundbreaking advancement in digital finance, designed to revolutionize financial transactions through innovative technology and accessibility:

### 🎯 Core Features & Vision
- **Zero Mandatory Fees**: Revolutionary transaction model with optional voluntary tips
- **Advanced Consensus**: Communication speed-based mechanism ensuring optimal efficiency
- **Deployment Status**: 
  - Current: Post-audit development phase (August 2025)
  - Status: 85% production ready with enterprise compliance in progress
  - Network: Mainnet deployment preparation underway
- **Financial Empowerment**: Focused on simplifying digital transactions and increasing accessibility

### 💫 Technical Innovation
- **Consensus Mechanism**: Utilizes network communication speed metrics for efficient block validation
- **Transaction Model**: UTXO-based system with voluntary tip structure
- **Security**: Hybrid cryptographic system supporting both Ed25519 and Dilithium5 simultaneously on the same network
  - Runtime algorithm selection via `algo_id` field in addresses and messages
  - Ed25519: 32-byte public keys, 64-byte signatures (default, production-ready)
  - Dilithium5: 2592-byte public keys, 4595-byte signatures (post-quantum secure)
  - Address format: `HASH160(algo_id || pubkey)` prevents cross-algorithm collisions
- **Network Efficiency**: Optimized P2P communication with DHT-based node discovery

## 🚀 Features

### 🔐 Core Cryptographic Features
- SHA-512 & RIPEMD-160 hashing (ISO/IEC 10118-3)
- Argon2 key derivation (ISO/IEC 11889)
- **Hybrid Digital Signatures**: Runtime algorithm selection supporting multiple signature schemes simultaneously
  - **Ed25519** (default): 32-byte public keys, 64-byte private keys, 64-byte signatures
  - **Dilithium5** (post-quantum): 2592-byte public keys, 4864-byte private keys, 4595-byte signatures
  - Algorithm identification via `algo_id` field (1=Ed25519, 2=Dilithium5)
  - Unified API: `mxd_sig_keygen()`, `mxd_sig_sign()`, `mxd_sig_verify()` dispatch to appropriate backend
- Elliptic curve cryptography (secp256k1) for robust transaction security
- Base58Check address encoding with algorithm-aware derivation

### 💎 Blockchain & Consensus
- Advanced Rapid Stake Consensus (RSC) with Validation Chain Protocol
- Sequential validation by ≥50% of Rapid Table nodes with cryptographic signatures
- Network Time Protocol (NTP) synchronization for precise timing
- RocksDB persistence for high-performance UTXO and blockchain storage
- Transaction management with UTXO model and voluntary tip system
- Memory pool for transaction staging
- P2P networking with DHT-based discovery and tamper-proof routing
- Eco-friendly design with minimal energy consumption
### Validation Chain Protocol rules
- A block is valid only if it has signatures from at least 50% of Rapid Table validators
- Each signature is over: block_hash || previous_validator_id || timestamp
- Timestamp drift allowance: ±60 seconds
- One signature per validator per block height
- Relay only if you just signed the block, or the block has ≥3 valid, ordered signatures
- Fork resolution preference: more valid signatures, then cumulative latency Σ(1/latency_i), then stake weight


### 📜 Smart Contracts & Extensions
**Status**: Smart contracts are currently **disabled by default** due to incomplete implementation.

The basic WASM3 runtime integration exists, but critical features are missing:
- ⚠️ No instruction-level gas metering (vulnerability to resource exhaustion)
- ⚠️ Incomplete storage implementation (no Merkle tree verification)
- ⚠️ No state root in block headers (prevents state verification)
- ⚠️ Limited security testing

**For Development/Testing Only**: Smart contracts can be enabled via configuration:
```json
{
  "contracts": {
    "enabled": true,
    "gas_limit_default": 1000000,
    "timeout_seconds": 5,
    "metering_enabled": true,
    "max_memory_pages": 256
  }
}
```

**WARNING**: Do not enable smart contracts on production networks. See [Smart Contracts Roadmap](docs/SMART_CONTRACTS_ROADMAP.md) for the complete implementation plan and timeline.

## 📚 Documentation

Detailed documentation is available in the `docs` directory:
- [Hybrid Cryptography Guide](docs/HYBRID_CRYPTO.md) - **Comprehensive guide to Ed25519 and Dilithium5 support**
- [Module Documentation](docs/MODULES.md)
- [Build Instructions](docs/BUILD.md)
- [Integration Guide](docs/INTEGRATION.md)
- [Implementation Matrix](docs/IMPLEMENTATION_MATRIX.md)
- [MXD Whitepaper (English)](https://mxd.com.mx/WhitePaper_En.pdf)

The library's architecture is designed for optimal performance and security in cryptocurrency operations, with a focus on rapid transaction processing and network efficiency. Our modular design separates concerns into distinct components:

### 📦 Module Organization
- **Crypto Module**: Implements hashing (SHA-512, RIPEMD-160) and signing operations
- **Address Management**: Handles wallet address generation and validation
- **Blockchain Core**: Manages consensus mechanism and block validation
- **Transaction Processing**: Implements UTXO model with voluntary tip system
- **P2P Networking**: Handles node discovery and communication
- **Smart Contracts**: Manages WASM-based contract execution
- **Checkpoints**: Provides blockchain synchronization points
- **Data Quantization**: Optimizes data storage and transmission

## 🛠️ Quick Start

### ✅ PRODUCTION STATUS (August 2025)
**SECURITY**: Critical security vulnerabilities resolved through comprehensive audit and implementation of secure logging framework and environment-based secrets management.

**CURRENT STATUS**: 85% Production Ready
- ✅ Core cryptographic and blockchain functionality implemented
- ✅ Security vulnerabilities addressed and verified
- ✅ Basic infrastructure and monitoring operational
- 🔄 Enterprise compliance and advanced monitoring in progress

**PERFORMANCE**: Current validated capacity of 10 TPS with enterprise target of 100 TPS
**NETWORK**: 3-second maximum latency (enterprise target: <1 second)

**See**: `docs/planning/NEXT_STEPS_POST_AUDIT.md` for complete enterprise readiness roadmap

### 🔒 Security Development Guidelines
If you are contributing to this project:

1. **Use secure logging framework** - MXD_LOG_* macros implemented in `src/mxd_logging.c`
2. **Environment-based secrets** - Load from environment variables, never hardcode
3. **Input validation required** - Use existing validation framework for all inputs
4. **Follow security patterns** - Review implemented security measures in codebase

### Node Configuration

#### Configuration File
The node can be started with or without a configuration file:
```bash
# Start with custom config
./mxd_node --config custom_config.json

# Start with default config (loads default_config.json from executable directory)
./mxd_node
```

#### Configuration Options
The configuration file supports the following options:

**Core Settings:**
- `node_id` (string): Unique identifier for this node (default: "default_node")
- `node_name` (string): Human-readable name for this node (default: "MXD Default Node")
- `network_type` (string): Network to connect to - "mainnet" or "testnet" (default: "testnet")
- `port` (integer): P2P listening port (default: 8000)
- `data_dir` (string): Directory for blockchain data storage (default: "./data")
- `initial_stake` (number): Initial stake amount for this node (default: 100.0)

**Cryptographic Algorithm Selection:**
- `preferred_sign_algo` (integer): Signature algorithm to use for this node
  - `1` = Ed25519 (default, production-ready, 32-byte keys, 64-byte signatures)
  - `2` = Dilithium5 (post-quantum secure, 2592-byte keys, 4595-byte signatures)
  
**Bootstrap Nodes:**
- `bootstrap_nodes` (array): List of bootstrap nodes in "host:port" format
  - Testnet: `["34.31.52.198:8000"]`
  - Mainnet: Contact network administrators for current bootstrap nodes

**Metrics Configuration:**
- `metrics.update_interval` (integer): Metrics collection interval in milliseconds (default: 1000)
- `metrics.display_interval` (integer): Metrics display refresh interval in milliseconds (default: 5000)
- `metrics.performance_threshold` (integer): Minimum TPS threshold (default: 10)
- `metrics.max_latency` (integer): Maximum acceptable network latency in milliseconds (default: 3000)
- `metrics.error_threshold` (integer): Maximum consecutive errors before alert (default: 10)

**Validation Settings:**
- `validation.min_tps` (integer): Minimum transactions per second required (default: 10)
- `validation.stake_table_update_interval` (integer): Rapid Table update interval in milliseconds (default: 60000)

**Network Settings:**
- `network.max_peers` (integer): Maximum number of peer connections (default: 50)
- `network.connection_timeout` (integer): Connection timeout in milliseconds (default: 5000)

**Pool Settings:**
- `pool.max_size` (integer): Maximum mempool size (default: 10000)
- `pool.cleanup_interval` (integer): Mempool cleanup interval in seconds (default: 3600)

**Logging:**
- `log_level` (string): Logging verbosity - "debug", "info", "warn", "error" (default: "info")

#### Example Configuration File
```json
{
    "node_id": "my_node_001",
    "node_name": "My MXD Node",
    "network_type": "testnet",
    "port": 8000,
    "data_dir": "./data",
    "initial_stake": 100.0,
    "preferred_sign_algo": 1,
    "bootstrap_nodes": [
        "34.31.52.198:8000"
    ],
    "metrics": {
        "update_interval": 1000,
        "display_interval": 5000,
        "performance_threshold": 10,
        "max_latency": 3000,
        "error_threshold": 10
    },
    "validation": {
        "min_tps": 10,
        "stake_table_update_interval": 60000
    },
    "network": {
        "max_peers": 50,
        "connection_timeout": 5000
    },
    "log_level": "info",
    "pool": {
        "max_size": 10000,
        "cleanup_interval": 3600
    }
}
```

#### Command-Line Options
The node supports the following command-line flags:

**Configuration:**
- `--config <file>`: Specify custom configuration file path
  ```bash
  ./mxd_node --config /path/to/config.json
  ```

**Algorithm Override:**
Override the `preferred_sign_algo` from configuration file:
- `--algo <algorithm>`: Force use of specific signature algorithm
  - `--algo ed25519`: Use Ed25519 signatures (32-byte keys, 64-byte signatures)
  - `--algo dilithium5`: Use Dilithium5 signatures (2592-byte keys, 4595-byte signatures)
  ```bash
  ./mxd_node --algo ed25519
  ./mxd_node --algo dilithium5
  ```

**Network:**
- `--port <number>`: Override P2P listening port
  ```bash
  ./mxd_node --port 9000
  ```
- `--bootstrap`: Register this node as a bootstrap node
  ```bash
  ./mxd_node --bootstrap
  ```

**Example Usage:**
```bash
# Start with Ed25519 on custom port
./mxd_node --algo ed25519 --port 9000

# Start with Dilithium5 using custom config
./mxd_node --config testnet.json --algo dilithium5

# Start as bootstrap node with default settings
./mxd_node --bootstrap
```

**Note on Algorithm Selection:**
- The `preferred_sign_algo` setting only affects **new keypair generation**
- If a keypair already exists in the data directory, the node will use the algorithm from the existing keypair
- To switch algorithms, delete the existing keypair file or use a different `data_dir`
- Both Ed25519 and Dilithium5 nodes can coexist on the same network seamlessly

### 🔐 Cryptographic Implementation Status:
- **Hybrid System**: Both Ed25519 and Dilithium5 supported simultaneously on the same network
- **Default Algorithm**: Ed25519 signatures via libsodium (production ready)
- **Post-Quantum**: Dilithium5 signatures available (both backends always compiled and linked)
- **Runtime Selection**: Nodes can use different algorithms; `algo_id` field identifies which algorithm each address uses
- **Wire Protocol**: Self-describing messages include `algo_id` and length fields for variable-size keys/signatures
- **Address Derivation**: `HASH160(algo_id || pubkey)` prevents cross-algorithm address collisions
- **API**: Unified `mxd_sig_*` functions dispatch to appropriate backend based on `algo_id`
- **Breaking Change**: Address format changed in v2 protocol; requires coordinated network reset

### Prerequisites

⚠️ **Important**: Before proceeding with any build or test operations, you must first install all dependencies:

```bash
./install_dependencies.sh [--force_build]
```

This step is mandatory and ensures all required libraries and tools are properly configured.

The script automatically detects your operating system and runs the appropriate installation script:
- Linux: Uses apt-get and builds from source
- macOS: Uses Homebrew and builds from source (supports both Intel and Apple Silicon)
- Windows: Uses MSYS2/MinGW and builds from source

Options:
- `--force_build`: Force rebuild and installation of libraries even if they are already installed

These scripts will automatically install:
#### System Dependencies
- build-essential (Ubuntu/Debian)
- cmake
- libssl-dev
- libsodium-dev
- libgmp-dev

#### Required Libraries
- wasm3 (WebAssembly Runtime)
- libuv (Event-driven Library)
- uvwasi (WASI Implementation)

The script supports both Ubuntu/Debian and macOS systems.

For manual installation instructions, see below:

#### System Dependencies (Manual Installation)
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev libsodium-dev libgmp-dev

# macOS
brew install cmake openssl libsodium gmp
```

#### Required Libraries (Manual Installation)
The following libraries need to be built and installed:

1. wasm3 (WebAssembly Runtime):
```bash
git clone https://github.com/wasm3/wasm3
cd wasm3 && mkdir build && cd build
cmake -DBUILD_WASM3_LIBS=ON ..
make && sudo make install
```

2. libuv (Event-driven Library):
```bash
git clone https://github.com/libuv/libuv
cd libuv && mkdir build && cd build
cmake ..
make && sudo make install
```

3. uvwasi (WASI Implementation):
```bash
git clone https://github.com/nodejs/uvwasi
cd uvwasi && mkdir build && cd build
cmake ..
make && sudo make install
```

After installing all dependencies, update the library cache:
```bash
sudo ldconfig
```

### Build Steps
```bash
# Clone repository
git clone https://github.com/AlanRuno/mxdlib.git
cd mxdlib

# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
make

# Run tests (requires completed dependency installation)
make test
```

### 🧪 Testing Information
The test suite includes:
- Unit tests for all core modules
- Integration tests for blockchain operations
- Performance tests for cryptographic operations
- Network simulation tests for consensus mechanism
- Smart contract execution tests

Expected test duration: 3-5 minutes on standard hardware
Memory requirement: Minimum 4GB RAM recommended
Note: Some tests require network connectivity for P2P simulations

## 💡 Basic Usage

For comprehensive examples and detailed API documentation, see [docs/HYBRID_CRYPTO.md](docs/HYBRID_CRYPTO.md).

### Generate MXD Address (Ed25519)
```c
#include <mxd_address.h>
#include <mxd_crypto.h>

// Generate Ed25519 keypair (default, production-ready)
uint8_t algo_id = MXD_SIGALG_ED25519;
uint8_t public_key[MXD_PUBKEY_MAX_LEN];
uint8_t private_key[MXD_PRIVKEY_MAX_LEN];
mxd_sig_keygen(algo_id, public_key, private_key);

// Get actual key lengths for the algorithm
size_t pubkey_len = mxd_sig_pubkey_len(algo_id);  // Returns 32 for Ed25519

// Derive address (includes algo_id to prevent collisions)
uint8_t address[20];
mxd_derive_address(algo_id, public_key, pubkey_len, address);

// Generate Base58Check address string (v2 format)
char address_str[42];
mxd_address_to_string_v2(algo_id, public_key, pubkey_len, 
                         address_str, sizeof(address_str));
```

### Generate MXD Address (Dilithium5 - Post-Quantum)
```c
#include <mxd_address.h>
#include <mxd_crypto.h>

// Generate Dilithium5 keypair (post-quantum secure)
uint8_t algo_id = MXD_SIGALG_DILITHIUM5;
uint8_t public_key[MXD_PUBKEY_MAX_LEN];
uint8_t private_key[MXD_PRIVKEY_MAX_LEN];
mxd_sig_keygen(algo_id, public_key, private_key);

// Get actual key lengths for the algorithm
size_t pubkey_len = mxd_sig_pubkey_len(algo_id);  // Returns 2592 for Dilithium5

// Derive address with algorithm identification
char address_str[42];
mxd_address_to_string_v2(algo_id, public_key, pubkey_len,
                         address_str, sizeof(address_str));
```

### Create Transaction
```c
#include <mxd_transaction.h>

// Create transaction
mxd_transaction_t tx;
mxd_create_transaction(&tx);

// Add input with algorithm specification
uint8_t prev_tx_hash[64] = {/* ... */};
uint8_t algo_id = MXD_SIGALG_ED25519;
uint8_t public_key[32];
mxd_add_tx_input(&tx, prev_tx_hash, 0, algo_id, public_key, 32);

// Add output
uint8_t recipient_addr[20] = {/* ... */};
mxd_add_tx_output(&tx, recipient_addr, 1.0);

// Sign input with private key
uint8_t private_key[64];
mxd_sign_tx_input(&tx, 0, algo_id, private_key);

// Cleanup
mxd_free_transaction(&tx);
```

### Deploy Smart Contract (Development Only)
**Note**: Smart contracts are disabled by default. Enable via configuration for development/testing only.

```c
#include <mxd_smart_contracts.h>

// Smart contracts must be enabled in configuration first
// See docs/SMART_CONTRACTS_ROADMAP.md for details

mxd_contract_state_t state;
int result = mxd_deploy_contract(wasm_code, wasm_size, &state);
if (result != 0) {
    // Returns error if contracts are disabled or deployment fails
    printf("Contract deployment failed (contracts may be disabled)\n");
}
```

## 🤝 Contributing
Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links
- [Issue Tracker](https://github.com/AlanRuno/mxdlib/issues)
- [Release Notes](https://github.com/AlanRuno/mxdlib/releases)

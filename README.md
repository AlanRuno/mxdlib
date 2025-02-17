# 🌟 MXD Universal Dynamic Library

A cross-platform dynamic library implementing cryptographic, blockchain, and networking functionalities with ISO compliance and post-quantum security.

## 🚀 Features

### 🔐 Core Cryptographic Features
- SHA-512 & RIPEMD-160 hashing (ISO/IEC 10118-3)
- Argon2 key derivation (ISO/IEC 11889)
- Dilithium5 post-quantum signatures (ISO/IEC 18033-3)
- Base58Check address encoding

### 💎 Blockchain & Consensus
- Block structure and validation
- Rapid Stake Consensus (RSC)
- Transaction management with UTXO model
- Memory pool for transaction staging
- P2P networking with DHT-based discovery

### 📜 Smart Contracts & Extensions
- WebAssembly (WASM) runtime using wasm3
- Contract deployment and execution
- Gas metering and limits
- State management and validation
- Secure storage with Merkle trees

## 📚 Documentation

Detailed documentation is available in the `docs` directory:
- [Module Documentation](docs/MODULES.md)
- [Build Instructions](docs/BUILD.md)
- [Integration Guide](docs/INTEGRATION.md)

## 🛠️ Quick Start

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev libsodium-dev libgmp-dev

# macOS
brew install cmake openssl libsodium gmp
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

# Run tests
make test
```

## 💡 Basic Usage

### Generate MXD Address
```c
#include <mxd_address.h>

char address[42];
uint8_t public_key[256];
mxd_generate_address(public_key, address, sizeof(address));
```

### Create Transaction
```c
#include <mxd_transaction.h>

mxd_transaction_t tx;
mxd_create_transaction(&tx);
mxd_add_tx_output(&tx, recipient_key, 1.0);
mxd_sign_tx_input(&tx, 0, private_key);
```

### Deploy Smart Contract
```c
#include <mxd_smart_contracts.h>

mxd_contract_state_t state;
mxd_deploy_contract(wasm_code, wasm_size, &state);
```

## 🤝 Contributing
Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links
- [Issue Tracker](https://github.com/AlanRuno/mxdlib/issues)
- [Release Notes](https://github.com/AlanRuno/mxdlib/releases)

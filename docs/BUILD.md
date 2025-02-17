# 🛠️ Building MXD Library

## Prerequisites

### Required Tools
- CMake 3.10+
- C11 compatible compiler
- OpenSSL 3.0+
- libsodium
- GMP (GNU Multiple Precision Arithmetic Library)
- wasm3
- uvwasi and libuv

### Platform-Specific Setup

#### Ubuntu/Debian
```bash
# Install build tools
sudo apt-get update
sudo apt-get install -y build-essential cmake

# Install dependencies
sudo apt-get install -y libssl-dev libsodium-dev libgmp-dev

# Install WebAssembly runtime dependencies
sudo apt-get install -y libuv1-dev
```

#### macOS
```bash
# Install build tools
brew install cmake

# Install dependencies
brew install openssl libsodium gmp

# Install WebAssembly runtime dependencies
brew install libuv
```

#### Windows
```bash
# Using vcpkg
vcpkg install openssl:x64-windows
vcpkg install libsodium:x64-windows
vcpkg install gmp:x64-windows
vcpkg install libuv:x64-windows
```

## Build Steps

1. Clone the repository:
```bash
git clone https://github.com/AlanRuno/mxdlib.git
cd mxdlib
```

2. Create build directory:
```bash
mkdir build
cd build
```

3. Configure with CMake:
```bash
# Unix-like systems
cmake ..

# Windows with vcpkg
cmake -DCMAKE_TOOLCHAIN_FILE=[vcpkg root]/scripts/buildsystems/vcpkg.cmake ..
```

4. Build the library:
```bash
cmake --build .
```

5. Run tests:
```bash
ctest --output-on-failure
```

## Installation

### System-wide Installation
```bash
sudo cmake --install .
```

### Custom Installation Directory
```bash
cmake --install . --prefix /path/to/install
```

## Troubleshooting

### Common Issues

1. OpenSSL Not Found
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# macOS
brew install openssl
export OPENSSL_ROOT_DIR=$(brew --prefix openssl)
```

2. libsodium Not Found
```bash
# Ubuntu/Debian
sudo apt-get install libsodium-dev

# macOS
brew install libsodium
```

3. GMP Not Found
```bash
# Ubuntu/Debian
sudo apt-get install libgmp-dev

# macOS
brew install gmp
```

### Build Verification
After building, verify the installation:
```bash
# Run all tests
make test

# Run specific test
./tests/test_crypto
./tests/test_address
```

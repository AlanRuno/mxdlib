# MXD Universal Dynamic Library

## Build Requirements

### System Dependencies
- CMake (3.10 or higher)
- GCC/Clang with C11 support
- libsodium-dev
- libgmp-dev

### Required Libraries
The following libraries need to be built and installed before building mxdlib:

#### wasm3
```bash
git clone https://github.com/wasm3/wasm3
cd wasm3 && mkdir build && cd build
cmake -DBUILD_WASM3_LIBS=ON ..
make && sudo make install
```

#### libuv
```bash
git clone https://github.com/libuv/libuv
cd libuv && mkdir build && cd build
cmake ..
make && sudo make install
```

#### uvwasi
```bash
git clone https://github.com/nodejs/uvwasi
cd uvwasi && mkdir build && cd build
cmake ..
make && sudo make install
```

After installing dependencies, update the library cache:
```bash
sudo ldconfig
```

## Building mxdlib

1. Clone the repository:
```bash
git clone https://github.com/AlanRuno/mxdlib.git
cd mxdlib
```

2. Create build directory and build:
```bash
mkdir build && cd build
cmake ..
make
```

## Running Tests

All tests can be run from the build/lib directory:
```bash
cd build/lib
./mxd_*_tests
```

### Network Tests
To run network tests, use the --network flag with a config file:
```bash
./mxd_dht_tests --network --config ../../testnet/node0/config.json
./mxd_p2p_tests --network --config ../../testnet/node0/config.json
```

## Network Architecture

### Node Discovery
Nodes discover each other through:
1. Well-known bootstrap nodes (hardcoded IP addresses)
2. DNS seeds that provide lists of active nodes
3. Node address sharing between peers
4. Periodic network scanning for known ports

New nodes connect to these entry points to join the network.

### DHT (Distributed Hash Table)
The network uses a Kademlia-based DHT for peer discovery and routing:
- Each node has a unique ID
- Bootstrap nodes serve as initial entry points
- Nodes maintain routing tables of known peers
- Peer discovery uses XOR distance metrics
- K-buckets organize peer information efficiently


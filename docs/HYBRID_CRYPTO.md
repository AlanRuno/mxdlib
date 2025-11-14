# Hybrid Cryptography Implementation Guide

## Overview

The MXD blockchain implements a **hybrid cryptographic system** that supports both classical (Ed25519) and post-quantum (Dilithium5) signature algorithms simultaneously on the same network. This design ensures both current security and future-proofing against quantum computing threats.

## Key Concepts

### Runtime Algorithm Selection

Unlike systems that require network-wide algorithm upgrades, MXD allows **individual nodes to choose their preferred algorithm** at runtime. Both Ed25519 and Dilithium5 nodes can coexist and interact seamlessly on the same network.

### Algorithm Identification

Every cryptographic operation in MXD includes an `algo_id` field that identifies which algorithm is being used:

```c
typedef enum {
    MXD_SIGALG_ED25519 = 1,      // Classical, production-ready
    MXD_SIGALG_DILITHIUM5 = 2    // Post-quantum secure
} mxd_sig_alg_t;
```

### Key and Signature Sizes

The two algorithms have vastly different key and signature sizes:

| Algorithm | Public Key | Private Key | Signature |
|-----------|-----------|-------------|-----------|
| Ed25519 | 32 bytes | 64 bytes | 64 bytes |
| Dilithium5 | 2,592 bytes | 4,864 bytes | 4,595 bytes |

All protocol messages and data structures use **variable-length fields** with explicit length prefixes to accommodate both algorithms.

## Architecture

### 1. Unified Cryptographic API

The MXD library provides algorithm-agnostic functions that dispatch to the appropriate backend based on `algo_id`:

```c
// Key generation
int mxd_sig_keygen(uint8_t algo_id, uint8_t *public_key, uint8_t *secret_key);

// Signing
int mxd_sig_sign(uint8_t algo_id, uint8_t *signature, size_t *signature_length,
                 const uint8_t *message, size_t message_length,
                 const uint8_t *secret_key);

// Verification
int mxd_sig_verify(uint8_t algo_id, const uint8_t *signature, size_t signature_length,
                   const uint8_t *message, size_t message_length,
                   const uint8_t *public_key);

// Length helpers
size_t mxd_sig_pubkey_len(uint8_t algo_id);
size_t mxd_sig_privkey_len(uint8_t algo_id);
size_t mxd_sig_signature_len(uint8_t algo_id);
const char* mxd_sig_alg_name(uint8_t algo_id);
```

**Implementation Details:**
- Ed25519 operations use **libsodium** (`crypto_sign_*` functions)
- Dilithium5 operations use **liboqs** (Open Quantum Safe library)
- Both backends are always compiled and linked; selection happens at runtime

### 2. Address Derivation with Algorithm Awareness

MXD addresses include the algorithm ID in their derivation to prevent cross-algorithm collisions:

```c
// Address derivation: HASH160(algo_id || pubkey)
int mxd_derive_address(uint8_t algo_id, const uint8_t *public_key, 
                       size_t pubkey_len, uint8_t address[20]);
```

**Address Format (v2):**
```
Version Byte | Address20 (HASH160) | Checksum (4 bytes)
     1 byte  |      20 bytes       |     4 bytes
```

**Version Bytes:**
- `0x32` (50 decimal): Ed25519 address
- `0x33` (51 decimal): Dilithium5 address

**Example:**
```c
// Generate Ed25519 address
uint8_t ed25519_pubkey[32];
uint8_t ed25519_privkey[64];
mxd_sig_keygen(MXD_SIGALG_ED25519, ed25519_pubkey, ed25519_privkey);

char address[42];
mxd_address_to_string_v2(MXD_SIGALG_ED25519, ed25519_pubkey, 32, 
                         address, sizeof(address));
// Result: Address starting with "M" (Base58Check encoded)

// Generate Dilithium5 address
uint8_t dilithium5_pubkey[2592];
uint8_t dilithium5_privkey[4864];
mxd_sig_keygen(MXD_SIGALG_DILITHIUM5, dilithium5_pubkey, dilithium5_privkey);

mxd_address_to_string_v2(MXD_SIGALG_DILITHIUM5, dilithium5_pubkey, 2592,
                         address, sizeof(address));
// Result: Different address due to algo_id in derivation
```

**Address Parsing:**
```c
// Extract algo_id and address20 from Base58Check address
uint8_t algo_id;
uint8_t addr20[20];
mxd_parse_address(address_string, &algo_id, addr20);
```

### 3. Protocol v2 Wire Format

All network messages in Protocol v2 are **self-describing** with explicit algorithm and length fields.

#### Handshake Payload Structure

```c
typedef struct {
    char node_id[256];                      // Node identifier (wallet address)
    uint32_t protocol_version;              // Protocol version (2 for hybrid)
    uint16_t listen_port;                   // Listening port
    uint8_t algo_id;                        // Algorithm ID (1 or 2)
    uint16_t public_key_length;             // Length of public key
    uint8_t public_key[MXD_PUBKEY_MAX_LEN]; // Public key (variable size)
    uint8_t challenge[32];                  // Random challenge nonce
    uint16_t signature_length;              // Length of signature
    uint8_t signature[MXD_SIG_MAX_LEN];     // Signature (variable size)
} mxd_handshake_payload_t;
```

**Wire Serialization:**
1. Fixed-size fields are serialized in network byte order (big-endian)
2. Variable-size fields are prefixed with their length (2 bytes, network order)
3. Actual data follows the length prefix

**Example Wire Format:**
```
[node_id: 256 bytes]
[protocol_version: 4 bytes]
[listen_port: 2 bytes]
[algo_id: 1 byte]
[public_key_length: 2 bytes]  <- Length prefix
[public_key: variable]         <- Actual key data
[challenge: 32 bytes]
[signature_length: 2 bytes]    <- Length prefix
[signature: variable]          <- Actual signature data
```

### 4. Transaction Structure (v2)

Transaction inputs include algorithm information for signature verification:

```c
typedef struct {
    uint8_t prev_tx_hash[64];      // Previous transaction hash
    uint32_t output_index;         // Output index in previous tx
    uint8_t algo_id;               // Algorithm used for signature
    uint16_t public_key_length;    // Length of public key
    uint8_t *public_key;           // Public key (heap-allocated)
    uint16_t signature_length;     // Length of signature
    uint8_t *signature;            // Signature (heap-allocated)
} mxd_tx_input_t;
```

**Transaction Validation:**
```c
// Validation checks algorithm-specific lengths
size_t expected_pubkey_len = mxd_sig_pubkey_len(input->algo_id);
if (input->public_key_length != expected_pubkey_len) {
    return -1; // Invalid key length for algorithm
}

size_t expected_sig_len = mxd_sig_signature_len(input->algo_id);
if (input->signature_length != expected_sig_len) {
    return -1; // Invalid signature length for algorithm
}

// Verify signature using algorithm-aware function
mxd_sig_verify(input->algo_id, input->signature, input->signature_length,
               tx_hash, 64, input->public_key);
```

### 5. Blockchain Structures

#### Validator Signatures

```c
typedef struct {
    uint8_t validator_id[20];      // Validator address (address20)
    uint64_t timestamp;            // Signature timestamp
    uint8_t algo_id;               // Algorithm used
    uint16_t signature_length;     // Length of signature
    uint8_t signature[MXD_SIGNATURE_MAX]; // Signature data
    uint32_t chain_position;       // Position in validation chain
} mxd_validator_signature_t;
```

#### Rapid Membership Entries

```c
typedef struct {
    uint8_t node_address[20];      // Node address (address20)
    uint64_t timestamp;            // Entry timestamp
    uint8_t algo_id;               // Algorithm used
    uint16_t public_key_length;    // Length of public key
    uint8_t public_key[2592];      // Public key (max size)
    uint16_t signature_length;     // Length of signature
    uint8_t signature[MXD_SIGNATURE_MAX]; // Signature data
} mxd_rapid_membership_entry_t;
```

**Membership Validation:**
```c
// Validate algo_id
if (algo_id != MXD_SIGALG_ED25519 && algo_id != MXD_SIGALG_DILITHIUM5) {
    return -1; // Invalid algorithm
}

// Validate key length matches algorithm
size_t expected_pubkey_len = mxd_sig_pubkey_len(algo_id);
if (public_key_length != expected_pubkey_len) {
    return -1; // Mismatched key length
}

// Validate signature length matches algorithm
size_t expected_sig_len = mxd_sig_signature_len(algo_id);
if (signature_length != expected_sig_len) {
    return -1; // Mismatched signature length
}

// Verify signature over membership digest
uint8_t digest[64];
mxd_calculate_membership_digest(block, digest);
mxd_sig_verify(algo_id, signature, signature_length, digest, 64, public_key);
```

## Configuration

### Node Configuration

Nodes specify their preferred algorithm in the configuration file:

```json
{
    "node_id": "my_node_001",
    "preferred_sign_algo": 1,  // 1=Ed25519, 2=Dilithium5
    "port": 8000,
    "network_type": "testnet"
}
```

### Command-Line Override

The algorithm can be overridden via command-line:

```bash
# Use Ed25519
./mxd_node --algo ed25519

# Use Dilithium5
./mxd_node --algo dilithium5
```

### Algorithm Persistence

**Important:** Once a node generates a keypair, the algorithm is determined by the existing keypair file. To change algorithms:

1. Stop the node
2. Delete or backup the keypair file in `data_dir`
3. Restart with the new algorithm setting

## Network Compatibility

### Mixed-Algorithm Networks

Ed25519 and Dilithium5 nodes can coexist on the same network:

- **P2P Handshake**: Each node advertises its `algo_id` during connection
- **Transaction Validation**: Validators check `algo_id` and use appropriate verification
- **Block Validation**: Validation chains can contain signatures from both algorithm types
- **Address Resolution**: Address version byte identifies the algorithm

### Protocol Version Negotiation

- **Protocol v1**: Ed25519 only (legacy, deprecated)
- **Protocol v2**: Hybrid support (current)

Nodes using Protocol v2 can communicate with each other regardless of their chosen algorithm. Protocol v1 nodes are not compatible with v2 and require upgrade.

## Security Considerations

### Collision Prevention

The address derivation formula `HASH160(algo_id || pubkey)` ensures that:
- The same public key bytes with different algorithms produce different addresses
- No address collisions can occur between Ed25519 and Dilithium5 keys

### Algorithm Downgrade Protection

The protocol prevents algorithm downgrade attacks:
- Address version byte is cryptographically bound to the address
- Signature verification always checks `algo_id` matches the expected algorithm
- Transaction inputs explicitly specify the algorithm used

### Quantum Resistance Timeline

- **Current (2025)**: Ed25519 provides adequate security against classical computers
- **Future (2030+)**: Large-scale quantum computers may threaten Ed25519
- **Dilithium5**: Provides security against both classical and quantum attacks

**Recommendation:** Use Ed25519 for production deployments today. Migrate to Dilithium5 when:
1. Quantum computing threats become imminent
2. Performance requirements allow for larger signatures
3. Network bandwidth can accommodate increased message sizes

## Performance Characteristics

### Ed25519 Performance

- **Key Generation**: ~50,000 keypairs/second
- **Signing**: ~20,000 signatures/second
- **Verification**: ~10,000 verifications/second
- **Signature Size**: 64 bytes (minimal network overhead)

### Dilithium5 Performance

- **Key Generation**: ~5,000 keypairs/second
- **Signing**: ~2,000 signatures/second
- **Verification**: ~3,000 verifications/second
- **Signature Size**: 4,595 bytes (72x larger than Ed25519)

### Network Impact

**Bandwidth Considerations:**
- Ed25519 transaction: ~200 bytes typical
- Dilithium5 transaction: ~5,000 bytes typical (25x larger)
- Block with 100 Ed25519 validators: ~6.4 KB signatures
- Block with 100 Dilithium5 validators: ~459.5 KB signatures

**Recommendation:** For high-throughput networks, Ed25519 is currently more practical. Dilithium5 should be reserved for high-security scenarios or future quantum threats.

## Testing

### Unit Tests

The test suite includes comprehensive hybrid cryptography tests:

```bash
# Run all tests
make test

# Run specific hybrid crypto tests
./build/tests/test_mixed_algorithms
./build/tests/test_crypto
./build/tests/test_address
```

### Test Coverage

- **test_mixed_algorithms.c**: Dedicated hybrid key test suite
  - Mixed keygen and signature verification
  - Mixed address generation with collision prevention
  - Mixed transaction inputs
  - Mixed validator signatures
  - Cross-algorithm verification failure tests

- **test_crypto.c**: Algorithm-specific primitive tests
- **test_address.c**: Address generation and validation
- **test_p2p.c**: Protocol v2 handshake tests
- **test_blockchain.c**: Block validation with mixed algorithms
- **test_validation_chain.c**: Validation chain with hybrid signatures

## Migration Guide

### Upgrading from Protocol v1 to v2

**Breaking Changes:**
- Address format changed to include `algo_id` in derivation
- All addresses must be regenerated
- Requires coordinated network upgrade

**Migration Steps:**

1. **Announce Upgrade**: Coordinate with network participants
2. **Backup Data**: Save all keypairs and wallet data
3. **Network Halt**: Stop all nodes at agreed block height
4. **Upgrade Software**: Deploy Protocol v2 binaries
5. **Regenerate Addresses**: Use v2 address generation
6. **Genesis Reset**: Create new genesis block with v2 addresses
7. **Network Restart**: Start all nodes with v2 protocol

### Adding Dilithium5 to Existing Ed25519 Network

**No Breaking Changes Required:**
- New Dilithium5 nodes can join existing Ed25519 networks
- Existing Ed25519 nodes continue operating normally
- Gradual migration possible

**Steps:**

1. **Deploy v2 Protocol**: Ensure all nodes support Protocol v2
2. **Add Dilithium5 Nodes**: Start new nodes with `preferred_sign_algo: 2`
3. **Verify Compatibility**: Test transactions between Ed25519 and Dilithium5 nodes
4. **Monitor Performance**: Track network bandwidth and latency
5. **Gradual Migration**: Migrate existing nodes as needed

## API Examples

### Example 1: Generate Keypair and Address

```c
#include <mxd_crypto.h>
#include <mxd_address.h>

// Choose algorithm
uint8_t algo_id = MXD_SIGALG_DILITHIUM5;

// Generate keypair
uint8_t public_key[MXD_PUBKEY_MAX_LEN];
uint8_t private_key[MXD_PRIVKEY_MAX_LEN];
if (mxd_sig_keygen(algo_id, public_key, private_key) != 0) {
    fprintf(stderr, "Keygen failed\n");
    return -1;
}

// Get actual key lengths
size_t pubkey_len = mxd_sig_pubkey_len(algo_id);
size_t privkey_len = mxd_sig_privkey_len(algo_id);

printf("Generated %s keypair\n", mxd_sig_alg_name(algo_id));
printf("Public key: %zu bytes\n", pubkey_len);
printf("Private key: %zu bytes\n", privkey_len);

// Generate address
char address[42];
if (mxd_address_to_string_v2(algo_id, public_key, pubkey_len, 
                              address, sizeof(address)) != 0) {
    fprintf(stderr, "Address generation failed\n");
    return -1;
}

printf("Address: %s\n", address);
```

### Example 2: Sign and Verify Message

```c
#include <mxd_crypto.h>

uint8_t algo_id = MXD_SIGALG_ED25519;
uint8_t public_key[MXD_PUBKEY_MAX_LEN];
uint8_t private_key[MXD_PRIVKEY_MAX_LEN];

// Generate keypair
mxd_sig_keygen(algo_id, public_key, private_key);

// Message to sign
const char *message = "Hello, MXD!";
size_t message_len = strlen(message);

// Sign message
uint8_t signature[MXD_SIG_MAX_LEN];
size_t signature_len = 0;
if (mxd_sig_sign(algo_id, signature, &signature_len,
                 (const uint8_t*)message, message_len,
                 private_key) != 0) {
    fprintf(stderr, "Signing failed\n");
    return -1;
}

printf("Signature: %zu bytes\n", signature_len);

// Verify signature
if (mxd_sig_verify(algo_id, signature, signature_len,
                   (const uint8_t*)message, message_len,
                   public_key) == 0) {
    printf("Signature valid!\n");
} else {
    printf("Signature invalid!\n");
}
```

### Example 3: Create Transaction with Dilithium5

```c
#include <mxd_transaction.h>
#include <mxd_crypto.h>

// Create transaction
mxd_transaction_t tx;
mxd_create_transaction(&tx);

// Add input with Dilithium5 signature
uint8_t prev_tx_hash[64] = {/* ... */};
uint32_t output_index = 0;
uint8_t algo_id = MXD_SIGALG_DILITHIUM5;

uint8_t public_key[2592];
uint8_t private_key[4864];
mxd_sig_keygen(algo_id, public_key, private_key);

// Add input
mxd_add_tx_input(&tx, prev_tx_hash, output_index, algo_id, 
                 public_key, 2592);

// Add output
uint8_t recipient_addr[20] = {/* ... */};
mxd_add_tx_output(&tx, recipient_addr, 10.0);

// Sign input
mxd_sign_tx_input(&tx, 0, algo_id, private_key);

// Validate transaction
if (mxd_validate_transaction(&tx) == 0) {
    printf("Transaction valid!\n");
}

// Cleanup
mxd_free_transaction(&tx);
```

## Troubleshooting

### Common Issues

**Issue: "Invalid algorithm ID"**
- Cause: Using algo_id value other than 1 or 2
- Solution: Use `MXD_SIGALG_ED25519` (1) or `MXD_SIGALG_DILITHIUM5` (2)

**Issue: "Invalid key length for algorithm"**
- Cause: Key length doesn't match expected size for algorithm
- Solution: Use `mxd_sig_pubkey_len(algo_id)` to get correct length

**Issue: "Signature verification failed"**
- Cause: Algorithm mismatch between signing and verification
- Solution: Ensure same `algo_id` used for both operations

**Issue: "Address collision detected"**
- Cause: Using Protocol v1 address derivation
- Solution: Use `mxd_address_to_string_v2()` with `algo_id` parameter

### Debug Logging

Enable debug logging to trace algorithm selection:

```bash
export MXD_LOG_LEVEL=debug
./mxd_node --algo dilithium5
```

Look for log messages like:
```
[crypto] Using algorithm: Dilithium5 (algo_id=2)
[crypto] Public key length: 2592 bytes
[crypto] Signature length: 4595 bytes
```

## References

### Standards and Specifications

- **Ed25519**: RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)
- **Dilithium**: NIST FIPS 204 - Module-Lattice-Based Digital Signature Standard
- **HASH160**: Bitcoin-style address derivation (RIPEMD-160(SHA-256(x)))
- **Base58Check**: Bitcoin-style address encoding

### External Libraries

- **libsodium**: https://libsodium.gitbook.io/
- **liboqs**: https://github.com/open-quantum-safe/liboqs
- **NIST PQC**: https://csrc.nist.gov/projects/post-quantum-cryptography

### Further Reading

- MXD Whitepaper: https://mxd.com.mx/WhitePaper_En.pdf
- Implementation Matrix: docs/IMPLEMENTATION_MATRIX.md
- Module Documentation: docs/MODULES.md
- Build Instructions: docs/BUILD.md

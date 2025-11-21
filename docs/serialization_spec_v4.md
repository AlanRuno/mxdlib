# MXD Serialization Specification v4

## Overview

This document specifies the canonical serialization format for MXD blockchain data structures. All multi-byte integers use big-endian (network byte order) encoding for cross-platform compatibility.

## Version History

- **v4**: Canonical big-endian serialization with integer amounts (Phase 1 & 2)
- **v3**: Session token binding for P2P messages
- **v2**: Hybrid cryptography support (Ed25519 + Dilithium5)
- **v1**: Initial specification

## Primitive Types

### Integer Encoding

All multi-byte integers are encoded in big-endian (network byte order):

- `u8`: 1 byte, unsigned
- `u16`: 2 bytes, big-endian
- `u32`: 4 bytes, big-endian  
- `u64`: 8 bytes, big-endian

### Amount Type

Currency amounts use `mxd_amount_t` (u64) representing base units:
- 1 MXD = 100,000,000 base units (8 decimal places)
- Range: 0 to 18,446,744,073,709,551,615 base units
- Maximum: ~184,467,440,737 MXD

### Hash Type

All hashes use SHA-512:
- Length: 64 bytes
- Encoding: Raw binary

### Address Type

Node addresses use HASH160 (RIPEMD-160 of SHA-256):
- Format: `HASH160(algo_id || pubkey)`
- Length: 20 bytes
- Encoding: Raw binary

## Transaction Serialization

### Transaction Structure

```
version:          u32
input_count:      u32
output_count:     u32
voluntary_tip:    u64 (amount in base units)
timestamp:        u64 (Unix timestamp in seconds)
inputs:           [TxInput; input_count]
outputs:          [TxOutput; output_count]
is_coinbase:      u8 (boolean)
```

### Transaction Input

```
prev_tx_hash:        [u8; 64]
output_index:        u32
algo_id:             u8
public_key_length:   u16
public_key:          [u8; public_key_length]
signature_length:    u16
signature:           [u8; signature_length]
```

### Transaction Output

```
recipient_addr:  [u8; 20]
amount:          u64 (base units)
```

### Transaction Hash Calculation

1. Serialize transaction fields (excluding signatures) using canonical format
2. Compute SHA-512 hash of serialized data
3. Compute SHA-512 hash of the result (double SHA-512)

## Block Serialization

### Block Header

```
version:                    u32
prev_block_hash:            [u8; 64]
merkle_root:                [u8; 64]
timestamp:                  u64 (Unix timestamp in seconds)
difficulty:                 u32
nonce:                      u64
block_hash:                 [u8; 64]
proposer_id:                [u8; 20]
height:                     u32
validation_count:           u32
rapid_membership_count:     u32
total_supply:               u64 (base units)
transaction_set_frozen:     u8 (boolean)
```

### Validator Signature

```
validator_id:       [u8; 20]
timestamp:          u64
algo_id:            u8
signature_length:   u16
signature:          [u8; signature_length]
chain_position:     u32
```

### Rapid Membership Entry

```
node_address:          [u8; 20]
timestamp:             u64
algo_id:               u8
public_key_length:     u16
public_key:            [u8; public_key_length]
signature_length:      u16
signature:             [u8; signature_length]
```

## Database Keys

All database keys use big-endian encoding for integer components:

### Block Keys

```
block:height:{height_be}    - Block by height (height as u32 big-endian)
block:hash:{hash}           - Block by hash (64 bytes)
```

### Signature Keys

```
sig:{height_be}:{validator_id}  - Signature (height as u32 big-endian, validator_id 20 bytes)
```

### Validator Keys

```
validator:{validator_id}    - Validator metadata (validator_id 20 bytes)
```

### UTXO Keys

```
utxo:{tx_hash}:{output_index_be}  - UTXO (tx_hash 64 bytes, output_index as u32 big-endian)
```

## P2P Message Format

### Message Header

```
magic:          u32 (network identifier)
type:           u32 (message type enum)
length:         u32 (payload length)
checksum:       [u8; 64] (SHA-512 of payload)
session_token:  [u8; 16] (message binding token)
```

### Message Types

- `MXD_MSG_HANDSHAKE = 0`
- `MXD_MSG_PING = 1`
- `MXD_MSG_PONG = 2`
- `MXD_MSG_GET_PEERS = 3`
- `MXD_MSG_PEERS = 4`
- `MXD_MSG_GET_BLOCKS = 5`
- `MXD_MSG_BLOCKS = 6`
- `MXD_MSG_GET_TRANSACTIONS = 7`
- `MXD_MSG_TRANSACTIONS = 8`
- `MXD_MSG_BLOCK_VALIDATION = 9`
- `MXD_MSG_VALIDATION_SIGNATURE = 10`
- `MXD_MSG_GET_VALIDATION_CHAIN = 11`
- `MXD_MSG_VALIDATION_CHAIN = 12`
- `MXD_MSG_RAPID_TABLE_UPDATE = 13`
- `MXD_MSG_GENESIS_ANNOUNCE = 14`
- `MXD_MSG_GENESIS_SIGN_REQUEST = 15`
- `MXD_MSG_GENESIS_SIGN_RESPONSE = 16`
- `MXD_MSG_SESSION_TOKEN = 17`

## Cryptographic Algorithms

### Supported Algorithms

- **Ed25519** (algo_id = 1):
  - Public key: 32 bytes
  - Private key: 64 bytes
  - Signature: 64 bytes

- **Dilithium5** (algo_id = 2):
  - Public key: 2592 bytes
  - Private key: 4864 bytes
  - Signature: 4595 bytes

### Algorithm Selection

Nodes specify their algorithm via `algo_id` in all cryptographic operations. The network supports both algorithms simultaneously through:

1. Self-describing message formats with `algo_id` and length fields
2. Address derivation including `algo_id` to prevent collisions
3. Runtime algorithm selection (no compile-time flags)

## Validation Rules

### Timestamp Validation

- Maximum drift: ±60 seconds from system time
- Reject signatures outside this window
- Nodes should sync time via NTP

### Signature Validation

- Verify signature using specified `algo_id`
- Check validator is in Rapid Table
- Verify chain position is sequential
- Ensure no duplicate signatures per validator per height

### Block Relay Threshold

- Minimum signatures for relay: 3 (X=3)
- Dynamic threshold: `max(3, floor(RapidTable.size() * 0.25))`
- Only relay blocks with sufficient valid signatures

## Implementation Notes

### Serialization Helpers

Use the canonical serialization helpers from `mxd_serialize.h`:

```c
// Write helpers
void mxd_write_u8(uint8_t **buf, uint8_t val);
void mxd_write_u16_be(uint8_t **buf, uint16_t val);
void mxd_write_u32_be(uint8_t **buf, uint32_t val);
void mxd_write_u64_be(uint8_t **buf, uint64_t val);
void mxd_write_bytes(uint8_t **buf, const uint8_t *data, size_t len);

// Read helpers
uint8_t mxd_read_u8(const uint8_t **buf);
uint16_t mxd_read_u16_be(const uint8_t **buf);
uint32_t mxd_read_u32_be(const uint8_t **buf);
uint64_t mxd_read_u64_be(const uint8_t **buf);
void mxd_read_bytes(const uint8_t **buf, uint8_t *data, size_t len);

// Database key helpers
void mxd_create_key_with_u32(uint8_t *key, size_t *key_len, 
                             const char *prefix, uint32_t value);
void mxd_create_key_with_u64(uint8_t *key, size_t *key_len,
                             const char *prefix, uint64_t value);
```

### Breaking Changes

This specification introduces breaking changes from v3:

1. **Amount representation**: Changed from `double` to `u64` base units
2. **Serialization format**: All integers now use big-endian encoding
3. **Database keys**: Integer components now use big-endian encoding

**Migration**: Requires coordinated network upgrade with hard fork. All nodes must upgrade simultaneously.

## Testing

### Serialization Tests

- Verify big-endian encoding on different architectures
- Test round-trip serialization/deserialization
- Validate cross-platform compatibility

### Amount Tests

- Test overflow detection in amount operations
- Verify precision preservation (8 decimal places)
- Test conversion between display format and base units

### Database Tests

- Verify key ordering with big-endian encoding
- Test range queries across block heights
- Validate UTXO lookups with canonical keys

## References

- RFC 1321: MD5 Message-Digest Algorithm
- RFC 3174: US Secure Hash Algorithm 1 (SHA-1)
- RFC 6234: US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)
- FIPS 202: SHA-3 Standard
- NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (Dilithium)
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)

# Bridge Transactions (v3)

## Overview

Bridge transactions enable the transfer of value between BNB Chain (BSC) and MXD Network. This document describes the v3 transaction protocol that supports bridge operations.

**Last Updated**: 2024-01-29
**Protocol Version**: v3
**Status**: Implementation Complete

## Table of Contents

1. [Architecture](#architecture)
2. [Transaction Types](#transaction-types)
3. [Bridge Transaction Flow](#bridge-transaction-flow)
4. [Security Model](#security-model)
5. [API Reference](#api-reference)
6. [Examples](#examples)
7. [Testing](#testing)

## Architecture

### High-Level Design

```
BNB Chain (BSC)                        MXD Network
┌────────────────┐                    ┌────────────────┐
│ BNBMXD Token   │                    │ Native MXD     │
│  (BEP-20)      │                    │   (UTXO)       │
└────────┬───────┘                    └────────▲───────┘
         │                                     │
         │ 1. User deposits/burns BNBMXD      │
         ▼                                     │
┌────────────────┐     Oracle/Relayer        │
│ Bridge         │──────────────────────────┘
│ Contract       │     2. Monitor event
│ (Solidity)     │     3. Submit proof
└────────────────┘     4. Process on MXD

                       ┌────────────────┐
                       │ Bridge         │
                       │ Transaction    │
                       │ Validation     │
                       └────────────────┘
```

### Components

1. **BNB Chain Bridge Contract** (Solidity)
   - Locks/burns BNBMXD tokens
   - Emits deposit/burn events
   - Verifies unlock proofs

2. **MXD Bridge Transactions** (This implementation)
   - Mints MXD (from BNB deposits)
   - Burns MXD (to unlock BNBMXD)
   - Validates proofs and prevents replays

3. **Oracle/Relayer Service** (Node.js)
   - Monitors BNB Chain events
   - Generates proofs (Merkle or signatures)
   - Submits bridge transactions to MXD

## Transaction Types

### v3 Transaction Structure

```c
typedef enum {
    MXD_TX_TYPE_REGULAR = 0,
    MXD_TX_TYPE_COINBASE = 1,
    MXD_TX_TYPE_CONTRACT_DEPLOY = 2,
    MXD_TX_TYPE_CONTRACT_CALL = 3,
    MXD_TX_TYPE_BRIDGE_MINT = 4,      // BNB → MXD
    MXD_TX_TYPE_BRIDGE_BURN = 5       // MXD → BNB
} mxd_tx_type_t;

typedef struct {
    uint32_t version;           // Always 3 for bridge transactions
    mxd_tx_type_t type;         // BRIDGE_MINT or BRIDGE_BURN
    uint32_t input_count;       // 0 for mint, >0 for burn
    uint32_t output_count;      // Always 1
    mxd_amount_t voluntary_tip; // Optional tip
    uint64_t timestamp;         // Unix timestamp
    mxd_tx_input_t *inputs;     // UTXOs being spent (burn only)
    mxd_tx_output_t *outputs;   // Recipient (mint) or burn address (burn)

    union {
        mxd_bridge_payload_t *bridge;  // Bridge-specific data
    } payload;

    uint8_t tx_hash[64];        // SHA-512 transaction hash
} mxd_transaction_v3_t;
```

### Bridge Payload

```c
typedef struct {
    uint8_t bridge_contract[64];      // Authorized bridge contract hash
    uint8_t source_chain_id[32];      // BNB Chain ID (56=mainnet, 97=testnet)
    uint8_t source_tx_hash[32];       // BNB transaction hash
    uint64_t source_block_number;     // BNB block number
    uint8_t recipient_addr[20];       // MXD recipient (mint) or BNB recipient (burn)
    mxd_amount_t amount;              // Amount to mint/burn
    uint8_t proof[1024];              // Merkle proof or multi-sig
    uint16_t proof_length;            // Proof size in bytes
} mxd_bridge_payload_t;
```

## Bridge Transaction Flow

### Mint Flow (BNB → MXD)

**Step 1**: User deposits BNBMXD on BNB Chain

```solidity
// BNB Chain contract
function deposit(uint256 amount, bytes20 mxdRecipient) external {
    require(bnbmxdToken.transferFrom(msg.sender, address(this), amount));
    emit Deposit(msg.sender, mxdRecipient, amount, block.timestamp);
}
```

**Step 2**: Oracle detects deposit event

```javascript
// Oracle service monitors BNB Chain
bridgeContract.events.Deposit({ fromBlock: lastBlock })
.on('data', async (event) => {
    // Generate proof and submit to MXD
});
```

**Step 3**: Oracle creates bridge mint transaction

```c
mxd_bridge_payload_t payload;
memset(&payload, 0, sizeof(payload));

// Set bridge contract (must be pre-authorized)
memcpy(payload.bridge_contract, authorized_bridge_hash, 64);

// Set source chain ID (BNB testnet = 97)
uint32_t chain_id = 97;
memcpy(payload.source_chain_id, &chain_id, sizeof(uint32_t));

// Set source transaction
memcpy(payload.source_tx_hash, bnb_tx_hash, 32);
payload.source_block_number = bnb_block_number;

// Set recipient
memcpy(payload.recipient_addr, mxd_recipient, 20);

// Set amount
payload.amount = 100000000000;  // 100 MXD in base units

// Add proof (Merkle proof or multi-sig)
payload.proof_length = generate_proof(payload.proof, ...);

// Create transaction
mxd_transaction_v3_t tx;
mxd_create_bridge_mint_tx(&tx, &payload);
```

**Step 4**: MXD node validates and applies

```c
// Validation checks:
// 1. Bridge contract authorized?
if (!mxd_is_bridge_contract_authorized(payload.bridge_contract)) {
    return -1;
}

// 2. Chain ID supported? (56 or 97)
uint32_t chain_id;
memcpy(&chain_id, payload.source_chain_id, sizeof(uint32_t));
if (chain_id != 56 && chain_id != 97) {
    return -1;
}

// 3. Replay attack? (already processed?)
if (mxd_is_bridge_tx_processed(payload.source_tx_hash)) {
    return -1;  // Duplicate!
}

// 4. Proof valid?
// (Implementation depends on proof type - Merkle or multi-sig)

// 5. Amount positive?
if (payload.amount == 0) {
    return -1;
}

// All checks passed - mint MXD!
```

**Step 5**: MXD minted to recipient

```c
// Mark as processed (prevent replay)
mxd_mark_bridge_tx_processed(&payload, tx_hash, block_index);

// Apply transaction (creates UTXO)
mxd_apply_transaction_to_utxo(&tx);
```

### Burn Flow (MXD → BNB)

**Step 1**: User creates bridge burn transaction

```c
uint8_t sender_addr[20] = {...};
mxd_amount_t burn_amount = 50000000000;  // 50 MXD
uint8_t bridge_contract[64] = {...};
uint32_t dest_chain_id = 97;  // BNB testnet
uint8_t bnb_recipient[20] = {...};

mxd_transaction_v3_t tx;
mxd_create_bridge_burn_tx(&tx, sender_addr, burn_amount,
                          bridge_contract, dest_chain_id, bnb_recipient);

// Add inputs (UTXOs to spend)
mxd_add_tx_input(&tx, prev_tx_hash, output_index, algo_id, public_key, pubkey_len);

// Sign inputs
mxd_sign_tx_input(&tx, 0, algo_id, private_key);

// Submit to MXD network
```

**Step 2**: MXD node validates and burns

```c
// Validation:
// - Bridge contract authorized
// - Inputs valid (UTXO exists, signatures correct)
// - Total input >= burn amount + fee
// - Output is to burn address (0x00...00)

// Burn succeeds - MXD sent to zero address (destroyed)
```

**Step 3**: Oracle detects burn event

```javascript
// Oracle monitors MXD blockchain
const response = await fetch(`${mxdNodeUrl}/contract/events?event=BurnForUnlock`);
const events = await response.json();

for (const event of events) {
    // Process burn event
}
```

**Step 4**: Oracle unlocks BNBMXD on BNB Chain

```solidity
// BNB Chain contract
function withdraw(
    address recipient,
    uint256 amount,
    bytes32 mxdTxHash,
    bytes calldata signature
) external onlyOperator {
    require(!processedMXDTxs[mxdTxHash], "Already processed");
    require(verifySignature(messageHash, signature), "Invalid signature");

    processedMXDTxs[mxdTxHash] = true;
    require(bnbmxdToken.transfer(recipient, amount), "Transfer failed");
}
```

## Security Model

### 1. Authorization

**Bridge Contract Whitelist**:
- Only pre-authorized bridge contracts can mint MXD
- Authorization stored in database with key: `bridge_auth:<contract_hash>`
- Value: `"1"` (authorized) or `"0"` (revoked)

**Management Tool**:
```bash
# Authorize bridge contract
./manage_bridge_auth --add abc123...def456

# Revoke authorization
./manage_bridge_auth --revoke abc123...def456

# List all authorized contracts
./manage_bridge_auth --list

# Check if contract is authorized
./manage_bridge_auth --check abc123...def456
```

### 2. Replay Protection

**Mint Transactions**:
- Each BNB transaction can only be processed once
- Tracked by `source_tx_hash` in database: `bridge_tx:<source_tx_hash>`
- Attempting to process same transaction twice fails validation

**Burn Transactions**:
- Oracle tracks processed MXD burn transactions
- BNB contract marks `mxdTxHash` as processed
- Double-spend prevented by UTXO model

### 3. Chain ID Validation

Only supported chains allowed:
- **56**: BNB Chain Mainnet
- **97**: BNB Chain Testnet

Transactions from other chains are rejected.

### 4. Amount Validation

**Mint**:
- Amount must be positive (`> 0`)
- No maximum limit (set by bridge contract on BNB side)

**Burn**:
- Amount must be positive
- Total inputs must cover `burn_amount + voluntary_tip`
- Excess goes to change address (standard UTXO model)

### 5. Proof Verification

**Current Implementation**: Placeholder
- Proof stored in `proof[1024]` field
- Actual verification depends on proof type:
  - **Merkle Proof**: Verify against BNB block receipt tree
  - **Multi-Signature**: Verify threshold signatures (e.g., 3-of-5 oracles)
  - **Light Client**: SPV proof from BNB Chain

**TODO**: Implement actual proof verification in Phase 5 (Oracle/Relayer).

### 6. Access Control

**Mint Transactions**:
- Only authorized oracles can submit (enforced by bridge contract authorization)
- No user can directly create mint transactions

**Burn Transactions**:
- Any user can burn their own MXD
- Must prove ownership via UTXO signatures

## API Reference

### Creating Bridge Transactions

#### `mxd_create_bridge_mint_tx`

```c
int mxd_create_bridge_mint_tx(mxd_transaction_v3_t *tx,
                               const mxd_bridge_payload_t *payload);
```

**Parameters**:
- `tx`: Output transaction structure (must be uninitialized)
- `payload`: Bridge payload with all required fields

**Returns**: 0 on success, -1 on error

**Example**:
```c
mxd_bridge_payload_t payload;
// ... fill payload ...

mxd_transaction_v3_t tx;
if (mxd_create_bridge_mint_tx(&tx, &payload) == 0) {
    // Transaction created successfully
    mxd_free_transaction_v3(&tx);
}
```

#### `mxd_create_bridge_burn_tx`

```c
int mxd_create_bridge_burn_tx(mxd_transaction_v3_t *tx,
                               const uint8_t sender_addr[20],
                               mxd_amount_t burn_amount,
                               const uint8_t bridge_contract[64],
                               uint32_t dest_chain_id,
                               const uint8_t dest_recipient[20]);
```

**Parameters**:
- `tx`: Output transaction structure
- `sender_addr`: MXD sender address (for reference, actual spending proven by inputs)
- `burn_amount`: Amount of MXD to burn
- `bridge_contract`: Authorized bridge contract hash
- `dest_chain_id`: Destination chain (56 or 97)
- `dest_recipient`: BNB Chain recipient address

**Returns**: 0 on success, -1 on error

**Example**:
```c
uint8_t sender[20] = {...};
uint8_t bridge[64] = {...};
uint8_t bnb_recipient[20] = {...};

mxd_transaction_v3_t tx;
if (mxd_create_bridge_burn_tx(&tx, sender, 50000000000, bridge, 97, bnb_recipient) == 0) {
    // Add inputs and sign
    mxd_add_tx_input(&tx, ...);
    mxd_sign_tx_input(&tx, 0, ...);

    mxd_free_transaction_v3(&tx);
}
```

### Validating Bridge Transactions

#### `mxd_validate_bridge_mint_tx`

```c
int mxd_validate_bridge_mint_tx(const mxd_transaction_v3_t *tx);
```

**Validation Checks**:
1. Version = 3, Type = BRIDGE_MINT
2. Bridge contract authorized
3. Chain ID supported (56 or 97)
4. Source transaction not already processed (replay protection)
5. Amount > 0
6. Recipient not zero address
7. Proof present (length > 0 and <= 1024)
8. Exactly one output matching payload
9. No inputs (mint creates new coins)

**Returns**: 0 if valid, -1 if invalid

#### `mxd_validate_bridge_burn_tx`

```c
int mxd_validate_bridge_burn_tx(const mxd_transaction_v3_t *tx);
```

**Validation Checks**:
1. Version = 3, Type = BRIDGE_BURN
2. Bridge contract authorized
3. Destination chain ID supported
4. Amount > 0
5. Recipient not zero address
6. Exactly one output to burn address (0x00...00)
7. At least one input
8. Inputs valid (UTXOs exist, signatures correct)
9. Total input >= burn amount + fee

**Returns**: 0 if valid, -1 if invalid

#### `mxd_validate_transaction_v3`

```c
int mxd_validate_transaction_v3(const mxd_transaction_v3_t *tx);
```

General v3 transaction validation - dispatches to type-specific validators.

### Replay Protection

#### `mxd_is_bridge_tx_processed`

```c
int mxd_is_bridge_tx_processed(const uint8_t source_tx_hash[32]);
```

Check if a bridge mint transaction has already been processed.

**Returns**: 1 if processed, 0 if not

#### `mxd_mark_bridge_tx_processed`

```c
int mxd_mark_bridge_tx_processed(const mxd_bridge_payload_t *payload,
                                  const uint8_t mxd_tx_hash[64],
                                  uint32_t block_index);
```

Mark a bridge transaction as processed (called after successful mint).

**Returns**: 0 on success, -1 on error

### Authorization

#### `mxd_is_bridge_contract_authorized`

```c
int mxd_is_bridge_contract_authorized(const uint8_t contract_hash[64]);
```

Check if a bridge contract is authorized.

**Returns**: 1 if authorized, 0 if not

### Hashing

#### `mxd_calculate_tx_hash_v3`

```c
int mxd_calculate_tx_hash_v3(const mxd_transaction_v3_t *tx, uint8_t hash[64]);
```

Calculate SHA-512 hash of v3 transaction.

**Returns**: 0 on success, -1 on error

### Memory Management

#### `mxd_free_transaction_v3`

```c
void mxd_free_transaction_v3(mxd_transaction_v3_t *tx);
```

Free all dynamically allocated memory in v3 transaction.

## Examples

### Example 1: Authorize Bridge Contract

```bash
# Generate bridge contract hash (SHA-512 of WASM bytecode)
sha512sum bridge.wasm
# Output: abc123...def456

# Authorize the contract
./manage_bridge_auth --add abc123...def456

# Verify authorization
./manage_bridge_auth --check abc123...def456
# Output: Contract abc123...def456: AUTHORIZED
```

### Example 2: Mint MXD (Oracle Code)

```c
// Oracle detects BNB deposit event
void process_bnb_deposit(BNBDepositEvent *event) {
    mxd_bridge_payload_t payload;
    memset(&payload, 0, sizeof(payload));

    // Set authorized bridge contract
    memcpy(payload.bridge_contract, AUTHORIZED_BRIDGE_HASH, 64);

    // Set source chain (BNB testnet)
    uint32_t chain_id = 97;
    memcpy(payload.source_chain_id, &chain_id, sizeof(uint32_t));

    // Set source transaction
    memcpy(payload.source_tx_hash, event->tx_hash, 32);
    payload.source_block_number = event->block_number;

    // Set recipient
    memcpy(payload.recipient_addr, event->mxd_recipient, 20);

    // Set amount
    payload.amount = event->amount;

    // Generate Merkle proof (or multi-sig)
    payload.proof_length = generate_merkle_proof(payload.proof, event);

    // Create mint transaction
    mxd_transaction_v3_t tx;
    if (mxd_create_bridge_mint_tx(&tx, &payload) != 0) {
        fprintf(stderr, "Failed to create bridge mint tx\n");
        return;
    }

    // Calculate transaction hash
    uint8_t tx_hash[64];
    mxd_calculate_tx_hash_v3(&tx, tx_hash);
    memcpy(tx.tx_hash, tx_hash, 64);

    // Submit to MXD network
    submit_transaction_to_mxd_network(&tx);

    mxd_free_transaction_v3(&tx);
}
```

### Example 3: Burn MXD (User Code)

```c
// User burns MXD to unlock BNBMXD on BNB Chain
void burn_mxd_for_bnbmxd(uint8_t *sender_addr, mxd_amount_t amount,
                         uint8_t *bnb_recipient, uint8_t *private_key) {
    mxd_transaction_v3_t tx;

    // Create burn transaction
    if (mxd_create_bridge_burn_tx(&tx, sender_addr, amount,
                                  AUTHORIZED_BRIDGE_HASH, 97, bnb_recipient) != 0) {
        fprintf(stderr, "Failed to create burn tx\n");
        return;
    }

    // Find UTXOs to spend
    // (Simplified - real implementation would query UTXO database)
    uint8_t prev_tx_hash[64];
    uint32_t output_index = 0;
    uint8_t public_key[32];
    // ... get UTXO details ...

    // Add input
    mxd_add_tx_input(&tx, prev_tx_hash, output_index, 1, public_key, 32);

    // Sign input
    mxd_sign_tx_input(&tx, 0, 1, private_key);

    // Calculate transaction hash
    uint8_t tx_hash[64];
    mxd_calculate_tx_hash_v3(&tx, tx_hash);
    memcpy(tx.tx_hash, tx_hash, 64);

    // Submit to MXD network
    submit_transaction_to_mxd_network(&tx);

    mxd_free_transaction_v3(&tx);
}
```

## Testing

### Running Tests

```bash
cd F:\Proyectos\mxdlib\tests
gcc -o test_bridge_transactions test_bridge_transactions.c \
    ../src/mxd_transaction.c \
    ../src/mxd_crypto.c \
    ../src/mxd_serialize.c \
    ../src/mxd_logging.c \
    -I../include \
    -lrocksdb -lsodium -lcrypto

./test_bridge_transactions
```

### Test Coverage

The test suite covers:

1. ✅ Create bridge mint transaction
2. ✅ Validate bridge mint transaction
3. ✅ Reject unauthorized bridge contract
4. ✅ Replay attack prevention
5. ✅ Invalid chain ID rejection
6. ✅ Zero amount rejection
7. ✅ Create bridge burn transaction
8. ✅ Calculate v3 transaction hash
9. ✅ Validate v3 transaction dispatch
10. ✅ Free v3 transaction

### Integration Tests

See `tests/integration/test_bridge_flow.sh` for end-to-end bridge tests that:
- Deploy BNB contract
- Deposit BNBMXD
- Oracle generates mint transaction
- MXD network mints
- User burns MXD
- Oracle unlocks BNBMXD

## Troubleshooting

### Common Issues

**Error: "Bridge contract not authorized"**
- **Cause**: Attempting to use a bridge contract that hasn't been authorized
- **Solution**: Use `manage_bridge_auth --add <hash>` to authorize

**Error: "Bridge transaction already processed (replay attack)"**
- **Cause**: Attempting to process the same BNB transaction twice
- **Solution**: Check `source_tx_hash` is unique

**Error**: "Unsupported source chain ID"**
- **Cause**: Using a chain ID other than 56 or 97
- **Solution**: Only BNB mainnet (56) and testnet (97) are supported

**Error**: "Insufficient input for bridge burn"**
- **Cause**: Total UTXO inputs < burn amount + fee
- **Solution**: Add more inputs or reduce burn amount

## Next Steps

- **Phase 3**: Develop MXD bridge contract in Rust/WASM
- **Phase 4**: Develop BNB Chain smart contracts (Solidity)
- **Phase 5**: Implement oracle/relayer service
- **Phase 6**: Comprehensive testing and security audit
- **Phase 7**: Deployment to testnet and mainnet

---

**Questions?** Contact dev@mxdnetwork.com

# Smart Contracts Roadmap

## Current Status

Smart contracts in MXD are currently **disabled by default** as the implementation is incomplete and not production-ready. The basic WASM3 runtime integration exists, but critical features required for secure and deterministic contract execution are missing.

## Why Smart Contracts Are Disabled

The current implementation has the following gaps that make it unsafe for production use:

1. **No Gas Metering**: The system lacks proper instruction-level gas counting, making it vulnerable to infinite loops and resource exhaustion attacks.
2. **Incomplete Storage**: Contract storage uses a simple in-memory key-value store without Merkle tree verification or persistence to the blockchain database.
3. **No State Root**: Block headers don't include contract state roots, preventing state verification across nodes.
4. **Limited Testing**: The contract system lacks comprehensive security and consensus testing.
5. **No Determinism Guarantees**: Cross-platform determinism for contract execution has not been verified.

## Enabling Smart Contracts (For Development Only)

Smart contracts can be enabled for development and testing purposes by setting the configuration flag:

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

**WARNING**: Do not enable smart contracts on production networks or mainnet. The incomplete implementation poses security and consensus risks.

## Future Implementation Plan

### Phase 1: Gas Metering (2-3 weeks)

**Goal**: Implement instruction-level gas counting to prevent resource exhaustion.

**Tasks**:
- Integrate WASM3 instruction hooks for gas counting
- Implement per-instruction gas costs based on computational complexity
- Add gas limit enforcement with graceful termination
- Test gas metering with various contract patterns (loops, recursion, memory operations)
- Benchmark gas costs to ensure reasonable pricing

**Deliverables**:
- `src/mxd_gas_metering.c` - Gas counting implementation
- Gas cost table for WASM instructions
- Unit tests for gas metering accuracy
- Performance benchmarks

### Phase 2: Persistent Storage with Merkle Trees (3-4 weeks)

**Goal**: Replace in-memory storage with Merkleized persistent storage backed by RocksDB.

**Tasks**:
- Design contract storage schema in RocksDB (separate column family)
- Implement Merkle Patricia Trie for contract state
- Add state root calculation and verification
- Implement storage rent/fees to prevent state bloat
- Add garbage collection for expired contract storage
- Migrate existing storage API to new backend

**Deliverables**:
- `src/mxd_contract_storage.c` - Merkleized storage implementation
- `src/mxd_merkle_trie.c` - Merkle Patricia Trie utilities
- Storage migration tools
- State root verification tests

### Phase 3: State Root Integration (1-2 weeks)

**Goal**: Add contract state roots to block headers for consensus verification.

**Tasks**:
- Extend block header structure to include `contracts_state_root` field
- Update block validation to verify state root consistency
- Implement state root calculation during block creation
- Add state root to block serialization (requires protocol version bump)
- Update fork resolution to consider state root mismatches

**Deliverables**:
- Updated `include/mxd_blockchain.h` with state root field
- State root validation in block processing
- Protocol version bump to v5
- Migration guide for state root activation

### Phase 4: Determinism and Cross-Platform Testing (2-3 weeks)

**Goal**: Ensure contract execution produces identical results across all platforms.

**Tasks**:
- Implement deterministic floating-point handling (if needed)
- Add cross-platform test suite (x86_64, ARM, 32-bit, 64-bit)
- Create golden test vectors for contract execution
- Test WASM3 behavior consistency across compilers (GCC, Clang, MSVC)
- Implement contract execution replay for debugging
- Add consensus monitoring for state divergence

**Deliverables**:
- Cross-platform CI matrix for contract tests
- Golden test vectors repository
- Determinism verification tools
- Consensus monitoring dashboard

### Phase 5: Security Hardening (2-3 weeks)

**Goal**: Harden the contract system against attacks and edge cases.

**Tasks**:
- Implement contract size limits and validation
- Add memory safety checks (bounds checking, stack overflow protection)
- Implement contract call depth limits
- Add reentrancy protection
- Implement contract upgrade mechanisms
- Security audit of contract execution path
- Fuzz testing with AFL/libFuzzer

**Deliverables**:
- Security test suite
- Fuzzing harness
- Security audit report
- Contract security best practices documentation

### Phase 6: Advanced Features (4-6 weeks)

**Goal**: Add advanced contract capabilities for real-world use cases.

**Tasks**:
- Implement contract-to-contract calls
- Add event emission and logging
- Implement contract factories
- Add precompiled contracts for common operations (crypto, hashing)
- Implement contract verification and source code registry
- Add contract debugging tools
- Create contract development SDK

**Deliverables**:
- Contract SDK with examples
- Precompiled contracts library
- Contract explorer/debugger
- Developer documentation

## Activation Strategy

Once all phases are complete, smart contracts will be activated through a coordinated hard fork:

1. **Testnet Activation**: Deploy to testnet with 2-week observation period
2. **Security Review**: External security audit of complete implementation
3. **Mainnet Preparation**: Set activation height 4-6 weeks in advance
4. **Operator Communication**: Release upgrade guide and migration tools
5. **Mainnet Activation**: Enable contracts at predetermined block height

## Estimated Timeline

- **Phase 1-2**: 5-7 weeks (Gas metering + Storage)
- **Phase 3-4**: 3-5 weeks (State root + Determinism)
- **Phase 5-6**: 6-9 weeks (Security + Advanced features)
- **Testing & Audit**: 4-6 weeks
- **Total**: 18-27 weeks (4.5-6.5 months)

## Current API

The following smart contract APIs exist but are disabled by default:

- `mxd_init_contracts()` - Initialize WASM3 runtime
- `mxd_deploy_contract()` - Deploy contract bytecode
- `mxd_execute_contract()` - Execute contract with input
- `mxd_validate_state_transition()` - Validate state changes
- `mxd_calculate_gas()` - Calculate gas cost (stub)
- `mxd_get_contract_storage()` - Get storage value
- `mxd_set_contract_storage()` - Set storage value
- `mxd_free_contract_state()` - Free contract resources

All APIs return error when contracts are disabled.

## Contributing

If you're interested in contributing to smart contract development:

1. Review this roadmap and choose a phase to work on
2. Open an issue to discuss your approach
3. Submit PRs with comprehensive tests
4. Ensure cross-platform compatibility
5. Follow security best practices

For questions or discussions, please open an issue on GitHub.

## References

- [WASM3 Documentation](https://github.com/wasm3/wasm3)
- [WebAssembly Specification](https://webassembly.github.io/spec/)
- [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf) (for gas metering inspiration)
- [Merkle Patricia Trie](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/)

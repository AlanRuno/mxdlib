# Cross-Platform Determinism Guide

## Overview

MXD Network smart contracts **MUST** produce identical results across all platforms. This is critical for blockchain consensus - any difference in execution results would cause network forks.

## Supported Platforms

Smart contracts are tested and guaranteed deterministic on:

| Platform | Architecture | Compilers | Status |
|----------|--------------|-----------|--------|
| **Linux** | x86_64 | GCC 11+, Clang 14+ | ✅ Verified |
| **Linux** | ARM64 | GCC 11+, Clang 14+ | ✅ Verified |
| **macOS** | ARM64 (M1/M2) | Clang 14+ | ✅ Verified |
| **macOS** | x86_64 (Intel) | Clang 14+ | ✅ Verified |
| **Windows** | x86_64 | MSVC 2022, MinGW-w64 | ✅ Verified |

## Determinism Requirements

### Allowed Operations

✅ **Safe for blockchain consensus:**

- **Integer arithmetic** (i32, i64):
  - Addition, subtraction, multiplication
  - Division (signed and unsigned)
  - Remainder operations
  - Bitwise operations (AND, OR, XOR, NOT)
  - Shifts and rotations
  - Comparisons

- **Memory operations**:
  - Load/store (fixed sizes)
  - Fixed-size memory allocation
  - Deterministic addressing

- **Control flow**:
  - Conditional branches
  - Loops (with gas limits)
  - Function calls

- **Cryptographic operations**:
  - SHA-256, SHA-512
  - Ed25519, Dilithium5 signatures
  - RIPEMD-160

### Banned Operations

❌ **Causes non-determinism:**

- **Floating-point operations** (f32, f64):
  ```wasm
  f32.add, f32.sub, f32.mul, f32.div  ; BANNED
  f64.add, f64.sub, f64.mul, f64.div  ; BANNED
  ```
  **Reason**: Different rounding modes across platforms

- **Dynamic memory growth**:
  ```wasm
  memory.grow  ; BANNED
  ```
  **Reason**: Platform-specific allocation behavior

- **Non-deterministic imports**:
  ```wasm
  (import "env" "random")      ; BANNED
  (import "env" "current_time"); BANNED (use get_timestamp instead)
  ```

## Why Floating-Point is Banned

Floating-point operations are **fundamentally non-deterministic** across platforms:

### Problem 1: Rounding Modes

Different platforms may use different IEEE 754 rounding modes:
- Round to nearest (default)
- Round toward zero
- Round toward +∞
- Round toward -∞

Example that produces different results:
```c
// On some platforms: 0.3
// On others: 0.30000000000000004
float result = 0.1f + 0.2f;
```

### Problem 2: Extended Precision

Intel x86/x64 processors have 80-bit extended precision registers:
- Intermediate calculations may use 80 bits
- Final result truncated to 64 bits
- Different timing = different results

ARM processors use strict 64-bit precision:
- No extended precision
- Different results than x86

### Problem 3: Denormal Numbers

Handling of denormal (subnormal) numbers varies:
- Some CPUs flush denormals to zero (DAZ mode)
- Others preserve them
- Performance differences lead to different optimizations

### Solution: Integer-Only Arithmetic

Use **fixed-point arithmetic** instead:

```rust
// WRONG: Floating-point (non-deterministic)
fn calculate_fee_wrong(amount: f64) -> f64 {
    amount * 0.01  // 1% fee - different results on different platforms!
}

// CORRECT: Fixed-point with integers (deterministic)
fn calculate_fee_correct(amount: u64) -> u64 {
    amount / 100  // 1% fee - identical everywhere!
}
```

## Platform-Specific Considerations

### Integer Size Consistency

C/C++ integer sizes vary by platform:

| Type | Size (32-bit) | Size (64-bit) |
|------|---------------|---------------|
| `int` | 4 bytes | 4 bytes |
| `long` | 4 bytes | **8 bytes** (Linux/macOS)<br>**4 bytes** (Windows) |
| `long long` | 8 bytes | 8 bytes |
| `size_t` | 4 bytes | 8 bytes |

**Solution**: Always use fixed-size types in WASM:
- `i32` = 32-bit signed integer (guaranteed)
- `i64` = 64-bit signed integer (guaranteed)
- `u32` = 32-bit unsigned integer
- `u64` = 64-bit unsigned integer

### Endianness

WASM uses **little-endian** regardless of host platform:
- x86/x64: Little-endian (native)
- ARM: Bi-endian (configured as little-endian for WASM)
- No conversion needed in WASM bytecode

### Division Behavior

Integer division is **deterministic** but platform-dependent for edge cases:

```wasm
;; Signed division of minimum value by -1
i32.const -2147483648  ;; i32::MIN
i32.const -1
i32.div_s
;; Trap on overflow (all platforms must trap identically)
```

**Requirement**: All platforms must trap on division overflow.

### Alignment

Memory access alignment requirements:
- **x86/x64**: Unaligned access allowed (slower)
- **ARM**: Unaligned access may trap
- **WASM**: Alignment hints are optional, all access must work

**Solution**: WASM3 handles alignment automatically.

## Testing for Determinism

### Automated Testing

Run on all platforms:
```bash
cd mxdlib/tests
./test_cross_platform_determinism
```

Expected output includes:
```
Full SHA-512 hash for verification:
a1b2c3d4e5f6...
```

**All platforms MUST produce identical hash.**

### Manual Verification

1. **Deploy test contract on all platforms**:
   ```bash
   mxd-cli contract deploy --wasm test_contract.wasm
   ```

2. **Execute with identical input**:
   ```bash
   mxd-cli contract call <hash> --input 0x1234
   ```

3. **Compare output hashes**:
   ```bash
   sha512sum output_linux.bin
   sha512sum output_macos.bin
   sha512sum output_windows.bin
   # All must match!
   ```

### CI/CD Integration

GitHub Actions automatically runs determinism tests on every commit:
- Linux x64 (GCC, Clang)
- Linux ARM64
- macOS ARM64
- Windows x64 (MSVC, MinGW)

Any hash mismatch **fails the build**.

## Writing Deterministic Contracts

### Do's ✅

```rust
// Use integer arithmetic
fn calculate_reward(stake: u64, rate: u64) -> u64 {
    stake * rate / 10000  // Basis points
}

// Use deterministic storage
fn get_balance(addr: &[u8; 20]) -> u64 {
    storage::get("balances", addr).unwrap_or(0)
}

// Use blockchain-provided randomness
fn get_random() -> u64 {
    // Use block hash as entropy source
    let block_hash = get_block_hash();
    u64::from_le_bytes(block_hash[0..8].try_into().unwrap())
}
```

### Don'ts ❌

```rust
// NO floating-point!
fn calculate_interest_wrong(principal: f64) -> f64 {
    principal * 1.05  // WRONG - non-deterministic!
}

// NO system calls!
fn get_timestamp_wrong() -> u64 {
    std::time::SystemTime::now()  // WRONG - different on each node!
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// NO external randomness!
fn roll_dice_wrong() -> u32 {
    rand::random::<u32>() % 6 + 1  // WRONG - non-deterministic!
}
```

## Validation Process

Every contract goes through validation before deployment:

### 1. WASM Bytecode Analysis

```c
int mxd_validate_wasm_determinism(const uint8_t *bytecode, size_t size,
                                   mxd_wasm_validation_result_t *result);
```

Checks:
- ✅ Valid WASM magic number
- ✅ Supported WASM version
- ✅ No floating-point instructions
- ✅ No `memory.grow`
- ✅ Only approved imports
- ✅ Size limits (max 1MB)

### 2. Import Validation

Allowed imports from `env` module:
- `get_storage(key) -> value`
- `set_storage(key, value)`
- `get_sender() -> address`
- `get_block_height() -> u64`
- `get_timestamp() -> u64`
- `sha256(data) -> hash`
- `sha512(data) -> hash`
- `verify_signature(msg, sig, pubkey) -> bool`

Any other import is **rejected**.

### 3. Gas Metering

All operations are metered:
- Prevents infinite loops
- Ensures bounded execution time
- Deterministic gas costs across platforms

## Debugging Non-Determinism

If tests fail with hash mismatch:

### Step 1: Identify Platform

```bash
# Compare outputs
diff output_linux.bin output_macos.bin
diff output_linux.bin output_windows.bin
```

### Step 2: Binary Analysis

```bash
# Hexdump comparison
hexdump -C output_linux.bin > linux.hex
hexdump -C output_windows.bin > windows.hex
diff linux.hex windows.hex
```

### Step 3: Trace Execution

```bash
# Enable WASM3 debug tracing
MXD_WASM_TRACE=1 ./test_contract
```

### Step 4: Common Culprits

1. **Uninitialized memory**: Always zero-initialize
2. **Platform-specific types**: Use `i32`/`i64`, not `long`
3. **Alignment issues**: Let WASM3 handle it
4. **Import differences**: Verify all imports are deterministic

## Performance Considerations

### Integer vs Floating-Point

**Myth**: "Floating-point is faster"

**Reality**: On modern CPUs, integer and FP performance is similar:
- x86: Both ~1 cycle latency for basic ops
- ARM: Integer often faster (NEON)
- Division: Integer faster on most platforms

### Fixed-Point Arithmetic

For decimal calculations, use fixed-point:

```rust
// Store amount as "cents" (2 decimal places)
type Amount = u64;  // In cents

fn from_dollars(dollars: u64) -> Amount {
    dollars * 100
}

fn to_dollars(amount: Amount) -> u64 {
    amount / 100
}

fn add_amounts(a: Amount, b: Amount) -> Amount {
    a + b  // Deterministic!
}

// For more precision (e.g., 8 decimals like Bitcoin)
const SATOSHI: u64 = 100_000_000;

fn from_btc(btc: u64) -> u64 {
    btc * SATOSHI
}
```

### Lookup Tables

Precomputed values are deterministic:

```rust
// Deterministic logarithm via lookup table
const LOG_TABLE: [u64; 256] = [/* precomputed */];

fn fast_log(x: u8) -> u64 {
    LOG_TABLE[x as usize]
}
```

## Future Enhancements

Planned additions to determinism framework:

1. **Formal Verification**:
   - Prove contracts are deterministic mathematically
   - Use tools like KLEE or VeriFast

2. **Additional Platforms**:
   - RISC-V
   - MIPS
   - PowerPC

3. **Enhanced Validation**:
   - Data flow analysis
   - Symbolic execution
   - Fuzz testing

4. **Performance Monitoring**:
   - Track execution time variance
   - Alert on platform-specific slowdowns

## Resources

- [WASM Specification](https://webassembly.github.io/spec/)
- [IEEE 754 Floating-Point Standard](https://en.wikipedia.org/wiki/IEEE_754)
- [Fixed-Point Arithmetic](https://en.wikipedia.org/wiki/Fixed-point_arithmetic)
- [MXD Smart Contract Guide](./SMART_CONTRACTS.md)

## Support

If you encounter determinism issues:

1. **Check CI logs**: GitHub Actions shows platform-specific results
2. **Run local tests**: `./test_cross_platform_determinism`
3. **Report issues**: Include platform info and contract bytecode
4. **Discord**: #smart-contracts channel
5. **Email**: dev@mxdnetwork.com

---

**Remember**: Determinism is NOT optional for blockchain smart contracts. Any non-deterministic behavior will cause network forks and consensus failures. When in doubt, ask!

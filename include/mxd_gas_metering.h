#ifndef MXD_GAS_METERING_H
#define MXD_GAS_METERING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/**
 * Calculate gas cost by analyzing WASM bytecode
 * 
 * This function parses the WASM binary format and calculates gas costs
 * based on instruction types and counts. Different instruction categories
 * have different gas costs based on their computational complexity:
 * 
 * - Basic operations (local.get, drop): 1 gas
 * - Arithmetic operations (add, sub, mul): 2 gas
 * - Division operations: 10 gas
 * - Memory operations: 3 gas
 * - Control flow (br, if): 5 gas
 * - Function calls: 10 gas
 * - Memory grow: 1000 gas
 * 
 * @param code Pointer to WASM bytecode
 * @param code_size Size of bytecode in bytes
 * @return Total gas cost for executing the contract
 */
uint64_t mxd_calculate_gas_from_bytecode(const uint8_t *code, size_t code_size);

#ifdef __cplusplus
}
#endif

#endif // MXD_GAS_METERING_H

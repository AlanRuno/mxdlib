#include "../include/mxd_wasm_validator.h"
#include "../include/mxd_logging.h"
#include <string.h>
#include <stdio.h>

// WASM magic number and version
#define WASM_MAGIC_0 0x00
#define WASM_MAGIC_1 0x61  // 'a'
#define WASM_MAGIC_2 0x73  // 's'
#define WASM_MAGIC_3 0x6D  // 'm'
#define WASM_VERSION 0x01

// WASM section IDs
#define WASM_SECTION_IMPORT 2
#define WASM_SECTION_CODE 10

// Banned instructions for determinism
static const mxd_banned_instruction_t BANNED_INSTRUCTIONS[] = {
    // Floating-point operations (f32)
    {0x43, "f32.const", "Floating-point operations are non-deterministic"},
    {0x8B, "f32.add", "Floating-point operations are non-deterministic"},
    {0x8C, "f32.sub", "Floating-point operations are non-deterministic"},
    {0x8D, "f32.mul", "Floating-point operations are non-deterministic"},
    {0x8E, "f32.div", "Floating-point operations are non-deterministic"},
    {0x8F, "f32.min", "Floating-point operations are non-deterministic"},
    {0x90, "f32.max", "Floating-point operations are non-deterministic"},
    {0x91, "f32.copysign", "Floating-point operations are non-deterministic"},
    {0x92, "f32.abs", "Floating-point operations are non-deterministic"},
    {0x93, "f32.neg", "Floating-point operations are non-deterministic"},
    {0x94, "f32.ceil", "Floating-point operations are non-deterministic"},
    {0x95, "f32.floor", "Floating-point operations are non-deterministic"},
    {0x96, "f32.trunc", "Floating-point operations are non-deterministic"},
    {0x97, "f32.nearest", "Floating-point operations are non-deterministic"},
    {0x98, "f32.sqrt", "Floating-point operations are non-deterministic"},

    // Floating-point operations (f64)
    {0x44, "f64.const", "Floating-point operations are non-deterministic"},
    {0x99, "f64.add", "Floating-point operations are non-deterministic"},
    {0x9A, "f64.sub", "Floating-point operations are non-deterministic"},
    {0x9B, "f64.mul", "Floating-point operations are non-deterministic"},
    {0x9C, "f64.div", "Floating-point operations are non-deterministic"},
    {0x9D, "f64.min", "Floating-point operations are non-deterministic"},
    {0x9E, "f64.max", "Floating-point operations are non-deterministic"},
    {0x9F, "f64.copysign", "Floating-point operations are non-deterministic"},
    {0xA0, "f64.abs", "Floating-point operations are non-deterministic"},
    {0xA1, "f64.neg", "Floating-point operations are non-deterministic"},
    {0xA2, "f64.ceil", "Floating-point operations are non-deterministic"},
    {0xA3, "f64.floor", "Floating-point operations are non-deterministic"},
    {0xA4, "f64.trunc", "Floating-point operations are non-deterministic"},
    {0xA5, "f64.nearest", "Floating-point operations are non-deterministic"},
    {0xA6, "f64.sqrt", "Floating-point operations are non-deterministic"},

    // Memory grow (non-deterministic allocation)
    {0x40, "memory.grow", "Dynamic memory growth is non-deterministic"},

    // Floating-point comparisons
    {0x5B, "f32.eq", "Floating-point operations are non-deterministic"},
    {0x5C, "f32.ne", "Floating-point operations are non-deterministic"},
    {0x5D, "f32.lt", "Floating-point operations are non-deterministic"},
    {0x5E, "f32.gt", "Floating-point operations are non-deterministic"},
    {0x5F, "f32.le", "Floating-point operations are non-deterministic"},
    {0x60, "f32.ge", "Floating-point operations are non-deterministic"},
    {0x61, "f64.eq", "Floating-point operations are non-deterministic"},
    {0x62, "f64.ne", "Floating-point operations are non-deterministic"},
    {0x63, "f64.lt", "Floating-point operations are non-deterministic"},
    {0x64, "f64.gt", "Floating-point operations are non-deterministic"},
    {0x65, "f64.le", "Floating-point operations are non-deterministic"},
    {0x66, "f64.ge", "Floating-point operations are non-deterministic"},

    // Floating-point conversions
    {0xA7, "i32.trunc_f32_s", "Floating-point operations are non-deterministic"},
    {0xA8, "i32.trunc_f32_u", "Floating-point operations are non-deterministic"},
    {0xA9, "i32.trunc_f64_s", "Floating-point operations are non-deterministic"},
    {0xAA, "i32.trunc_f64_u", "Floating-point operations are non-deterministic"},
    {0xAE, "i64.trunc_f32_s", "Floating-point operations are non-deterministic"},
    {0xAF, "i64.trunc_f32_u", "Floating-point operations are non-deterministic"},
    {0xB0, "i64.trunc_f64_s", "Floating-point operations are non-deterministic"},
    {0xB1, "i64.trunc_f64_u", "Floating-point operations are non-deterministic"},
    {0xB2, "f32.convert_i32_s", "Floating-point operations are non-deterministic"},
    {0xB3, "f32.convert_i32_u", "Floating-point operations are non-deterministic"},
    {0xB4, "f32.convert_i64_s", "Floating-point operations are non-deterministic"},
    {0xB5, "f32.convert_i64_u", "Floating-point operations are non-deterministic"},
    {0xB6, "f32.demote_f64", "Floating-point operations are non-deterministic"},
    {0xB7, "f64.convert_i32_s", "Floating-point operations are non-deterministic"},
    {0xB8, "f64.convert_i32_u", "Floating-point operations are non-deterministic"},
    {0xB9, "f64.convert_i64_s", "Floating-point operations are non-deterministic"},
    {0xBA, "f64.convert_i64_u", "Floating-point operations are non-deterministic"},
    {0xBB, "f64.promote_f32", "Floating-point operations are non-deterministic"},

    // Floating-point memory operations
    {0x2A, "f32.load", "Floating-point operations are non-deterministic"},
    {0x2B, "f64.load", "Floating-point operations are non-deterministic"},
    {0x38, "f32.store", "Floating-point operations are non-deterministic"},
    {0x39, "f64.store", "Floating-point operations are non-deterministic"},
};

#define BANNED_INSTRUCTIONS_COUNT (sizeof(BANNED_INSTRUCTIONS) / sizeof(mxd_banned_instruction_t))

// LEB128 parsing helper
static uint64_t parse_leb128_u(const uint8_t **ptr, const uint8_t *end) {
    uint64_t result = 0;
    int shift = 0;

    while (*ptr < end) {
        uint8_t byte = **ptr;
        (*ptr)++;

        result |= ((uint64_t)(byte & 0x7F)) << shift;

        if ((byte & 0x80) == 0) {
            break;
        }

        shift += 7;
        if (shift >= 64) {
            break;
        }
    }

    return result;
}

// Check if an opcode is banned
const mxd_banned_instruction_t *mxd_is_opcode_banned(uint8_t opcode) {
    for (size_t i = 0; i < BANNED_INSTRUCTIONS_COUNT; i++) {
        if (BANNED_INSTRUCTIONS[i].opcode == opcode) {
            return &BANNED_INSTRUCTIONS[i];
        }
    }
    return NULL;
}

// Get list of all banned instructions
const mxd_banned_instruction_t *mxd_get_banned_instructions(size_t *count) {
    if (count) {
        *count = BANNED_INSTRUCTIONS_COUNT;
    }
    return BANNED_INSTRUCTIONS;
}

// Check if import is allowed
int mxd_is_import_allowed(const char *module_name, const char *field_name) {
    // For now, only allow "env" module with specific functions
    if (strcmp(module_name, "env") != 0) {
        return 0; // Only "env" module allowed
    }

    // Allowed env imports (deterministic host functions)
    const char *allowed_imports[] = {
        "get_storage",
        "set_storage",
        "get_sender",
        "get_value",
        "get_timestamp",
        "get_block_height",
        "sha256",
        "sha512",
        "verify_signature",
        NULL
    };

    for (int i = 0; allowed_imports[i] != NULL; i++) {
        if (strcmp(field_name, allowed_imports[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

// Main validation function
int mxd_validate_wasm_determinism(const uint8_t *bytecode, size_t size,
                                   mxd_wasm_validation_result_t *result) {
    if (!bytecode || !result) {
        return MXD_WASM_INVALID_MAGIC;
    }

    // Initialize result
    memset(result, 0, sizeof(mxd_wasm_validation_result_t));
    result->result_code = MXD_WASM_VALID;

    // Check minimum size (magic + version = 8 bytes)
    if (size < 8) {
        result->result_code = MXD_WASM_INVALID_MAGIC;
        snprintf(result->error_message, sizeof(result->error_message),
                 "WASM bytecode too small: %zu bytes (minimum 8)", size);
        return MXD_WASM_INVALID_MAGIC;
    }

    // Check size limit (1MB)
    if (size > 1048576) {
        result->result_code = MXD_WASM_TOO_LARGE;
        snprintf(result->error_message, sizeof(result->error_message),
                 "WASM bytecode too large: %zu bytes (maximum 1048576)", size);
        return MXD_WASM_TOO_LARGE;
    }

    // Verify magic number
    if (bytecode[0] != WASM_MAGIC_0 || bytecode[1] != WASM_MAGIC_1 ||
        bytecode[2] != WASM_MAGIC_2 || bytecode[3] != WASM_MAGIC_3) {
        result->result_code = MXD_WASM_INVALID_MAGIC;
        snprintf(result->error_message, sizeof(result->error_message),
                 "Invalid WASM magic number");
        return MXD_WASM_INVALID_MAGIC;
    }

    // Verify version
    if (bytecode[4] != WASM_VERSION || bytecode[5] != 0 ||
        bytecode[6] != 0 || bytecode[7] != 0) {
        result->result_code = MXD_WASM_INVALID_VERSION;
        snprintf(result->error_message, sizeof(result->error_message),
                 "Unsupported WASM version");
        return MXD_WASM_INVALID_VERSION;
    }

    const uint8_t *ptr = bytecode + 8;
    const uint8_t *end = bytecode + size;

    // Parse sections
    while (ptr < end) {
        if (ptr + 1 > end) break;

        uint8_t section_id = *ptr++;
        uint64_t section_size = parse_leb128_u(&ptr, end);

        const uint8_t *section_end = ptr + section_size;
        if (section_end > end) {
            section_end = end;
        }

        // Check import section
        if (section_id == WASM_SECTION_IMPORT) {
            uint64_t import_count = parse_leb128_u(&ptr, section_end);

            for (uint64_t i = 0; i < import_count && ptr < section_end; i++) {
                // Parse module name
                uint64_t module_len = parse_leb128_u(&ptr, section_end);
                if (ptr + module_len > section_end) break;

                char module_name[256] = {0};
                size_t copy_len = module_len < sizeof(module_name) - 1 ?
                                  module_len : sizeof(module_name) - 1;
                memcpy(module_name, ptr, copy_len);
                ptr += module_len;

                // Parse field name
                uint64_t field_len = parse_leb128_u(&ptr, section_end);
                if (ptr + field_len > section_end) break;

                char field_name[256] = {0};
                copy_len = field_len < sizeof(field_name) - 1 ?
                           field_len : sizeof(field_name) - 1;
                memcpy(field_name, ptr, copy_len);
                ptr += field_len;

                // Validate import
                if (!mxd_is_import_allowed(module_name, field_name)) {
                    result->result_code = MXD_WASM_INVALID_IMPORT;
                    result->error_offset = ptr - bytecode;
                    snprintf(result->error_message, sizeof(result->error_message),
                             "Banned import: %s.%s", module_name, field_name);
                    MXD_LOG_ERROR("wasm", "Banned import detected: %s.%s",
                                  module_name, field_name);
                    return MXD_WASM_INVALID_IMPORT;
                }

                // Skip import kind and type
                if (ptr < section_end) ptr++; // kind
                parse_leb128_u(&ptr, section_end); // type index
            }
        }

        // Check code section for banned opcodes
        if (section_id == WASM_SECTION_CODE) {
            uint64_t function_count = parse_leb128_u(&ptr, section_end);

            for (uint64_t i = 0; i < function_count && ptr < section_end; i++) {
                uint64_t body_size = parse_leb128_u(&ptr, section_end);
                const uint8_t *body_end = ptr + body_size;
                if (body_end > section_end) {
                    body_end = section_end;
                }

                // Skip local declarations
                uint64_t local_count = parse_leb128_u(&ptr, body_end);
                for (uint64_t j = 0; j < local_count && ptr < body_end; j++) {
                    parse_leb128_u(&ptr, body_end); // count
                    if (ptr < body_end) ptr++; // type
                }

                // Check instructions
                while (ptr < body_end) {
                    uint8_t opcode = *ptr;
                    const mxd_banned_instruction_t *banned = mxd_is_opcode_banned(opcode);

                    if (banned) {
                        result->result_code = MXD_WASM_NON_DETERMINISTIC;
                        result->error_offset = ptr - bytecode;
                        result->banned_opcode = opcode;
                        result->banned_instruction = banned->name;
                        snprintf(result->error_message, sizeof(result->error_message),
                                 "Banned instruction at offset %u: %s - %s",
                                 result->error_offset, banned->name, banned->reason);
                        MXD_LOG_ERROR("wasm", "%s", result->error_message);
                        return MXD_WASM_NON_DETERMINISTIC;
                    }

                    ptr++;

                    // Skip operands (simplified - full parser would be more complex)
                    if (opcode >= 0x20 && opcode <= 0x24) { // Variable access
                        parse_leb128_u(&ptr, body_end);
                    } else if (opcode >= 0x28 && opcode <= 0x3E) { // Memory ops
                        parse_leb128_u(&ptr, body_end); // align
                        parse_leb128_u(&ptr, body_end); // offset
                    } else if (opcode == 0x41) { // i32.const
                        parse_leb128_u(&ptr, body_end);
                    } else if (opcode == 0x42) { // i64.const
                        parse_leb128_u(&ptr, body_end);
                    }
                }
            }
        }

        ptr = section_end;
    }

    MXD_LOG_DEBUG("wasm", "WASM bytecode passed determinism validation");
    return MXD_WASM_VALID;
}

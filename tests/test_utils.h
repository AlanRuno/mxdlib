#ifndef MXD_TEST_UTILS_H
#define MXD_TEST_UTILS_H

#include <stdio.h>

#define TEST_START(name) printf("\n=== Starting test: %s ===\n", name)
#define TEST_END(name) printf("=== Test completed: %s ===\n\n", name)
#define TEST_ASSERT(condition, message) do { \
    printf("  Checking: %s\n", message); \
    assert(condition); \
    printf("  ✓ Passed: %s\n", message); \
} while(0)
#define TEST_VALUE(desc, fmt, val) printf("  %s: " fmt "\n", desc, val)
#define TEST_ARRAY(desc, arr, len) do { \
    printf("  %s: [", desc); \
    for(size_t i = 0; i < len; i++) { \
        printf("%02x%s", arr[i], i < len-1 ? " " : ""); \
    } \
    printf("]\n"); \
} while(0)

#endif

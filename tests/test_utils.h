#ifndef MXD_TEST_UTILS_H
#define MXD_TEST_UTILS_H

#include <stdio.h>
#include <assert.h>

#define TEST_START(name) do { \
    printf("\n=== Starting test: %s ===\n", name); \
    fflush(stdout); \
} while(0)

#define TEST_END(name) do { \
    printf("=== Test completed: %s ===\n\n", name); \
    fflush(stdout); \
} while(0)

#define TEST_ASSERT(condition, message) do { \
    assert(condition); \
} while(0)

#define TEST_VALUE(desc, fmt, val) do { \
    printf("  %s: " fmt "\n", desc, val); \
    fflush(stdout); \
} while(0)

#define TEST_ARRAY(desc, arr, len) do { \
    printf("  %s: [", desc); \
    for(size_t i = 0; i < len; i++) { \
        printf("%02x%s", arr[i], i < len-1 ? " " : ""); \
    } \
    printf("]\n"); \
    fflush(stdout); \
} while(0)

#endif

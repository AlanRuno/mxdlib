cmake_minimum_required(VERSION 3.10)
project(mxd_library)

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -O0")

# Find OpenSSL and Libsodium
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Include Libsodium
include_directories(/usr/local/include)
link_directories(/usr/local/lib)

# Find wasm3 and uvwasi
find_library(WASM3_LIBRARY m3 PATHS /usr/local/lib)
find_library(UVWASI_LIBRARY uvwasi_a PATHS /usr/local/lib)
find_library(UV_LIBRARY uv_a PATHS /usr/local/lib)
find_path(WASM3_INCLUDE_DIR wasm3.h PATHS /usr/local/include)

if(NOT WASM3_LIBRARY OR NOT WASM3_INCLUDE_DIR)
    message(FATAL_ERROR "wasm3 library not found")
endif()

if(NOT UVWASI_LIBRARY)
    message(FATAL_ERROR "uvwasi library not found")
endif()

if(NOT UV_LIBRARY)
    message(FATAL_ERROR "libuv library not found")
endif()

include_directories(${WASM3_INCLUDE_DIR})

# Set output directories
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Create project structure
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)

# Add library target
add_library(mxd SHARED
    src/mxd_crypto.c
    src/mxd_address.c
    src/base58.c
    src/blockchain/mxd_blockchain.c
    src/blockchain/mxd_rsc.c
    src/mxd_transaction.c
    src/mxd_utxo.c
    src/mxd_mempool.c
    src/mxd_p2p.c
    src/mxd_smart_contracts.c
    src/checkpoints/mxd_checkpoints.c
    src/quantization/mxd_data_quantization.c
    src/mxd_ntp.c)

# Link libraries
target_link_libraries(mxd 
    ${OPENSSL_LIBRARIES}
    sodium
    -static-libgcc
    -static-libstdc++
    gmp
    ${WASM3_LIBRARY}
    m
)

# Include directories
target_include_directories(mxd PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Install rules
install(TARGETS mxd
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include/mxd
    FILES_MATCHING PATTERN "*.h"
)

# Enable testing
enable_testing()
add_subdirectory(tests)

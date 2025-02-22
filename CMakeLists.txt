cmake_minimum_required(VERSION 3.10)
project(mxd_library)

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -O0")

# Windows-specific configuration
if(WIN32)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    set(CMAKE_SHARED_LIBRARY_PREFIX "lib")
    set(BUILD_SHARED_LIBS ON)
    if(DEFINED ENV{MINGW_PREFIX})
        set(CMAKE_INSTALL_PREFIX $ENV{MINGW_PREFIX})
    else()
        set(CMAKE_INSTALL_PREFIX "/mingw64")
    endif()
endif()

# Find OpenSSL and Libsodium
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Include Libsodium
include_directories($ENV{HOME}/.local/include /usr/local/include)
link_directories($ENV{HOME}/.local/lib /usr/local/lib)

# Find dependencies
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

# Use pkg-config to find libraries
pkg_check_modules(LIBUV REQUIRED libuv>=1.0.0)
pkg_check_modules(UVWASI REQUIRED uvwasi>=0.0.20)
pkg_check_modules(WASM3 REQUIRED wasm3>=1.0.0)

include_directories(
    ${LIBUV_INCLUDE_DIRS}
    ${UVWASI_INCLUDE_DIRS}
    ${WASM3_INCLUDE_DIRS}
)

# Set output directories
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Create project structure
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)

# Add library target
add_library(mxd STATIC
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
    src/mxd_ntp.c
    src/mxd_metrics.c
    src/mxd_dht.c
    src/mxd_dht_network.c
    src/mxd_config.c
    src/mxd_blockchain_sync.c
    src/node/metrics_display.c)

# Link libraries
if(WIN32)
    target_link_libraries(mxd PRIVATE
        ${OPENSSL_LIBRARIES}
        sodium
        gmp
        ${LIBUV_LIBRARIES}
        ${UVWASI_LIBRARIES}
        ${WASM3_LIBRARIES}
        ws2_32
        iphlpapi
        userenv)
else()
    # Define common libraries
    set(COMMON_LIBS
        ${OPENSSL_LIBRARIES}
        sodium
        gmp
        ${WASM3_LIBRARIES}
        ${UVWASI_LIBRARIES}
        ${LIBUV_LIBRARIES}
        m
        pthread
        dl)

    if(APPLE)
        target_link_libraries(mxd PRIVATE ${COMMON_LIBS})
    else()
        target_link_libraries(mxd PRIVATE
            ${COMMON_LIBS}
            -static-libgcc
            -static-libstdc++
            rt)
    endif()
endif()

# Include directories
target_include_directories(mxd PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Install rules
install(TARGETS mxd
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include/mxd
    FILES_MATCHING PATTERN "*.h"
)

# Enable testing
enable_testing()
add_subdirectory(tests)

# Add main node executable
add_executable(mxd_node src/node/main.c)
if(APPLE)
    target_link_libraries(mxd_node PRIVATE mxd ${COMMON_LIBS})
else()
    target_link_libraries(mxd_node PRIVATE mxd ${COMMON_LIBS} rt)
endif()

install(TARGETS mxd_node
    RUNTIME DESTINATION bin)

cmake_minimum_required(VERSION 3.10)
project(mxd_library)

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find OpenSSL and Libsodium
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Include Libsodium
include_directories(/usr/local/include)
link_directories(/usr/local/lib)

# Create project structure
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Source files
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)

# Add library target
add_library(mxd SHARED
    src/mxd_crypto.c
    src/mxd_address.c
    src/mxd_blockchain.c
    src/mxd_rsc.c
)

# Link libraries
target_link_libraries(mxd 
    ${OPENSSL_LIBRARIES}
    sodium
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

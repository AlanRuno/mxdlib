#!/bin/bash

set -e

FORCE_BUILD=false
ARCH=$(uname -m)
BREW_PREFIX=$(brew --prefix)

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

check_library_installed() {
    local lib=$1
    find "${BREW_PREFIX}/lib" -name "lib${lib}.dylib*" >/dev/null 2>&1
}

verify_pkgconfig() {
    local pkg=$1
    local min_version=$2
    # Include both Homebrew and system paths
    local pkgconfig_paths=(
        "${BREW_PREFIX}/lib/pkgconfig"
        "/usr/local/lib/pkgconfig"
        "/usr/lib/pkgconfig"
    )
    export PKG_CONFIG_PATH=$(IFS=:; echo "${pkgconfig_paths[*]}"):${PKG_CONFIG_PATH:-}
    if ! pkg-config --exists "$pkg"; then
        log "Error: $pkg.pc not found in pkg-config search path"
        log "Search paths: $(pkg-config --variable pc_path pkg-config)"
        log "Debug information:"
        for dir in "${pkgconfig_paths[@]}"; do
            log "Checking $dir:"
            ls -la "$dir"/*.pc 2>/dev/null || log "  No .pc files found"
        done
        return 1
    fi
    if [ -n "$min_version" ] && ! pkg-config --atleast-version="$min_version" "$pkg"; then
        log "Error: $pkg version $(pkg-config --modversion "$pkg") is less than required $min_version"
        return 1
    fi
    log "Successfully verified $pkg$([ -n "$min_version" ] && echo " >= $min_version")"
    return 0
}

verify_system_deps() {
    local errors=0
    for lib in libssl libsodium libgmp; do
        if ! find "${BREW_PREFIX}/lib" -name "${lib}.dylib*" >/dev/null 2>&1; then
            log "Error: ${lib} not found"
            errors=$((errors + 1))
        fi
    done
    return $errors
}

install_system_deps() {
    if ! check_command brew; then
        log "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    brew install cmake openssl libsodium gmp pkg-config
    
    if ! verify_system_deps; then
        log "Error: Some system dependencies are still missing"
        exit 1
    fi
}

check_wasm3_installed() {
    # Check for library files and headers
    [ -f "${BREW_PREFIX}/lib/libm3.dylib" ] && \
    [ -f "${BREW_PREFIX}/include/wasm3.h" ] && \
    [ -f "${BREW_PREFIX}/lib/cmake/wasm3/wasm3Config.cmake" ]
}

check_libuv_installed() {
    check_library_installed "libuv" && [ -f "${BREW_PREFIX}/include/uv.h" ]
}

check_uvwasi_installed() {
    check_library_installed "libuvwasi" && [ -f "${BREW_PREFIX}/include/uvwasi/uvwasi.h" ]
}

install_wasm3() {
    if [ "$FORCE_BUILD" = "true" ]; then
        log "Force rebuilding wasm3..."
        rm -rf "${BREW_PREFIX}/lib/libm3.dylib*" "${BREW_PREFIX}/include/wasm3*"
    elif check_wasm3_installed; then
        log "wasm3 is already installed, skipping"
        return 0
    fi
    
    log "Installing wasm3..."
    # Clean up existing wasm3 directory if it exists
    rm -rf wasm3
    
    # Ensure pkg-config directories exist and are writable
    for pkgconfig_dir in "${BREW_PREFIX}/lib/pkgconfig" "/usr/local/lib/pkgconfig"; do
        if [ ! -d "$pkgconfig_dir" ]; then
            sudo mkdir -p "$pkgconfig_dir"
        fi
        if [ ! -w "$pkgconfig_dir" ]; then
            sudo chown -R $(whoami) "$pkgconfig_dir"
        fi
    done
    
    git clone https://github.com/wasm3/wasm3
    cd wasm3
    mkdir -p build && cd build
    
    # Create pkg-config file and directory
    mkdir -p source
    mkdir -p "${BREW_PREFIX}/lib/pkgconfig"
    echo "Creating source directory and copying pkg-config file..."
    cp ../../wasm3.pc.in source/wasm3.pc.in || {
        echo "Failed to copy wasm3.pc.in. Debug info:"
        echo "Current directory: $(pwd)"
        echo "Source exists: $(test -f ../../wasm3.pc.in && echo "Yes" || echo "No")"
        echo "Target directory exists: $(test -d source && echo "Yes" || echo "No")"
        exit 1
    }
    
    # Create main CMakeLists.txt
    cat > CMakeLists.txt << 'EOL'
cmake_minimum_required(VERSION 3.12)
project(wasm3)

include(GNUInstallDirs)
option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS ON)

# Set installation paths
set(PKGCONFIG_INSTALL_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig"
    CACHE PATH "Installation directory for pkg-config files")

# Configure and install pkg-config file
message(STATUS "Configuring pkg-config file...")
message(STATUS "pkg-config installation directory: ${PKGCONFIG_INSTALL_DIR}")

# Ensure pkg-config file is configured with correct paths
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc
    @ONLY)

if(NOT EXISTS ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc)
    message(FATAL_ERROR "Failed to generate wasm3.pc")
endif()

message(STATUS "Installing pkg-config file to: ${PKGCONFIG_INSTALL_DIR}")

# Install pkg-config file with explicit permissions
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc
    DESTINATION ${PKGCONFIG_INSTALL_DIR}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    COMPONENT development)

# Add source files
file(GLOB M3_SOURCES source/*.c)

# Add executable target
add_executable(wasm3 platforms/app/main.c)
target_link_libraries(wasm3 PRIVATE m3)

# Install executable
install(TARGETS wasm3 RUNTIME DESTINATION bin)
EOL

    # Configure for macOS
    export PKG_CONFIG_PATH="${BREW_PREFIX}/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
    # Verify pkg-config directory exists and is writable
    if [ ! -d "${BREW_PREFIX}/lib/pkgconfig" ]; then
        sudo mkdir -p "${BREW_PREFIX}/lib/pkgconfig"
    fi
    if [ ! -w "${BREW_PREFIX}/lib/pkgconfig" ]; then
        sudo chown -R $(whoami) "${BREW_PREFIX}/lib/pkgconfig"
    fi
    cmake -DCMAKE_INSTALL_PREFIX="${BREW_PREFIX}" \
          -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_SHARED_LIBS=ON \
          -DPKGCONFIG_INSTALL_DIR="${BREW_PREFIX}/lib/pkgconfig" \
          -DCMAKE_C_FLAGS="-fPIC" \
          -DCMAKE_INSTALL_RPATH="${BREW_PREFIX}/lib" \
          -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
          -DCMAKE_INSTALL_NAME_DIR="${BREW_PREFIX}/lib" \
          -DCMAKE_MACOSX_RPATH=ON \
          ..
    
    make
    make install
    
    # Verify wasm3 installation
    if ! verify_pkgconfig wasm3 "1.0.0"; then
        log "Error: wasm3 pkg-config verification failed"
        exit 1
    fi
    
    cd ../..
    rm -rf wasm3
}

install_libuv() {
    if [ "$FORCE_BUILD" = "true" ]; then
        log "Force rebuilding libuv..."
        rm -rf "${BREW_PREFIX}/lib/libuv.dylib*" "${BREW_PREFIX}/include/uv*"
    elif check_libuv_installed; then
        log "libuv is already installed, skipping"
        return 0
    fi
    
    log "Installing libuv..."
    git clone https://github.com/libuv/libuv
    cd libuv
    mkdir -p build && cd build
    
    cmake -DCMAKE_INSTALL_PREFIX="${BREW_PREFIX}" \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_INSTALL_NAME_DIR="${BREW_PREFIX}/lib" \
          -DCMAKE_MACOSX_RPATH=ON \
          ..
    
    make
    make install
    cd ../..
    rm -rf libuv
    
    # Verify libuv installation
    if ! verify_pkgconfig libuv "1.0.0"; then
        log "Error: libuv pkg-config verification failed"
        exit 1
    fi
}

install_uvwasi() {
    if [ "$FORCE_BUILD" = "true" ]; then
        log "Force rebuilding uvwasi..."
        rm -rf "${BREW_PREFIX}/lib/libuvwasi.dylib*" "${BREW_PREFIX}/include/uvwasi*"
    elif check_uvwasi_installed; then
        log "uvwasi is already installed, skipping"
        return 0
    fi
    
    log "Installing uvwasi..."
    git clone https://github.com/nodejs/uvwasi
    cd uvwasi
    mkdir -p build && cd build
    
    cmake -DCMAKE_INSTALL_PREFIX="${BREW_PREFIX}" \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_INSTALL_NAME_DIR="${BREW_PREFIX}/lib" \
          -DCMAKE_MACOSX_RPATH=ON \
          ..
    
    make
    make install
    cd ../..
    rm -rf uvwasi
    
    # Verify uvwasi installation
    if ! verify_pkgconfig uvwasi "0.0.20"; then
        log "Error: uvwasi pkg-config verification failed"
        exit 1
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --force_build)
                FORCE_BUILD=true
                shift
                ;;
            *)
                log "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

main() {
    parse_args "$@"
    
    log "Installing for macOS (${ARCH})"
    install_system_deps
    install_libuv
    install_uvwasi
    install_wasm3
    
    log "All dependencies installed successfully"
}

main "$@"

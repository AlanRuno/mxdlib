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
    git clone https://github.com/wasm3/wasm3
    cd wasm3
    mkdir -p build && cd build
    
    # Create pkg-config file
    cp ../../wasm3.pc.in source/wasm3.pc.in
    
    # Create main CMakeLists.txt
    cat > CMakeLists.txt << 'EOL'
cmake_minimum_required(VERSION 3.12)
project(wasm3)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS ON)

# Configure pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc
    @ONLY)

# Install pkg-config file
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc
    DESTINATION lib/pkgconfig)

# Add source files
file(GLOB M3_SOURCES source/*.c)
EOL

    # Configure for macOS
    PKG_CONFIG_PATH="${BREW_PREFIX}/lib/pkgconfig" \
    cmake -DCMAKE_INSTALL_PREFIX="${BREW_PREFIX}" \
          -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_C_FLAGS="-fPIC" \
          -DCMAKE_INSTALL_RPATH="${BREW_PREFIX}/lib" \
          -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
          -DCMAKE_INSTALL_NAME_DIR="${BREW_PREFIX}/lib" \
          -DCMAKE_MACOSX_RPATH=ON \
          ..
    
    make
    make install
    
    # Verify wasm3 pkg-config installation
    if ! pkg-config --exists wasm3; then
        log "Error: wasm3.pc not found by pkg-config"
        exit 1
    fi
    log "wasm3 pkg-config file installed successfully"
    
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

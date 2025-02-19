#!/bin/bash

set -e

FORCE_BUILD=false

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

check_library_installed() {
    local lib=$1
    if [[ "$OSTYPE" == "darwin"* ]]; then
        find /usr/local/lib -name "${lib/.so/.dylib}*" >/dev/null 2>&1
    else
        ldconfig -p | grep "$lib" >/dev/null 2>&1
    fi
}

check_wasm3_installed() {
    # Check for library files and headers
    if [[ "$OSTYPE" == "darwin"* ]]; then
        ([ -f "/usr/local/lib/libm3.dylib" ] || [ -f "/usr/local/lib/libm3.a" ]) && \
        [ -f "/usr/local/include/wasm3.h" ] && \
        [ -f "/usr/local/lib/cmake/wasm3/wasm3Config.cmake" ]
    else
        # Use ldconfig to check for library
        (ldconfig -p | grep -E "libm3\.(so|a)" >/dev/null 2>&1) && \
        [ -f "/usr/local/include/wasm3.h" ] && \
        [ -f "/usr/local/lib/cmake/wasm3/wasm3Config.cmake" ]
    fi
}

check_libuv_installed() {
    check_library_installed "libuv.so" && [ -f "/usr/local/include/uv.h" ]
}

check_uvwasi_installed() {
    check_library_installed "libuvwasi.so" && [ -f "/usr/local/include/uvwasi/uvwasi.h" ]
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

verify_system_deps() {
    local errors=0
    if [[ "$OSTYPE" == "darwin"* ]]; then
        for lib in libssl.dylib libsodium.dylib libgmp.dylib; do
            if ! find /usr/local/lib -name "$lib*" >/dev/null 2>&1; then
                log "Error: $lib not found"
                errors=$((errors + 1))
            fi
        done
    else
        for lib in libssl.so libsodium.so libgmp.so; do
            if ! ldconfig -p | grep "$lib" >/dev/null 2>&1; then
                log "Error: $lib not found"
                errors=$((errors + 1))
            fi
        done
    fi
    return $errors
}

install_system_deps() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if ! check_command brew; then
            log "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        brew install cmake openssl libsodium gmp
    else
        sudo apt-get update
        sudo apt-get install -y build-essential cmake libssl-dev libsodium-dev libgmp-dev
        sudo ldconfig
    fi
    
    if ! verify_system_deps; then
        log "Error: Some system dependencies are still missing"
        exit 1
    fi
}

create_wasm3_cmake_config() {
    sudo tee /usr/local/lib/cmake/wasm3/wasm3Config.cmake > /dev/null << 'EOF'
if(NOT TARGET wasm3::m3)
    add_library(wasm3::m3 UNKNOWN IMPORTED)
    set_target_properties(wasm3::m3 PROPERTIES
        IMPORTED_LOCATION "/usr/local/lib/libm3${CMAKE_SHARED_LIBRARY_SUFFIX}"
        INTERFACE_INCLUDE_DIRECTORIES "/usr/local/include"
    )
endif()
set(WASM3_FOUND TRUE)
EOF
}

install_wasm3() {
    if ! $FORCE_BUILD && check_wasm3_installed; then
        log "wasm3 is already installed, skipping (use --force_build to override)"
        return
    fi
    log "Installing wasm3..."
    git clone https://github.com/wasm3/wasm3
    cd wasm3
    mkdir -p build && cd build
    # Modify wasm3's CMake to support shared library and install targets
    # Add BUILD_WASM3_LIBS option handling
    sed -i '1i\option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)' source/CMakeLists.txt
    # Change library type to shared
    sed -i 's/STATIC/SHARED/g' source/CMakeLists.txt
    # Add install targets
    echo "install(TARGETS m3 LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)" >> source/CMakeLists.txt
    echo "install(FILES *.h DESTINATION include)" >> source/CMakeLists.txt
    # Build with proper install prefix
    cmake -DBUILD_WASM3_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local ..
    make
    sudo make install
    # Create CMake config directory and install config file
    sudo mkdir -p /usr/local/lib/cmake/wasm3
    create_wasm3_cmake_config
    cd ../..
    rm -rf wasm3
    sudo ldconfig
    
    # Verify installation
    if ! verify_system_deps || ! check_wasm3_installed; then
        log "Error: Installation verification failed"
        exit 1
    fi
    log "wasm3 installation verified successfully"
}

install_libuv() {
    if ! $FORCE_BUILD && check_libuv_installed; then
        log "libuv is already installed, skipping (use --force_build to override)"
        return
    fi
    log "Installing libuv..."
    git clone https://github.com/libuv/libuv
    cd libuv
    mkdir -p build && cd build
    cmake ..
    make
    sudo make install
    cd ../..
    rm -rf libuv
}

install_uvwasi() {
    if ! $FORCE_BUILD && check_uvwasi_installed; then
        log "uvwasi is already installed, skipping (use --force_build to override)"
        return
    fi
    log "Installing uvwasi..."
    git clone https://github.com/nodejs/uvwasi
    cd uvwasi
    mkdir -p build && cd build
    cmake ..
    make
    sudo make install
    cd ../..
    rm -rf uvwasi
}

verify_installation() {
    local errors=0
    
    # Check system dependencies
    for cmd in cmake gcc g++; do
        if ! check_command $cmd; then
            log "Error: $cmd not found"
            errors=$((errors + 1))
        fi
    done

    # Check libraries
    if [[ "$OSTYPE" == "darwin"* ]]; then
        for lib in libssl.dylib libsodium.dylib libgmp.dylib; do
            if ! find /usr/local/lib -name "$lib*" >/dev/null 2>&1; then
                log "Error: $lib not found"
                errors=$((errors + 1))
            fi
        done
    else
        for lib in libssl.so libsodium.so libgmp.so; do
            if ! ldconfig -p | grep "$lib" >/dev/null 2>&1; then
                log "Error: $lib not found"
                errors=$((errors + 1))
            fi
        done
    fi

    return $errors
}

main() {
    log "Starting installation..."
    parse_args "$@"
    
    install_system_deps
    install_wasm3
    install_libuv
    install_uvwasi

    if [[ "$OSTYPE" != "darwin"* ]]; then
        sudo ldconfig
    fi

    if verify_installation; then
        log "Installation completed successfully"
    else
        log "Installation completed with errors"
        exit 1
    fi
}

main

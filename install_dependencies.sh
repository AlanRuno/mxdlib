#!/bin/bash

set -e

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

check_command() {
    command -v "$1" >/dev/null 2>&1
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
    fi
}

install_wasm3() {
    log "Installing wasm3..."
    git clone https://github.com/wasm3/wasm3
    cd wasm3
    mkdir -p build && cd build
    cmake -DBUILD_WASM3_LIBS=ON ..
    make
    sudo make install
    cd ../..
    rm -rf wasm3
}

install_libuv() {
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
    for lib in libssl.so libsodium.so libgmp.so; do
        if [[ "$OSTYPE" == "darwin"* ]]; then
            lib_path="/usr/local/lib/${lib/.so/.dylib}"
        else
            lib_path="/usr/local/lib/$lib"
        fi
        if [ ! -f "$lib_path" ]; then
            log "Error: $lib not found"
            errors=$((errors + 1))
        fi
    done

    return $errors
}

main() {
    log "Starting installation..."
    
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

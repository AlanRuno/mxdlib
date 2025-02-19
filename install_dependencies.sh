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
    check_command m3 && [ -f "/usr/local/include/wasm3.h" ]
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
    cmake -DBUILD_WASM3_LIBS=ON ..
    make
    sudo make install
    cd ../..
    rm -rf wasm3
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

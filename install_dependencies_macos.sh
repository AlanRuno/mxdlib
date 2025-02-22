#!/bin/bash

set -e

FORCE_BUILD=false
ARCH=$(uname -m)
BREW_PREFIX=$(brew --prefix)

# Set up PKG_CONFIG_PATH at the start
export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:${PKG_CONFIG_PATH:-}"

# Verify PKG_CONFIG_PATH is set
if [ -z "$PKG_CONFIG_PATH" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Error: PKG_CONFIG_PATH is not set"
    exit 1
fi

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

verify_directory_permissions() {
    local dir="$1"
    local fallback_dir=""
    
    # Try Homebrew paths first
    if [[ "$dir" == "/usr/local/"* ]]; then
        fallback_dir="${BREW_PREFIX}/opt/$(basename "$dir")"
        if [ -w "$fallback_dir" ] || mkdir -p "$fallback_dir" 2>/dev/null; then
            log "Using Homebrew fallback path: $fallback_dir"
            echo "$fallback_dir"
            return 0
        fi
    fi
    
    # Try user's home directory next
    fallback_dir="$HOME/.local/$(basename "$dir")"
    if [ -w "$fallback_dir" ] || mkdir -p "$fallback_dir" 2>/dev/null; then
        log "Using home directory fallback path: $fallback_dir"
        echo "$fallback_dir"
        return 0
    fi
    
    # Try original directory as last resort
    if [ -w "$dir" ] || mkdir -p "$dir" 2>/dev/null; then
        log "Using original path: $dir"
        echo "$dir"
        return 0
    fi
    
    log "Error: Cannot find writable directory for $dir"
    return 1
}

install_pkgconfig_manually() {
    local version="1.0.0"
    local pc_paths=(
        "${BREW_PREFIX}/lib/pkgconfig"
        "$HOME/.local/lib/pkgconfig"
    )
    
    for pkgconfig_dir in "${pc_paths[@]}"; do
        # Create pkgconfig directory if needed
        mkdir -p "$pkgconfig_dir"
        local pc_file="$pkgconfig_dir/wasm3.pc"
    
    # Generate pkg-config file
    cat > "$pc_file" << EOL
prefix=${BREW_PREFIX}
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: wasm3
Description: High performance WebAssembly interpreter
Version: ${version}
Requires: libuv uvwasi
Libs: -L\${libdir} -lm3
Cflags: -I\${includedir}
EOL
        log "Created pkg-config file at $pc_file"
    done
    
    # Update PKG_CONFIG_PATH to include both locations
    export PKG_CONFIG_PATH="${BREW_PREFIX}/lib/pkgconfig:$HOME/.local/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
    log "Updated PKG_CONFIG_PATH: $PKG_CONFIG_PATH"
}

setup_pkgconfig_paths() {
    local verified_paths=()
    
    # Try standard locations in order of preference
    local standard_paths=(
        "${BREW_PREFIX}/opt/pkgconfig"
        "${BREW_PREFIX}/lib/pkgconfig"
        "${BREW_PREFIX}/share/pkgconfig"
        "$HOME/.local/lib/pkgconfig"
    )
    
    # Verify each path and collect working ones
    for dir in "${standard_paths[@]}"; do
        local actual_dir
        if actual_dir=$(verify_directory_permissions "$dir"); then
            verified_paths+=("$actual_dir")
            log "Added pkg-config path: $actual_dir"
        fi
    done
    
    # Add system paths for searching but not writing
    local system_paths=(
        "/usr/local/lib/pkgconfig"
        "/usr/local/share/pkgconfig"
        "/usr/lib/pkgconfig"
    )
    
    # Set PKG_CONFIG_PATH with verified directories
    if [ ${#verified_paths[@]} -eq 0 ]; then
        log "Error: No writable pkg-config paths found"
        return 1
    fi
    
    # Add Homebrew and user local paths
    verified_paths+=("${BREW_PREFIX}/lib/pkgconfig")
    verified_paths+=("$HOME/.local/lib/pkgconfig")
    
    # Create only user-writable directories
    mkdir -p "$HOME/.local/lib/pkgconfig"
    
    # Add system paths for searching only
    verified_paths+=("${system_paths[@]}")
    
    # Update PKG_CONFIG_PATH with additional paths
    local new_paths=$(IFS=:; echo "${verified_paths[*]}")
    export PKG_CONFIG_PATH="$new_paths:$PKG_CONFIG_PATH"
    log "PKG_CONFIG_PATH updated to: $PKG_CONFIG_PATH"
    return 0
}

verify_pkgconfig() {
    local pkg=$1
    local min_version=$2
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
    # Check for library files and headers in both Homebrew and local paths
    ([ -f "${BREW_PREFIX}/lib/libm3.dylib" ] && \
     [ -f "${BREW_PREFIX}/include/wasm3/wasm3.h" ] && \
     [ -f "${BREW_PREFIX}/lib/cmake/wasm3/wasm3Config.cmake" ]) || \
    ([ -f "$HOME/.local/lib/libm3.dylib" ] && \
     [ -f "$HOME/.local/include/wasm3/wasm3.h" ] && \
     [ -f "$HOME/.local/lib/cmake/wasm3/wasm3Config.cmake" ])
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
    
    # Set up pkg-config paths and verify permissions
    setup_pkgconfig_paths
    
    git clone https://github.com/wasm3/wasm3
    cd wasm3
    mkdir -p build && cd build
    
    # Create pkg-config file and directory
    mkdir -p source
    mkdir -p "$HOME/.local/lib/pkgconfig"
    
    # Create pkg-config file manually
    local pkgconfig_dir="$HOME/.local/lib/pkgconfig"
    mkdir -p "$pkgconfig_dir"
    
    # Create pkg-config file
    cat > "$pkgconfig_dir/wasm3.pc" << EOL
prefix=$HOME/.local
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include/wasm3

Name: wasm3
Description: High performance WebAssembly interpreter
Version: 1.0.0
Requires: libuv uvwasi
Libs: -L\${libdir} -lm3
Cflags: -I\${includedir}
EOL

    # Update pkg-config path
    export PKG_CONFIG_PATH="$pkgconfig_dir:$PKG_CONFIG_PATH"
    
    # Verify pkg-config file is found
    if ! pkg-config --exists wasm3; then
        log "Failed to find wasm3.pc in pkg-config path"
        return 1
    fi
    
    # Create main CMakeLists.txt
    cat > CMakeLists.txt << 'EOL'
cmake_minimum_required(VERSION 3.12)
project(wasm3)

include(GNUInstallDirs)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS ON)

# Add source files
file(GLOB M3_SOURCES ../source/*.c)
add_library(m3 ${M3_SOURCES})
target_include_directories(m3 PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../source>
    $<INSTALL_INTERFACE:include>)

# Add executable target
add_executable(wasm3 ../platforms/app/main.c)
target_link_libraries(wasm3 PRIVATE m3)

# Configure pkg-config file
configure_file(
    ../source/wasm3.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc
    @ONLY)

# Install targets
install(TARGETS m3 wasm3
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Install main header directly in wasm3 subdirectory
install(FILES ../source/wasm3.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/wasm3)

# Install other headers maintaining directory structure
install(DIRECTORY ../source/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/wasm3
    FILES_MATCHING PATTERN "*.h"
    PATTERN "wasm3.h" EXCLUDE)

# Install pkg-config file
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
EOL

    # Configure for macOS
    # Create necessary directories
    mkdir -p "$HOME/.local"/{lib,include/wasm3,lib/pkgconfig}
    
    # Create pkg-config file in user's local directory
    cat > "$HOME/.local/lib/pkgconfig/wasm3.pc" << EOL
prefix=$HOME/.local
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include/wasm3

Name: wasm3
Description: High performance WebAssembly interpreter
Version: 1.0.0
Requires: libuv uvwasi
Libs: -L\${libdir} -lm3
Cflags: -I\${includedir}/wasm3
EOL

    # Update pkg-config path
    export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"
    
    # Clean up and clone wasm3
    rm -rf wasm3
    log "Cloning wasm3..."
    git clone https://github.com/wasm3/wasm3.git || {
        log "Failed to clone wasm3"
        return 1
    }

    # Build wasm3
    cd wasm3 || {
        log "Failed to enter wasm3 directory"
        return 1
    }

    # Create build directory
    mkdir -p build
    cd build || {
        log "Failed to enter build directory"
        return 1
    }

    # Configure with correct installation paths
    export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
    cmake -DCMAKE_INSTALL_PREFIX="$HOME/.local" \
          -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_INSTALL_LIBDIR=lib \
          -DCMAKE_INSTALL_INCLUDEDIR=include \
          -DCMAKE_MODULE_PATH="$HOME/.local/lib/cmake" \
          -DCMAKE_PREFIX_PATH="$HOME/.local" \
          -DCMAKE_C_FLAGS="-fPIC -I$HOME/.local/include" \
          -DCMAKE_INSTALL_RPATH="$HOME/.local/lib" \
          -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
          -DCMAKE_INSTALL_NAME_DIR="$HOME/.local/lib" \
          -DCMAKE_MACOSX_RPATH=ON \
          .. || {
        log "Failed to configure wasm3"
        return 1
    }

    # Build and install wasm3
    make && make install || {
        log "Failed to build and install wasm3"
        return 1
    }

    # Verify installation
    if [ ! -f "$HOME/.local/include/wasm3/wasm3.h" ] || \
       [ ! -f "$HOME/.local/include/wasm3/wasm3_defs.h" ] || \
       ! ls "$HOME/.local/lib/libm3"* >/dev/null 2>&1; then
        log "Failed to verify wasm3 installation"
        echo "Current directory: $(pwd)"
        echo "Files in $HOME/.local/lib:"
        ls -la "$HOME/.local/lib"
        echo "Files in $HOME/.local/include/wasm3:"
        ls -la "$HOME/.local/include/wasm3"
        return 1
    fi

    # Create symbolic links for compatibility
    ln -sf "$HOME/.local/include/wasm3/wasm3.h" "$HOME/.local/include/wasm3.h" 2>/dev/null || true
    ln -sf "$HOME/.local/include/wasm3" "$HOME/.local/include/wasm3-include" 2>/dev/null || true

    # Verify pkg-config file is found
    if ! pkg-config --exists wasm3; then
        log "Failed to find wasm3.pc in pkg-config path"
        echo "PKG_CONFIG_PATH: $PKG_CONFIG_PATH"
        echo "Contents of $HOME/.local/lib/pkgconfig:"
        ls -la "$HOME/.local/lib/pkgconfig"
        return 1
    fi

    # Return to original directory and clean up
    cd ../..
    rm -rf wasm3
}

install_libuv() {
    if [ "$FORCE_BUILD" = "true" ]; then
        log "Force rebuilding libuv..."
        rm -rf "$HOME/.local/lib/libuv.*" "$HOME/.local/include/uv.h"
    elif check_libuv_installed; then
        log "libuv is already installed, skipping"
        return 0
    fi
    
    log "Installing libuv..."
    # Clean up existing directory if it exists
    rm -rf libuv
    git clone https://github.com/libuv/libuv
    cd libuv
    mkdir -p build && cd build
    
    # Configure with correct installation paths and disable tests
    cmake -DCMAKE_INSTALL_PREFIX="$HOME/.local" \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_INSTALL_NAME_DIR="$HOME/.local/lib" \
          -DCMAKE_MACOSX_RPATH=ON \
          -DLIBUV_BUILD_TESTS=OFF \
          -DCMAKE_INSTALL_LIBDIR=lib \
          -DCMAKE_INSTALL_INCLUDEDIR=include \
          -DCMAKE_INSTALL_RPATH="$HOME/.local/lib" \
          -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
          -DCMAKE_BUILD_TYPE=Release \
          ..
    
    # Build and install
    make && make install || {
        log "Failed to build and install libuv"
        return 1
    }
    
    # Create pkg-config file
    mkdir -p "$HOME/.local/lib/pkgconfig"
    cat > "$HOME/.local/lib/pkgconfig/libuv.pc" << EOL
prefix=$HOME/.local
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: libuv
Description: multi-platform support library with a focus on asynchronous I/O
Version: 1.0.0
Libs: -L\${libdir} -luv
Cflags: -I\${includedir}
EOL

    # Update pkg-config path
    export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"
    log "Installed to $HOME/.local"
    
    cd ../..
    rm -rf libuv
    
    # Verify libuv installation
    if ! verify_pkgconfig libuv "1.0.0"; then
        log "Error: libuv pkg-config verification failed"
        echo "PKG_CONFIG_PATH: $PKG_CONFIG_PATH"
        echo "Contents of $HOME/.local/lib/pkgconfig:"
        ls -la "$HOME/.local/lib/pkgconfig"
        return 1
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
    # Clean up existing directory if it exists
    rm -rf uvwasi
    git clone https://github.com/nodejs/uvwasi
    cd uvwasi
    mkdir -p build && cd build
    
    # Configure with correct installation paths
    cmake -DCMAKE_INSTALL_PREFIX="$HOME/.local" \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_INSTALL_NAME_DIR="$HOME/.local/lib" \
          -DCMAKE_INSTALL_LIBDIR=lib \
          -DCMAKE_INSTALL_INCLUDEDIR=include/wasm3 \
          -DCMAKE_INSTALL_RPATH="$HOME/.local/lib" \
          -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_MACOSX_RPATH=ON \
          ..
    
    # Build and install
    make && make install || {
        log "Failed to build and install uvwasi"
        return 1
    }
    
    # Create pkg-config file
    mkdir -p "$HOME/.local/lib/pkgconfig"
    cat > "$HOME/.local/lib/pkgconfig/uvwasi.pc" << EOL
prefix=$HOME/.local
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: uvwasi
Description: WASI system call implementation using libuv
Version: 0.0.20
Requires: libuv >= 1.0.0
Libs: -L\${libdir} -luvwasi
Cflags: -I\${includedir}/wasm3
EOL

    # Update pkg-config path
    export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"
    log "Installed to $HOME/.local"
    
    cd ../..
    rm -rf uvwasi
    
    # Verify uvwasi installation
    if ! verify_pkgconfig uvwasi "0.0.20"; then
        log "Error: uvwasi pkg-config verification failed"
        echo "PKG_CONFIG_PATH: $PKG_CONFIG_PATH"
        echo "Contents of $HOME/.local/lib/pkgconfig:"
        ls -la "$HOME/.local/lib/pkgconfig"
        return 1
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

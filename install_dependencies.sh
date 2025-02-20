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
        sudo apt-get install -y build-essential cmake libssl-dev libsodium-dev libgmp-dev pkg-config
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
    if [ "$FORCE_BUILD" = "true" ]; then
        log "Force rebuilding wasm3..."
        sudo rm -rf /usr/local/lib/libm3.so* /usr/local/include/wasm3*
    elif check_wasm3_installed; then
        log "wasm3 is already installed, skipping (use --force_build to override)"
        return 0
    fi
    log "Installing wasm3..."
    git clone https://github.com/wasm3/wasm3
    cd wasm3
    # Modify wasm3's CMake to support shared library and install targets
    # Create a new CMakeLists.txt in source directory
    # Patch CMake files to build shared library
    sed -i 's/add_library(m3 STATIC/add_library(m3 SHARED/' source/CMakeLists.txt
    sed -i 's/STATIC/SHARED/' source/CMakeLists.txt
    
    # Create main CMakeLists.txt
    cat > CMakeLists.txt << 'EOL'
cmake_minimum_required(VERSION 3.12)
project(wasm3)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS ON)

# Add source files
file(GLOB M3_SOURCES source/*.c)

# Add library target
add_library(m3 SHARED ${M3_SOURCES})

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/source>
    $<INSTALL_INTERFACE:include>)

# Install headers to wasm3 subdirectory
file(GLOB HEADER_FILES source/*.h)
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3 EXPORT wasm3Targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

# Generate and install pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc
    @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc
    DESTINATION lib/pkgconfig)

# Generate and install CMake config files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    @ONLY)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    DESTINATION lib/cmake/wasm3)

install(EXPORT wasm3Targets
    FILE wasm3Targets.cmake
    NAMESPACE wasm3::
    DESTINATION lib/cmake/wasm3)
EOL

    # Create main CMakeLists.txt
    cat > CMakeLists.txt << 'EOL'
cmake_minimum_required(VERSION 3.12)
project(wasm3)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS ON)

# Add subdirectory
add_subdirectory(source)

# Generate and install CMake config files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    @ONLY)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    DESTINATION lib/cmake/wasm3)

install(EXPORT wasm3Targets
    FILE wasm3Targets.cmake
    NAMESPACE wasm3::
    DESTINATION lib/cmake/wasm3)
EOL

    # Create CMake config file template
    cat > source/wasm3Config.cmake.in << 'EOL'
@PACKAGE_INIT@

include(CMakeFindDependencyMacro)
find_dependency(uvwasi)
find_dependency(uv)

include("${CMAKE_CURRENT_LIST_DIR}/wasm3Targets.cmake")

set(WASM3_INCLUDE_DIR "@CMAKE_INSTALL_PREFIX@/include")
set(WASM3_LIBRARY_DIR "@CMAKE_INSTALL_PREFIX@/lib")
set(WASM3_LIBRARIES m3)
EOL

    # Build and install
    mkdir -p build && cd build
    CFLAGS="-fPIC -fvisibility=default" \
    CXXFLAGS="-fPIC -fvisibility=default" \
    LDFLAGS="-L/usr/local/lib" \
    PKG_CONFIG_PATH="/usr/local/lib/pkgconfig" \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_C_FLAGS="-fPIC -fvisibility=default" \
          -DCMAKE_INSTALL_RPATH="/usr/local/lib" \
          -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
          -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON \
          -DCMAKE_SHARED_LINKER_FLAGS="-Wl,--no-undefined -Wl,--as-needed" \
          -DCMAKE_EXE_LINKER_FLAGS="-Wl,--no-undefined -Wl,--as-needed" \
          ..
    make
    sudo make install
    sudo ldconfig
# Add library target
add_library(m3 SHARED
    m3_api_libc.c
    m3_api_wasi.c
    m3_api_uvwasi.c
    m3_api_meta_wasi.c
    m3_api_tracer.c
    m3_bind.c
    m3_code.c
    m3_compile.c
    m3_core.c
    m3_env.c
    m3_exec.c
    m3_function.c
    m3_info.c
    m3_module.c
    m3_parse.c)

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/wasm3>)

# Install headers
file(GLOB HEADER_FILES "*.h")
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
EOL

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Install headers
file(GLOB HEADER_FILES "*.h")
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
EOL

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Install headers
file(GLOB HEADER_FILES "*.h")
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
EOL

    # Create main CMakeLists.txt
    cat > CMakeLists.txt << 'EOL'
cmake_minimum_required(VERSION 3.12)
project(wasm3)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS ON)

# Add subdirectory
add_subdirectory(source)

# Install headers to wasm3 subdirectory
file(GLOB HEADER_FILES source/*.h)
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Create symlinks for backward compatibility
install(CODE "
    file(MAKE_DIRECTORY \${CMAKE_INSTALL_PREFIX}/include/wasm3)
    file(GLOB HEADER_FILES \${CMAKE_INSTALL_PREFIX}/include/wasm3/*.h)
    foreach(HEADER \${HEADER_FILES})
        get_filename_component(HEADER_NAME \${HEADER} NAME)
        execute_process(
            COMMAND \${CMAKE_COMMAND} -E create_symlink wasm3/\${HEADER_NAME} \${CMAKE_INSTALL_PREFIX}/include/\${HEADER_NAME}
        )
    endforeach()
")
EOL

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Install headers
file(GLOB HEADER_FILES "*.h")
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
EOL

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/wasm3>)

# Install headers
file(GLOB HEADER_FILES "*.h")
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
EOL
    m3_api_libc.c
    m3_api_wasi.c
    m3_api_uvwasi.c
    m3_api_meta_wasi.c
    m3_api_tracer.c
    m3_bind.c
    m3_code.c
    m3_compile.c
    m3_core.c
    m3_env.c
    m3_exec.c
    m3_function.c
    m3_info.c
    m3_module.c
    m3_parse.c)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Install headers
file(GLOB HEADER_FILES "*.h")
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
EOL

    # Create main CMakeLists.txt
    cat > CMakeLists.txt << 'EOL'
cmake_minimum_required(VERSION 3.12)
project(wasm3)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS ON)

# Add subdirectory
add_subdirectory(source)

# Install headers to wasm3 subdirectory
file(GLOB HEADER_FILES source/*.h)
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Create symlinks for backward compatibility
install(CODE "
    file(MAKE_DIRECTORY \${CMAKE_INSTALL_PREFIX}/include/wasm3)
    file(GLOB HEADER_FILES \${CMAKE_INSTALL_PREFIX}/include/wasm3/*.h)
    foreach(HEADER \${HEADER_FILES})
        get_filename_component(HEADER_NAME \${HEADER} NAME)
        execute_process(
            COMMAND \${CMAKE_COMMAND} -E create_symlink wasm3/\${HEADER_NAME} \${CMAKE_INSTALL_PREFIX}/include/\${HEADER_NAME}
        )
    endforeach()
")
EOL
cmake_minimum_required(VERSION 3.12)
project(wasm3)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS ON)

# Add source files
file(GLOB M3_SOURCES source/*.c)

# Add library target
add_library(m3 ${M3_SOURCES})

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/source>
    $<INSTALL_INTERFACE:include>)

# Install headers to wasm3 subdirectory
file(GLOB HEADER_FILES source/*.h)
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Create symlinks for backward compatibility
install(CODE "
    file(MAKE_DIRECTORY \${CMAKE_INSTALL_PREFIX}/include/wasm3)
    file(GLOB HEADER_FILES \${CMAKE_INSTALL_PREFIX}/include/wasm3/*.h)
    foreach(HEADER \${HEADER_FILES})
        get_filename_component(HEADER_NAME \${HEADER} NAME)
        execute_process(
            COMMAND \${CMAKE_COMMAND} -E create_symlink wasm3/\${HEADER_NAME} \${CMAKE_INSTALL_PREFIX}/include/\${HEADER_NAME}
        )
    endforeach()
")

# Install library
install(TARGETS m3
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
EOL
cmake_minimum_required(VERSION 3.12)
project(wasm3)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Add source files
file(GLOB M3_SOURCES source/*.c)

# Add library target
add_library(m3 SHARED ${M3_SOURCES})

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/source>
    $<INSTALL_INTERFACE:include/wasm3>)

# Install headers to wasm3 subdirectory
file(GLOB HEADER_FILES source/*.h)
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3 EXPORT wasm3Targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

# Generate and install CMake config files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    @ONLY)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    DESTINATION lib/cmake/wasm3)

install(EXPORT wasm3Targets
    FILE wasm3Targets.cmake
    NAMESPACE wasm3::
    DESTINATION lib/cmake/wasm3)
EOL

# Create CMake config file template
cat > source/wasm3Config.cmake.in << 'EOL'
@PACKAGE_INIT@

include(CMakeFindDependencyMacro)
find_dependency(uvwasi)
find_dependency(uv)

include("${CMAKE_CURRENT_LIST_DIR}/wasm3Targets.cmake")

set(WASM3_INCLUDE_DIRS "${CMAKE_INSTALL_PREFIX}/include")
set(WASM3_LIBRARIES m3)
EOL
cmake_minimum_required(VERSION 3.12)
project(wasm3)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Add source files
file(GLOB M3_SOURCES source/*.c)

# Add library target
add_library(m3 SHARED ${M3_SOURCES})

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/source>
    $<INSTALL_INTERFACE:include>)

# Install headers to wasm3 subdirectory
file(GLOB HEADER_FILES source/*.h)
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3 EXPORT wasm3Targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

# Generate and install CMake config files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    @ONLY)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    DESTINATION lib/cmake/wasm3)

install(EXPORT wasm3Targets
    FILE wasm3Targets.cmake
    NAMESPACE wasm3::
    DESTINATION lib/cmake/wasm3)
EOL

# Create CMake config file template
cat > source/wasm3Config.cmake.in << 'EOL'
@PACKAGE_INIT@

include(CMakeFindDependencyMacro)
find_dependency(uvwasi)
find_dependency(uv)

include("${CMAKE_CURRENT_LIST_DIR}/wasm3Targets.cmake")

set(WASM3_INCLUDE_DIRS "${CMAKE_INSTALL_PREFIX}/include")
set(WASM3_LIBRARIES m3)
EOL
# Add library target
add_library(m3 SHARED
    m3_api_libc.c
    m3_api_wasi.c
    m3_api_uvwasi.c
    m3_api_meta_wasi.c
    m3_api_tracer.c
    m3_bind.c
    m3_code.c
    m3_compile.c
    m3_core.c
    m3_env.c
    m3_exec.c
    m3_function.c
    m3_info.c
    m3_module.c
    m3_parse.c)

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/wasm3>)

# Install headers to wasm3 subdirectory
file(GLOB HEADER_FILES *.h)
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3 EXPORT wasm3Targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
EOL

    # Create main CMakeLists.txt
    cat > CMakeLists.txt << 'EOL'
cmake_minimum_required(VERSION 3.12)
project(wasm3)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Add source files
file(GLOB M3_SOURCES source/*.c)

# Add library target
add_library(m3 SHARED ${M3_SOURCES})

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/source>
    $<INSTALL_INTERFACE:include>)

# Add subdirectory
add_subdirectory(source)

# Generate and install CMake config files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    @ONLY)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    DESTINATION lib/cmake/wasm3)

install(EXPORT wasm3Targets
    FILE wasm3Targets.cmake
    NAMESPACE wasm3::
    DESTINATION lib/cmake/wasm3)

# Install library
install(TARGETS m3 EXPORT wasm3Targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

# Generate and install CMake config files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    @ONLY)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    DESTINATION lib/cmake/wasm3)

install(EXPORT wasm3Targets
    FILE wasm3Targets.cmake
    NAMESPACE wasm3::
    DESTINATION lib/cmake/wasm3)
EOL

# Create CMake config file template
cat > source/wasm3Config.cmake.in << 'EOL'
@PACKAGE_INIT@

include(CMakeFindDependencyMacro)
find_dependency(uvwasi)
find_dependency(uv)

include("${CMAKE_CURRENT_LIST_DIR}/wasm3Targets.cmake")

set(WASM3_INCLUDE_DIRS "${CMAKE_INSTALL_PREFIX}/include")
set(WASM3_LIBRARIES m3)
EOL
cmake_minimum_required(VERSION 3.12)
project(wasm3)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Add source files
file(GLOB M3_SOURCES source/*.c)

# Add library target
add_library(m3 SHARED ${M3_SOURCES})

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/source>
    $<INSTALL_INTERFACE:include>)

# Install headers to wasm3 subdirectory
file(GLOB HEADER_FILES source/*.h)
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3 EXPORT wasm3Targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

# Generate and install CMake config files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    @ONLY)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    DESTINATION lib/cmake/wasm3)

install(EXPORT wasm3Targets
    FILE wasm3Targets.cmake
    NAMESPACE wasm3::
    DESTINATION lib/cmake/wasm3)
EOL

# Create CMake config file template
cat > source/wasm3Config.cmake.in << 'EOL'
@PACKAGE_INIT@

include(CMakeFindDependencyMacro)
find_dependency(uvwasi)
find_dependency(uv)

include("${CMAKE_CURRENT_LIST_DIR}/wasm3Targets.cmake")

set(WASM3_INCLUDE_DIRS "${CMAKE_INSTALL_PREFIX}/include")
set(WASM3_LIBRARIES m3)
EOL
cmake_minimum_required(VERSION 3.12)
project(wasm3)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Add source files
file(GLOB M3_SOURCES source/*.c)

# Add library target
add_library(m3 SHARED ${M3_SOURCES})

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/source>
    $<INSTALL_INTERFACE:include>)

# Install headers to wasm3 subdirectory
file(GLOB HEADER_FILES source/*.h)
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Create wasm3 directory symlink for backward compatibility
install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink wasm3.h \${CMAKE_INSTALL_PREFIX}/include/wasm3/wasm3.h)")

# Install library
install(TARGETS m3 EXPORT wasm3Targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

# Generate and install CMake config files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    INSTALL_DESTINATION lib/cmake/wasm3
    PATH_VARS CMAKE_INSTALL_PREFIX)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    DESTINATION lib/cmake/wasm3)

install(EXPORT wasm3Targets
    FILE wasm3Targets.cmake
    NAMESPACE wasm3::
    DESTINATION lib/cmake/wasm3)
EOL

# Create CMake config file template
cat > source/wasm3Config.cmake.in << 'EOL'
@PACKAGE_INIT@

include(CMakeFindDependencyMacro)
find_dependency(uvwasi)
find_dependency(uv)

include("${CMAKE_CURRENT_LIST_DIR}/wasm3Targets.cmake")

set(WASM3_INCLUDE_DIR "@CMAKE_INSTALL_PREFIX@/include")
set(WASM3_LIBRARY_DIR "@CMAKE_INSTALL_PREFIX@/lib")
EOL
cmake_minimum_required(VERSION 3.12)
project(wasm3)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Add source files
file(GLOB M3_SOURCES source/*.c)

# Add library target
add_library(m3 SHARED ${M3_SOURCES})

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/source>
    $<INSTALL_INTERFACE:include>)

# Install headers to wasm3 subdirectory
file(GLOB HEADER_FILES source/*.h)
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3 EXPORT wasm3Targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

# Install CMake config files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    @ONLY)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    DESTINATION lib/cmake/wasm3)

install(EXPORT wasm3Targets
    FILE wasm3Targets.cmake
    NAMESPACE wasm3::
    DESTINATION lib/cmake/wasm3)
EOL

# Create CMake config file template
cat > source/wasm3Config.cmake.in << 'EOL'
@PACKAGE_INIT@

include(CMakeFindDependencyMacro)
find_dependency(uvwasi)
find_dependency(uv)

include("${CMAKE_CURRENT_LIST_DIR}/wasm3Targets.cmake")
EOL
cmake_minimum_required(VERSION 3.12)
project(wasm3)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Add source files
file(GLOB M3_SOURCES source/*.c)

# Add library target
add_library(m3 SHARED ${M3_SOURCES})

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/source>
    $<INSTALL_INTERFACE:include>)

# Install headers to wasm3 subdirectory
file(GLOB HEADER_FILES source/*.h)
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

# Generate and install CMake config files
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3Config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake
    INSTALL_DESTINATION lib/cmake/wasm3)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake
    DESTINATION lib/cmake/wasm3)

install(EXPORT wasm3Targets
    FILE wasm3Targets.cmake
    NAMESPACE wasm3::
    DESTINATION lib/cmake/wasm3)

export(EXPORT wasm3Targets
    FILE ${CMAKE_CURRENT_BINARY_DIR}/wasm3Targets.cmake
    NAMESPACE wasm3::)
EOL

# Create CMake config file template
cat > source/wasm3Config.cmake.in << 'EOL'
@PACKAGE_INIT@

include("${CMAKE_CURRENT_LIST_DIR}/wasm3Targets.cmake")
EOL
cmake_minimum_required(VERSION 3.12)
project(wasm3)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Add source files
file(GLOB M3_SOURCES source/*.c)

# Add library target
add_library(m3 SHARED ${M3_SOURCES})

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/source>
    $<INSTALL_INTERFACE:include>)

# Install headers to wasm3 subdirectory
file(GLOB HEADER_FILES source/*.h)
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

# Add executable if not building as library only
if(NOT BUILD_WASM3_LIBS)
    add_executable(wasm3 platforms/app/main.c)
    target_link_libraries(wasm3 PRIVATE m3)
    install(TARGETS wasm3 RUNTIME DESTINATION bin)
endif()

# Generate and install pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc
    @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc
    DESTINATION lib/pkgconfig)
EOL

# Create pkg-config file template
cat > source/wasm3.pc.in << 'EOL'
prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=${prefix}
libdir=${exec_prefix}/lib
includedir=${prefix}/include

Name: wasm3
Description: High performance WebAssembly interpreter
Version: 1.0.0
Libs: -L${libdir} -lm3
Cflags: -I${includedir}
EOL
cmake_minimum_required(VERSION 3.12)
project(wasm3)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Add source files
file(GLOB M3_SOURCES source/*.c)

# Add library target
add_library(m3 SHARED ${M3_SOURCES})

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/source>
    $<INSTALL_INTERFACE:include>)

# Install headers
file(GLOB HEADER_FILES source/*.h)
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

# Add executable if not building as library only
if(NOT BUILD_WASM3_LIBS)
    add_executable(wasm3 platforms/app/main.c)
    target_link_libraries(wasm3 PRIVATE m3)
    install(TARGETS wasm3 RUNTIME DESTINATION bin)
endif()
EOL
# Set minimum CMake version
cmake_minimum_required(VERSION 3.12)

# Add library target
add_library(m3 SHARED
    m3_api_libc.c
    m3_api_wasi.c
    m3_api_uvwasi.c
    m3_api_meta_wasi.c
    m3_api_tracer.c
    m3_bind.c
    m3_code.c
    m3_compile.c
    m3_core.c
    m3_env.c
    m3_exec.c
    m3_function.c
    m3_info.c
    m3_module.c
    m3_parse.c)

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/wasm3>)

# Install headers
file(GLOB HEADER_FILES "*.h")
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
EOL
cmake_minimum_required(VERSION 3.12)
project(wasm3)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Add source files
file(GLOB M3_SOURCES source/*.c)

# Add library target
add_library(m3 SHARED ${M3_SOURCES})

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Install headers
file(GLOB HEADER_FILES source/*.h)
install(FILES ${HEADER_FILES} DESTINATION include)

# Install library
install(TARGETS m3
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

# Add executable if not building as library only
if(NOT BUILD_WASM3_LIBS)
    add_executable(wasm3 platforms/app/main.c)
    target_link_libraries(wasm3 PRIVATE m3)
    install(TARGETS wasm3 RUNTIME DESTINATION bin)
endif()
EOL
project(wasm3)

# Set minimum CMake version
cmake_minimum_required(VERSION 3.12)

# Enable position independent code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Add library target
add_library(m3 SHARED
    m3_api_libc.c
    m3_api_wasi.c
    m3_api_uvwasi.c
    m3_api_meta_wasi.c
    m3_api_tracer.c
    m3_bind.c
    m3_code.c
    m3_compile.c
    m3_core.c
    m3_env.c
    m3_exec.c
    m3_function.c
    m3_info.c
    m3_module.c
    m3_parse.c)

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Install headers
file(GLOB HEADER_FILES "*.h")
install(FILES ${HEADER_FILES} DESTINATION include)

# Install library
install(TARGETS m3
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
EOL
    # Add install targets and link dependencies
    echo "find_library(UVWASI_LIB uvwasi REQUIRED)" >> source/CMakeLists.txt
    echo "find_library(UV_LIB uv REQUIRED)" >> source/CMakeLists.txt
    echo "target_link_libraries(m3 PUBLIC \${UVWASI_LIB} \${UV_LIB} m pthread dl)" >> source/CMakeLists.txt
    echo "target_link_options(m3 PUBLIC -Wl,--no-as-needed -Wl,--no-undefined -Wl,--enable-new-dtags)" >> source/CMakeLists.txt
    echo "set_target_properties(m3 PROPERTIES LINK_FLAGS \"-Wl,-rpath,/usr/local/lib\")" >> source/CMakeLists.txt
    echo "set_target_properties(m3 PROPERTIES INSTALL_RPATH \"/usr/local/lib\")" >> source/CMakeLists.txt
    echo "set_target_properties(m3 PROPERTIES BUILD_WITH_INSTALL_RPATH TRUE)" >> source/CMakeLists.txt
    echo "set_target_properties(m3 PROPERTIES POSITION_INDEPENDENT_CODE ON)" >> source/CMakeLists.txt
    echo "set_target_properties(m3 PROPERTIES OUTPUT_NAME m3)" >> source/CMakeLists.txt
    echo "set_target_properties(m3 PROPERTIES VERSION 1.0.0 SOVERSION 1)" >> source/CMakeLists.txt
    echo "install(TARGETS m3 LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)" >> source/CMakeLists.txt
    echo "file(GLOB HEADER_FILES \"\${CMAKE_CURRENT_SOURCE_DIR}/*.h\")
    install(FILES \${HEADER_FILES} DESTINATION include)" >> source/CMakeLists.txt
    # Configure CMake with correct visibility and linking settings
    mkdir -p build && cd build

    # Configure CMake with proper symbol visibility and linking
    CFLAGS="-fPIC -fvisibility=default" \
    CXXFLAGS="-fPIC -fvisibility=default" \
    LDFLAGS="-L/usr/local/lib" \
    PKG_CONFIG_PATH="/usr/local/lib/pkgconfig" \
    # Configure with static linking of uvwasi and uv
    cmake -DBUILD_WASM3_LIBS=ON \
          -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_C_FLAGS="-fPIC -fvisibility=default" \
          -DCMAKE_INSTALL_RPATH="/usr/local/lib" \
          -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
          -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON \
          -DCMAKE_EXE_LINKER_FLAGS="-Wl,--no-as-needed -Wl,--no-undefined" \
          -DCMAKE_SHARED_LINKER_FLAGS="-Wl,--no-as-needed -Wl,--no-undefined" \
          -DLIBUV_BUILD_SHARED=ON \
          -DUVWASI_BUILD_SHARED=ON \
          ..

    # After CMake configures, patch uvwasi to export symbols
    cd _deps/uvwasi-src/include
    sed -i '1i#ifndef UVWASI_EXPORT\n#define UVWASI_EXPORT __attribute__((visibility("default")))\n#endif' uvwasi.h
    sed -i 's/uvwasi_/UVWASI_EXPORT uvwasi_/g' uvwasi.h
    cd ..
    # Patch uvwasi CMakeLists.txt to ensure symbols are exported
    sed -i 's/add_library(uvwasi_a/add_library(uvwasi_a SHARED/' CMakeLists.txt
    echo "set_target_properties(uvwasi_a PROPERTIES C_VISIBILITY_PRESET default)" >> CMakeLists.txt
    echo "set_target_properties(uvwasi_a PROPERTIES VISIBILITY_INLINES_HIDDEN OFF)" >> CMakeLists.txt
    echo "set_target_properties(uvwasi_a PROPERTIES POSITION_INDEPENDENT_CODE ON)" >> CMakeLists.txt
    echo "set_target_properties(uvwasi_a PROPERTIES OUTPUT_NAME uvwasi)" >> CMakeLists.txt
    cd ..

    # Build and install
    make
    sudo make install
    # Install wasm3 headers
    sudo mkdir -p /usr/local/include
    sudo cp -r ../source/*.h /usr/local/include/
    sudo ldconfig
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
    if [ "$FORCE_BUILD" = "true" ]; then
        log "Force rebuilding libuv..."
        sudo rm -rf /usr/local/lib/libuv.so* /usr/local/include/uv*
    elif check_libuv_installed; then
        log "libuv is already installed, skipping (use --force_build to override)"
        return 0
    fi
    log "Installing libuv..."
    git clone https://github.com/libuv/libuv
    cd libuv
    mkdir -p build && cd build
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_C_FLAGS="-fPIC -fvisibility=default" -DCMAKE_INSTALL_RPATH="/usr/local/lib" -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON -DLIBUV_BUILD_SHARED=ON -DUVWASI_BUILD_SHARED=ON ..
    make
    sudo make install
    cd ../..
    rm -rf libuv
}

install_uvwasi() {
    if [ "$FORCE_BUILD" = "true" ]; then
        log "Force rebuilding uvwasi..."
        sudo rm -rf /usr/local/lib/libuvwasi.so* /usr/local/include/uvwasi*
    elif check_uvwasi_installed; then
        log "uvwasi is already installed, skipping (use --force_build to override)"
        return 0
    fi
    log "Installing uvwasi..."
    git clone https://github.com/nodejs/uvwasi
    cd uvwasi
    mkdir -p build && cd build
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_C_FLAGS="-fPIC -fvisibility=default" -DCMAKE_INSTALL_RPATH="/usr/local/lib" -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON -DLIBUV_BUILD_SHARED=ON -DUVWASI_BUILD_SHARED=ON ..
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
    install_libuv
    install_uvwasi
    install_wasm3
    sudo ldconfig

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

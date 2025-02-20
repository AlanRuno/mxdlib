#!/bin/bash

set -e

# Detect operating system
case "$(uname -s)" in
    Linux*)     
        ./install_dependencies_linux.sh "$@"
        ;;
    Darwin*)    
        ./install_dependencies_macos.sh "$@"
        ;;
    CYGWIN*|MINGW32*|MSYS*|MINGW*)
        ./install_dependencies_windows.sh "$@"
        ;;
    *)
        echo "Unsupported operating system"
        exit 1
        ;;
esac

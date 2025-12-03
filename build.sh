#!/bin/sh
set -e

# This script builds the command-line tools (Z80Dump, Z80Asm).

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
BUILD_DIR="$SCRIPT_DIR/build"

echo "--- Building Z80 tools (Release mode) ---"

cmake -B "$BUILD_DIR" -S "$SCRIPT_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" --config Release
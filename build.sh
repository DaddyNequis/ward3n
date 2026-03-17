#!/usr/bin/env zsh
# build.sh — one-shot build script for ward3n
# Usage: ./build.sh [clean]

set -e

REPO="$(cd "$(dirname "$0")" && pwd)"
ARM_TOOLCHAIN="$HOME/arm-toolchain/bin"
PICO_SDK="$HOME/pico-sdk"

export PATH="/opt/homebrew/bin:/usr/bin:/bin:$ARM_TOOLCHAIN:$PATH"
export PICO_SDK_PATH="$PICO_SDK"

if [[ "$1" == "clean" ]]; then
    rm -rf "$REPO/build"
fi

mkdir -p "$REPO/build"
cd "$REPO/build"

cmake .. -DPICO_TOOLCHAIN_PATH="$ARM_TOOLCHAIN" -DPICO_SDK_PATH="$PICO_SDK"

make -j"$(sysctl -n hw.logicalcpu)"

echo ""
echo "✓ Build complete:"
ls -lh "$REPO/build/ward3n.uf2"
echo ""
echo "Flash: hold BOOT, plug in RP2040 Zero, drag ward3n.uf2 to RPI-RP2 volume."

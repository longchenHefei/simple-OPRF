#!/usr/bin/env bash
# Build the vendored (MP-SPDZ-era) libOTe with SoftSpokenOT + MR_KYBER.
# Prefer this over latest upstream libOTe (which needs coproto and more RAM).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC_REPO="${SRC_REPO:-$ROOT/../MP-SPDZ-master/deps}"
DEST="$ROOT/deps/libOTe-mpspdz"

echo "==> Preparing libOTe tree at $DEST"
mkdir -p "$ROOT/deps"
if [[ ! -d "$DEST/libOTe" ]]; then
  rm -rf "$DEST"
  cp -a "$SRC_REPO/libOTe" "$DEST"
fi

# KyberOT lives beside libOTe in MP-SPDZ deps
if [[ ! -f "$DEST/KyberOT/KyberOT.h" ]]; then
  echo "==> Linking KyberOT"
  rm -rf "$DEST/KyberOT"
  ln -s "$SRC_REPO/KyberOT" "$DEST/KyberOT"
fi

# Ensure cryptoTools submodule content exists (already vendored)
test -d "$DEST/cryptoTools/cryptoTools"

BUILD="$DEST/out/build/linux"
mkdir -p "$BUILD"
cd "$BUILD"

echo "==> cmake configure (SoftSpoken + MR_KYBER)"
cmake "$DEST" \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_BOOST=ON \
  -DENABLE_SODIUM=ON \
  -DENABLE_RELIC=OFF \
  -DENABLE_SIMPLESTOT=OFF \
  -DENABLE_MR=OFF \
  -DENABLE_MR_KYBER=ON \
  -DENABLE_SOFTSPOKEN_OT=ON \
  -DENABLE_IKNP=ON \
  -DENABLE_KOS=OFF \
  -DENABLE_SILENTOT=OFF \
  -DENABLE_ALL_OT=OFF \
  -DBUILD_SHARED_LIBS=OFF

echo "==> build -j1 (low RAM)"
cmake --build . -j 1

echo "==> artifacts"
find "$BUILD" \( -name 'libOTe*' -o -name 'libcryptoTools*' -o -name 'libKyberOT*' \) | head -40
echo "LIBOTE_ROOT=$DEST"
echo "LIBOTE_BUILD=$BUILD"

#!/usr/bin/env bash
# Clone & build libOTe on Linux with SoftSpokenOT + MR-Kyber (PQ base OT).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DEPS="$ROOT/deps"
mkdir -p "$DEPS"
cd "$DEPS"

if [[ ! -d libOTe/.git ]]; then
  echo "==> Cloning libOTe (recursive)"
  rm -rf libOTe
  git clone --recursive https://github.com/osu-crypto/libOTe.git
fi

cd libOTe
# Ensure KyberOT submodule
if [[ ! -f KyberOT/KyberOT.h ]]; then
  echo "==> Fetching KyberOT submodule"
  git submodule update --init --recursive || true
  if [[ ! -f KyberOT/KyberOT.h ]]; then
    git clone https://github.com/osu-crypto/KyberOT.git KyberOT || \
      git clone https://github.com/ladnir/KyberOT.git KyberOT || true
  fi
fi

echo "==> Building libOTe (SoftSpoken + MR_KYBER), -j1 for low RAM"
# Prefer python build.py if present; else cmake directly.
export CMAKE_BUILD_PARALLEL_LEVEL=1

python3 build.py --setup --boost --sodium -- -DENABLE_BOOST=ON \
  -DENABLE_SODIUM=ON \
  -DENABLE_SOFTSPOKEN_OT=ON \
  -DENABLE_MR_KYBER=ON \
  -DENABLE_ALL_OT=OFF \
  -DENABLE_IKNP=ON \
  -DCMAKE_BUILD_TYPE=Release \
  || {
    echo "build.py failed; trying cmake fallback"
    mkdir -p out/build/linux && cd out/build/linux
    cmake ../../.. \
      -DCMAKE_BUILD_TYPE=Release \
      -DENABLE_BOOST=ON \
      -DENABLE_SODIUM=ON \
      -DENABLE_SOFTSPOKEN_OT=ON \
      -DENABLE_MR_KYBER=ON \
      -DENABLE_IKNP=ON
    cmake --build . -j 1
  }

echo "==> libOTe build done"
find out -name 'libOTe*' 2>/dev/null | head -20

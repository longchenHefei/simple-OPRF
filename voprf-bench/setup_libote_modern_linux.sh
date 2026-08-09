#!/usr/bin/env bash
# Build modern libOTe (SoftSpokenMalOtExt + MR_KYBER + coproto) for Ours OT bench and Gold.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DEPS="$ROOT/deps"
PREFIX="$DEPS/local"
mkdir -p "$DEPS" "$PREFIX"
cd "$DEPS"

export CMAKE_BUILD_PARALLEL_LEVEL=1
export MAKEFLAGS="-j1"

if [[ ! -d libOTe/.git ]]; then
  rm -rf libOTe
  git clone --recursive https://github.com/osu-crypto/libOTe.git
fi
cd libOTe

# KyberOT (Linux only; may be optional submodule)
if [[ ! -f thirdparty/KyberOT/KyberOT.h && ! -f KyberOT/KyberOT.h ]]; then
  echo "==> Ensuring KyberOT present"
  if [[ -d thirdparty ]]; then
    git clone --depth 1 https://github.com/osu-crypto/KyberOT.git thirdparty/KyberOT \
      || cp -a "$ROOT/../MP-SPDZ-master/deps/KyberOT" thirdparty/KyberOT
  else
    git clone --depth 1 https://github.com/osu-crypto/KyberOT.git KyberOT \
      || cp -a "$ROOT/../MP-SPDZ-master/deps/KyberOT" KyberOT
  fi
fi
# Ensure keccak object if using MP-SPDZ KyberOT
if [[ -f thirdparty/KyberOT/keccak4x/KeccakP-1600-times4-SIMD256.c && \
      ! -f thirdparty/KyberOT/keccak4x/KeccakP-1600-times4-SIMD256.o ]]; then
  (cd thirdparty/KyberOT/keccak4x && gcc -O3 -mavx2 -c KeccakP-1600-times4-SIMD256.c -o KeccakP-1600-times4-SIMD256.o)
fi
if [[ -f KyberOT/keccak4x/KeccakP-1600-times4-SIMD256.c && \
      ! -f KyberOT/keccak4x/KeccakP-1600-times4-SIMD256.o ]]; then
  (cd KyberOT/keccak4x && gcc -O3 -mavx2 -c KeccakP-1600-times4-SIMD256.c -o KeccakP-1600-times4-SIMD256.o)
fi

echo "==> build.py --setup (boost + sodium + coproto deps)"
python3 build.py --setup --boost --sodium --coproto 2>&1 | tee "$ROOT/results/raw/libote_setup.log" || \
  python3 build.py --setup --boost --sodium 2>&1 | tee "$ROOT/results/raw/libote_setup.log"

echo "==> build.py configure+build SoftSpoken + MR_KYBER"
python3 build.py -- \
  -DENABLE_BOOST=ON \
  -DENABLE_SODIUM=ON \
  -DENABLE_SOFTSPOKEN_OT=ON \
  -DENABLE_MR_KYBER=ON \
  -DENABLE_MR=ON \
  -DENABLE_IKNP=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  2>&1 | tee "$ROOT/results/raw/libote_build.log"

echo "==> install to $PREFIX"
python3 build.py --install --installPrefix="$PREFIX" 2>&1 | tee -a "$ROOT/results/raw/libote_build.log" \
  || cmake --install out/build/linux --prefix "$PREFIX"

echo "DONE. PREFIX=$PREFIX"
ls "$PREFIX/lib" 2>/dev/null | head || ls "$PREFIX" | head

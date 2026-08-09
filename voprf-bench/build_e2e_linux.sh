#!/usr/bin/env bash
# Build voprf_e2e + stark-garble for Linux loopback E2E (Route B).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${LIBOTE_PREFIX:-$ROOT/deps/local}"
LOTE="$ROOT/deps/libOTe"
BUILD_LOTE="$LOTE/out/build/linux"
source /home/cl/miniconda3/etc/profile.d/conda.sh 2>/dev/null || true
conda activate voprf-bench 2>/dev/null || true
source "$HOME/.cargo/env" 2>/dev/null || true
CXX="${CXX:-g++}"
mkdir -p "$ROOT/build"

# STARK CLI (Fig.10 half-gate AIR)
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/stark-garble/target}"
# Prefer in-tree target/
unset CARGO_TARGET_DIR
if [[ ! -x "$ROOT/stark-garble/target/release/stark-garble" ]]; then
  (cd "$ROOT/stark-garble" && cargo build --release)
fi

CIRCUIT="${AES_CIRCUIT:-$ROOT/../MP-SPDZ-master/Programs/Circuits/aes_128.txt}"

INC=(
  -I"$ROOT"
  -I"$PREFIX/include"
  -I"${CONDA_PREFIX:-/usr}/include"
  -I"$LOTE"
  -I"$LOTE/cryptoTools"
  -I"$LOTE/out/coproto"
  -I"$LOTE/out/macoro"
  -I"$LOTE/out/install/linux/include"
  -I"$BUILD_LOTE"
  -I"$BUILD_LOTE/libOTe"
  -I"$BUILD_LOTE/cryptoTools"
)
LIBDIRS=(
  -L"$PREFIX/lib"
  -L"${CONDA_PREFIX:-/usr}/lib"
  -L"$BUILD_LOTE/libOTe"
  -L"$BUILD_LOTE/cryptoTools/cryptoTools"
  -L"$BUILD_LOTE/coproto/coproto"
  -L"$BUILD_LOTE/macoro/macoro"
  -L"$BUILD_LOTE/thirdparty/KyberOT"
  -L"$LOTE/out/install/linux/lib"
)

OTE_LIB=OTe
[[ -f $BUILD_LOTE/libOTe/liblibOTe.a ]] && OTE_LIB=libOTe

$CXX -O3 -std=c++20 -pthread -march=native -maes -mpclmul -msse4.2 -mavx2 \
  -DENABLE_MR_KYBER \
  "${INC[@]}" \
  -o "$ROOT/build/voprf_e2e" "$ROOT/voprf_e2e.cpp" \
  "${LIBDIRS[@]}" \
  -l${OTE_LIB} -lcryptoTools -lcoproto -lmacoro -lKyberOT \
  -lboost_system -lboost_thread -lboost_filesystem -lboost_chrono -lboost_atomic \
  -L"$LOTE/out/install/linux/lib" -lsodium \
  -lssl -lcrypto -lgmp -lgmpxx -ldl -lpthread \
  -Wl,-rpath,"$PREFIX/lib" -Wl,-rpath,"$LOTE/out/install/linux/lib" \
  -Wl,-rpath,"${CONDA_PREFIX:-}/lib"

$CXX -O2 -std=c++17 -march=native -maes -mpclmul \
  -I"$ROOT" -I"${CONDA_PREFIX:-/usr}/include" \
  -o "$ROOT/build/test_aes_gc" "$ROOT/test_aes_gc.cpp" \
  -L"${CONDA_PREFIX:-/usr}/lib" -lcrypto \
  -Wl,-rpath,"${CONDA_PREFIX:-}/lib"

$CXX -O2 -std=c++17 -march=native -maes -mpclmul \
  -I"$ROOT" -I"${CONDA_PREFIX:-/usr}/include" \
  -o "$ROOT/build/dump_stark_witness" "$ROOT/dump_stark_witness.cpp" \
  -L"${CONDA_PREFIX:-/usr}/lib" -lcrypto \
  -Wl,-rpath,"${CONDA_PREFIX:-}/lib"

echo "OK: $ROOT/build/voprf_e2e"
echo "OK: $ROOT/stark-garble/target/release/stark-garble"
echo "circuit: $CIRCUIT"

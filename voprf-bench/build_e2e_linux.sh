#!/usr/bin/env bash
# Build voprf_e2e + stark-mmo for Linux loopback E2E.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${LIBOTE_PREFIX:-$ROOT/deps/local}"
LOTE="$ROOT/deps/libOTe"
BUILD_LOTE="$LOTE/out/build/linux"
CXX="${CXX:-clang++-19}"
if ! "$CXX" --version 2>/dev/null | grep -qi clang; then CXX=clang++-19; fi
mkdir -p "$ROOT/build"

# STARK CLI
if [[ ! -x "$ROOT/stark-mmo/target/release/stark-mmo" ]]; then
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env" 2>/dev/null || true
  (cd "$ROOT/stark-mmo" && CARGO_TARGET_DIR=target cargo build --release)
fi

INC=(
  -I"$ROOT"
  -I"$PREFIX/include"
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
  -L"$BUILD_LOTE/libOTe"
  -L"$BUILD_LOTE/cryptoTools/cryptoTools"
  -L"$BUILD_LOTE/coproto/coproto"
  -L"$BUILD_LOTE/macoro/macoro"
  -L"$BUILD_LOTE/thirdparty/KyberOT"
  -L"$LOTE/out/install/linux/lib"
)

OTE_LIB=OTe
[[ -f $BUILD_LOTE/libOTe/liblibOTe.a ]] && OTE_LIB=libOTe

$CXX -O3 -std=c++20 -stdlib=libstdc++ -pthread -march=native -maes -mpclmul -msse4.2 -mavx2 \
  -DENABLE_MR_KYBER \
  "${INC[@]}" \
  -o "$ROOT/build/voprf_e2e" "$ROOT/voprf_e2e.cpp" \
  "${LIBDIRS[@]}" \
  -l${OTE_LIB} -lcryptoTools -lcoproto -lmacoro -lKyberOT \
  -lboost_system -lboost_thread -lboost_filesystem -lboost_chrono -lboost_atomic \
  -L"$LOTE/out/install/linux/lib" -lsodium \
  -lssl -lcrypto -lgmp -lgmpxx -ldl -lpthread

# Also refresh garble_bench against shared header
$CXX -O3 -std=c++17 -march=native -maes -mpclmul \
  -o "$ROOT/build/garble_bench" "$ROOT/garble_bench.cpp"

echo "OK: $ROOT/build/voprf_e2e"
echo "OK: $ROOT/stark-mmo/target/release/stark-mmo"

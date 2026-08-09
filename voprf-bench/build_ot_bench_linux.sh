#!/usr/bin/env bash
# Build ot_bench against modern libOTe (clang-19 recommended on this host).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${LIBOTE_PREFIX:-$ROOT/deps/local}"
LOTE="$ROOT/deps/libOTe"
BUILD_LOTE="$LOTE/out/build/linux"
CXX="${CXX:-clang++-19}"
# Force clang if g++ picked by environment
if ! "$CXX" --version 2>/dev/null | grep -qi clang; then CXX=clang++-19; fi
mkdir -p "$ROOT/build"

INC=(
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

# Detect lib name
OTE_LIB=OTe
[[ -f $BUILD_LOTE/libOTe/liblibOTe.a ]] && OTE_LIB=libOTe

$CXX -O3 -std=c++20 -stdlib=libstdc++ -pthread -march=native -maes -mpclmul -msse4.2 -mavx2 \
  "${INC[@]}" \
  -o "$ROOT/build/ot_bench" "$ROOT/ot_bench.cpp" \
  "${LIBDIRS[@]}" \
  -l${OTE_LIB} -lcryptoTools -lcoproto -lmacoro -lKyberOT \
  -lboost_system -lboost_thread -lboost_filesystem -lboost_chrono -lboost_atomic \
  -L"$LOTE/out/install/linux/lib" -lsodium \
  -lssl -lcrypto -lgmp -lgmpxx -ldl -lpthread

echo "OK: $ROOT/build/ot_bench"

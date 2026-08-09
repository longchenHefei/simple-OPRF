#!/usr/bin/env bash
# Local (prefix) setup for Gold / PR-OPRF on Linux with ENABLE_PQ.
# Avoids system-wide sudo install where possible.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DEPS="$ROOT/deps"
PREFIX="$DEPS/local"
PROP="$DEPS/PR-OPRF"
mkdir -p "$PREFIX" "$ROOT/results/raw"
export CMAKE_PREFIX_PATH="$PREFIX:${CMAKE_PREFIX_PATH:-}"
export PATH="$PREFIX/bin:$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib:${LD_LIBRARY_PATH:-}"
export CMAKE_BUILD_PARALLEL_LEVEL=1
export MAKEFLAGS="-j1"

echo "==> Install emp-tool + emp-ot into $PREFIX"
cd "$DEPS"
if [[ ! -d emp-tool/.git ]]; then
  git clone --depth 1 https://github.com/emp-toolkit/emp-tool.git
fi
if [[ ! -d emp-ot/.git ]]; then
  git clone --depth 1 https://github.com/emp-toolkit/emp-ot.git
fi

build_emp() {
  local name="$1"
  mkdir -p "$name/cmake-build"
  cd "$name/cmake-build"
  cmake .. -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_BUILD_TYPE=Release
  cmake --build . -j 1
  cmake --install .
  cd "$DEPS"
}

if [[ ! -f "$PREFIX/include/emp-tool/emp-tool.h" ]]; then
  build_emp emp-tool
fi
if [[ ! -f "$PREFIX/include/emp-ot/emp-ot.h" ]]; then
  build_emp emp-ot
fi

if [[ ! -f "$PREFIX/include/libOTe/config.h" && ! -f "$PREFIX/lib/cmake/libOTe/libOTeConfig.cmake" ]]; then
  echo "ERROR: libOTe not installed to $PREFIX. Run setup_libote_modern_linux.sh first."
  exit 1
fi

echo "==> Configure PR-OPRF with ENABLE_PQ + FINEGRAIN + SMALLN"
cd "$PROP"
# Patch test sources to enable macros if not already
for f in test/oprf/test_malicious_oprf.cpp test/oprf/test_single_malicious_oprf.cpp; do
  if [[ -f "$f" ]]; then
    grep -q 'ENABLE_PQ' "$f" || sed -i '1i#define ENABLE_PQ\n#define ENABLE_FINEGRAIN\n#define ENABLE_SMALLN\n#define ENABLE_MALICIOUS' "$f"
  fi
done

# Also ensure libot-pre gets ENABLE_PQ via compile definition
mkdir -p build && cd build
cmake .. \
  -DCMAKE_PREFIX_PATH="$PREFIX" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_FLAGS="-DENABLE_PQ -DENABLE_FINEGRAIN -DENABLE_SMALLN -DENABLE_MALICIOUS" \
  2>&1 | tee "$ROOT/results/raw/pr_oprf_cmake.log"
cmake --build . -j 1 2>&1 | tee "$ROOT/results/raw/pr_oprf_build.log"

echo "==> binaries"
find . -type f -executable -name 'test_oprf*' | head

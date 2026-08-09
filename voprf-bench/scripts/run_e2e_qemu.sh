#!/usr/bin/env bash
set -eo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONDA_ENV=/home/cl/miniconda3/envs/voprf-bench
PREFIX=$ROOT/deps/local
QEMU=$ROOT/deps/bin/qemu-x86_64-static
export PATH="$CONDA_ENV/bin:$PATH"
export LD_LIBRARY_PATH="$PREFIX/lib:$CONDA_ENV/lib:${LD_LIBRARY_PATH:-}"
CIRCUIT="${AES_CIRCUIT:-$ROOT/../MP-SPDZ-master/Programs/Circuits/aes_128.txt}"
STARK=$ROOT/stark-garble/target/release/stark-garble
BIN=$ROOT/build/voprf_e2e
OUT=$ROOT/results/raw
PORT="${1:-19121}"
M="${2:-2}"
N=$((M * 256))
TABLES="${3:-offline}"
mkdir -p "$OUT"

for pid in /proc/[0-9]*; do
  cmd=$(tr '\0' ' ' <"$pid/cmdline" 2>/dev/null || true)
  case "$cmd" in *voprf_e2e*) kill -9 "${pid##*/}" 2>/dev/null || true ;; esac
done
sleep 0.5

SLOG=$OUT/e2e_loopback_${TABLES}_server.txt
CLOG=$OUT/e2e_loopback_${TABLES}_client.txt

"$QEMU" -cpu Haswell "$BIN" -role server -ip 127.0.0.1 -port "$PORT" -m "$M" -n "$N" \
  -tables "$TABLES" -stark "$STARK" -circuit "$CIRCUIT" >"$SLOG" 2>&1 &
SPID=$!
echo "SERVER_PID=$SPID m=$M n=$N tables=$TABLES"

for i in $(seq 1 900); do
  if ss -ltn 2>/dev/null | grep -q ":$PORT "; then echo LISTENING; break; fi
  if ! kill -0 "$SPID" 2>/dev/null; then echo SERVER_DIED early; cat "$SLOG"; exit 1; fi
  sleep 1
done

set +e
"$QEMU" -cpu Haswell "$BIN" -role client -ip 127.0.0.1 -port "$PORT" -m "$M" -n "$N" \
  -tables "$TABLES" -stark "$STARK" -circuit "$CIRCUIT" >"$CLOG" 2>&1
CEC=$?
set -e
echo "CLIENT_EXIT=$CEC"

for i in $(seq 1 1800); do
  if ! kill -0 "$SPID" 2>/dev/null; then break; fi
  sleep 1
done
kill -9 "$SPID" 2>/dev/null || true

echo "=== SERVER ==="; cat "$SLOG"
echo "=== CLIENT ==="; cat "$CLOG"
grep -q 'check: pass' "$CLOG" && grep -q 'check: pass' "$SLOG"

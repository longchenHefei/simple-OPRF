#!/usr/bin/env bash
# Run Linux loopback GC-VOPRF E2E (server + client on this host).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export LD_LIBRARY_PATH="$ROOT/deps/libOTe/out/install/linux/lib:$ROOT/deps/local/lib:${LD_LIBRARY_PATH:-}"

TABLES="${1:-offline}" # offline | online
PORT="${2:-19000}"
OUT="$ROOT/results/raw"
mkdir -p "$OUT"
BIN="$ROOT/build/voprf_e2e"
STARK="$ROOT/stark-mmo/target/release/stark-mmo"

if [[ ! -x "$BIN" ]]; then
  echo "missing $BIN — run build_e2e_linux.sh first" >&2
  exit 1
fi
if [[ ! -x "$STARK" ]]; then
  echo "missing $STARK — run build_e2e_linux.sh first" >&2
  exit 1
fi

SLOG="$OUT/e2e_loopback_${TABLES}_server.txt"
CLOG="$OUT/e2e_loopback_${TABLES}_client.txt"

# Kill leftovers by /proc (avoid pkill -f self-match)
for pid in /proc/[0-9]*; do
  cmd=$(tr '\0' ' ' <"$pid/cmdline" 2>/dev/null || true)
  case "$cmd" in
    *"/build/voprf_e2e"*) kill -9 "${pid##*/}" 2>/dev/null || true ;;
  esac
done
sleep 0.5

"$BIN" -role server -ip 127.0.0.1 -port "$PORT" -m 128 -n 32768 \
  -tables "$TABLES" -stark "$STARK" -stark-n 16384 \
  >"$SLOG" 2>&1 &
SPID=$!
echo "SERVER_PID=$SPID tables=$TABLES port=$PORT"

for i in $(seq 1 60); do
  if ss -ltn 2>/dev/null | grep -q ":$PORT "; then break; fi
  sleep 0.25
done

set +e
"$BIN" -role client -ip 127.0.0.1 -port "$PORT" -m 128 -n 32768 \
  -tables "$TABLES" -stark "$STARK" -stark-n 16384 \
  >"$CLOG" 2>&1
CEC=$?
set -e
echo "CLIENT_EXIT=$CEC"

for i in $(seq 1 120); do
  if ! kill -0 "$SPID" 2>/dev/null; then break; fi
  sleep 0.5
done
if kill -0 "$SPID" 2>/dev/null; then kill -9 "$SPID" 2>/dev/null || true; fi

echo "=== SERVER ($SLOG) ==="
cat "$SLOG"
echo "=== CLIENT ($CLOG) ==="
cat "$CLOG"

grep -q 'check: pass' "$CLOG" && grep -q 'check: pass' "$SLOG"

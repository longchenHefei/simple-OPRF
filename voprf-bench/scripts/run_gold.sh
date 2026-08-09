#!/usr/bin/env bash
set -euo pipefail
export LD_LIBRARY_PATH="/root/simple-OPRF/voprf-bench/deps/libOTe/out/install/linux/lib:/root/simple-OPRF/voprf-bench/deps/local/lib:/root/simple-OPRF/voprf-bench/deps/local-emp010/lib:${LD_LIBRARY_PATH:-}"
MODE="${1:-single}" # single | batch
PORT="${2:-16161}"
OUT=/root/simple-OPRF/voprf-bench/results/raw
mkdir -p "$OUT"

if [[ "$MODE" == "single" ]]; then
  BIN=/root/simple-OPRF/voprf-bench/deps/PR-OPRF/build/bin/test_oprf_test_single_malicious_oprf
  SLOG="$OUT/gold_single_server.txt"
  CLOG="$OUT/gold_single_client.txt"
else
  BIN=/root/simple-OPRF/voprf-bench/deps/PR-OPRF/build/bin/test_oprf_test_malicious_oprf
  SLOG="$OUT/gold_batch_server.txt"
  CLOG="$OUT/gold_batch_client.txt"
fi

# Kill leftovers of this exact binary path via /proc
bname=$(basename "$BIN")
for pid in /proc/[0-9]*; do
  cmd=$(tr '\0' ' ' <"$pid/cmdline" 2>/dev/null || true)
  case "$cmd" in
    *"$bname"*) kill -9 "${pid##*/}" 2>/dev/null || true ;;
  esac
done
sleep 1

"$BIN" 1 "$PORT" 127.0.0.1 >"$SLOG" 2>&1 &
SPID=$!
echo "SERVER_PID=$SPID MODE=$MODE PORT=$PORT"

for i in $(seq 1 120); do
  if ss -ltn | grep -q ":$((PORT+1)) "; then
    echo "NetIO listening on $((PORT+1))"
    break
  fi
  sleep 0.25
done

set +e
"$BIN" 2 "$PORT" 127.0.0.1 >"$CLOG" 2>&1
CEC=$?
set -e
echo "CLIENT_EXIT=$CEC"

# If client already failed, do not wait forever on a stuck server.
WAIT_MAX=600
if [[ "$CEC" -ne 0 ]]; then WAIT_MAX=15; fi
for i in $(seq 1 "$WAIT_MAX"); do
  if ! kill -0 "$SPID" 2>/dev/null; then
    echo "SERVER_EXITED"
    break
  fi
  sleep 1
done
if kill -0 "$SPID" 2>/dev/null; then
  echo "SERVER_TIMEOUT_KILL"
  kill -9 "$SPID" 2>/dev/null || true
fi

echo '=== SERVER ==='
cat "$SLOG"
echo '=== CLIENT ==='
cat "$CLOG"

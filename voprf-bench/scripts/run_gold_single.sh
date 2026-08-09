#!/usr/bin/env bash
set -euo pipefail
export LD_LIBRARY_PATH="/root/simple-OPRF/voprf-bench/deps/libOTe/out/install/linux/lib:/root/simple-OPRF/voprf-bench/deps/local/lib:/root/simple-OPRF/voprf-bench/deps/local-emp010/lib:${LD_LIBRARY_PATH:-}"
BIN=/root/simple-OPRF/voprf-bench/deps/PR-OPRF/build/bin/test_oprf_test_single_malicious_oprf
PORT="${1:-15151}"
OUT=/root/simple-OPRF/voprf-bench/results/raw
mkdir -p "$OUT"

# Clean leftovers via /proc without matching this script's argv
for pid in /proc/[0-9]*; do
  cmd=$(tr '\0' ' ' <"$pid/cmdline" 2>/dev/null || true)
  case "$cmd" in
    *test_oprf_test_single_malicious_oprf*) kill -9 "${pid##*/}" 2>/dev/null || true ;;
  esac
done
sleep 1

"$BIN" 1 "$PORT" 127.0.0.1 >"$OUT/gold_single_server.txt" 2>&1 &
SPID=$!
echo "SERVER_PID=$SPID"

# Wait for emp NetIO listen on PORT+1
for i in $(seq 1 60); do
  if ss -ltn | grep -q ":$((PORT+1)) "; then
    echo "NetIO listening on $((PORT+1))"
    break
  fi
  sleep 0.25
done

"$BIN" 2 "$PORT" 127.0.0.1 >"$OUT/gold_single_client.txt" 2>&1
CEC=$?
echo "CLIENT_EXIT=$CEC"

# Wait for server up to 5 minutes
for i in $(seq 1 300); do
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
cat "$OUT/gold_single_server.txt"
echo '=== CLIENT ==='
cat "$OUT/gold_single_client.txt"

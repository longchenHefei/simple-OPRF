#!/usr/bin/env bash
# Linux loopback GC-VOPRF E2E — uses qemu when host lacks AVX2 (SoftSpoken/KyberOT).
set -eo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TABLES="${1:-offline}"
PORT="${2:-19000}"
M="${3:-128}"
exec bash "$ROOT/scripts/run_e2e_qemu.sh" "$PORT" "$M" "$TABLES"

# GC-VOPRF vs Gold — Same-Machine Linux/x86 Online Benchmarks

**Date:** 2026-08-09  
**Host:** `pqc-research-node` (Debian 12, KVM guest)  
**Purpose:** Replace cross-machine Table V numbers with **one machine** measurements for Ours (component synthesis) and Gold (PR-OPRF official, PQ malicious).

> All numbers in the final comparison table are from **this host**, except STARK verify (no `rustc` here; Mac baseline used and labeled).

---

## 1. Machine

| Item | Value |
|---|---|
| Kernel | Linux 6.1.0-49-amd64 x86_64 |
| CPU | AMD EPYC 9655P (KVM), **2 vCPUs** |
| RAM | 1.9 GiB + 5 GiB swap |
| ISA | AVX2 **yes**, AVX-512 **yes**, AES-NI **yes** |
| Compiler (benches) | Debian clang 19.1.7 |
| Notes | Much weaker than Apple M5 Pro Mac baseline; expect ~30× slower SoftSpoken OT |

Raw: `results/raw/machine.txt`

---

## 2. Reproduce

```bash
cd voprf-bench

# Garbling
g++ -O3 -march=native -maes -mpclmul -std=c++17 -o build/garble_bench garble_bench.cpp
./build/garble_bench 128 | tee results/raw/garble_bench.txt

# SoftSpokenMal OT + Kyber base OT (needs modern libOTe; see setup_libote_modern_linux.sh)
CXX=clang++-19 bash build_ot_bench_linux.sh
export LD_LIBRARY_PATH="$PWD/deps/libOTe/out/install/linux/lib:$PWD/deps/local/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
./build/ot_bench -n 32768 -trials 3 -port 12121 -kyberBase | tee results/raw/ot_sweep_final.txt

# Gold PQ malicious (ENABLE_PQ + FINEGRAIN + SMALLN + MALICIOUS in test TUs)
# Requires emp-tool 0.1.0 + emp-ot 0.1.1 under deps/local-emp010 and patched libOTe AsioSocket
bash scripts/run_gold.sh single 22121   # logs → results/raw/gold_single_*.txt
bash scripts/run_gold.sh batch 24141    # n=1000; logs → results/raw/gold_batch_*.txt
```

**Critical fix applied:** do **not** `#define COPROTO_ASIO_DEBUG` in `AsioSocket.h` (races with 2 `io_context` threads → `std::terminate`). Fixed in both `deps/libOTe/out/coproto/...` and `deps/local/include/coproto/...`.

---

## 3. Ours — component results (this host)

### 3.1 Garbling / GC eval (`garble_bench`)

Synthetic AES-128-scale circuit: **6553 AND + 24000 XOR**, half-gates + MMO AES-128, **AES-NI**.

| Metric | Linux (this host) | Mac M5 Pro (ref only) |
|---|---|---|
| garble ms/circuit | **0.509** | ~0.21 |
| eval ms/circuit | **0.570** | ~0.066 |
| tables | **209696 B (204.78 KiB)** | ~205 KiB |

Log: `results/raw/garble_bench.txt`

### 3.2 SoftSpokenMal OT extension (online only; fake base OT)

128-bit messages, `baseOtCount=128`, base OT **not** timed in extension path.

| n | recv ms (typ.) | send ms (typ.) | one-side KB | both-dir KB (×2) |
|---|---|---|---|---|
| 128 | ~176 | ~176 | 10.5 | 21.0 |
| 256 | ~176 | ~176 | 11.5 | 23.0 |
| 512 | ~176 | ~176 | 13.5 | 27.0 |
| 1024 | ~176 | ~176 | 17.5 | 35.0 |
| **32768** | **~176** | **~176** | **265.5** | **531.0** |

Mac SoftSpokenMal n=32768 was ~5.6 ms / ~531 KB both-dir → **same communication**, ~**31×** slower time here.

Log: `results/raw/ot_sweep_final.txt` (also earlier `ot_sweep.txt`).

### 3.3 Kyber / MR base OT (**offline / one-time**)

`MasnyRindalKyber`, n=128 (= SoftSpoken `baseOtCount()`).

| Side | Time (typ.) | Comm (one-side bytes) |
|---|---|---|
| sender / receiver | ~10–51 ms (jitter) | ~754 KB (~736 KiB) |

**Not** included in online client. Log: Kyber section of `ot_sweep_final.txt`.

### 3.4 STARK

`rustc` **not installed** on this host → **STARK 非本机**.  
For synthesis we use Mac verify **2.8 ms / batch (m=128)** and label it.

### 3.5 Synthesized Ours online (m=128)

**Working point:** one SoftSpokenMal extension with **n=32768** amortized over **m=128** evals (same as Mac/paper synthesis).

Formulas (unchanged):

```
online_client_ms/eval ≈ (OT_online_ms / m) + GC_eval_ms + (STARK_verify_ms / m)
online_comm_KB/eval (tables offline) ≈ OT_both_dir_KB / m
online_comm_KB/eval (tables online)  ≈ OT_both_dir_KB / m + tables_KB + (proof_KB / m)
```

Plug-in (this host):

| Input | Value | Source |
|---|---|---|
| OT_online_ms | **176** | SoftSpokenMal n=32768 wall (send/recv concurrent) |
| OT_both_dir_KB | **531.0** | 2 × 265.505 |
| GC_eval_ms | **0.570** | garble_bench |
| STARK_verify_ms | **2.8** | Mac (labeled) |
| tables_KB | **204.78** | garble_bench |
| proof_KB/m | **≈0** | Mac tables-online ≈210 KB ≈ OT/m + tables |

**Results:**

| Variant | Online client/eval | Online comm/eval | Online rounds | Notes |
|---|---|---|---|---|
| Ours (tables offline) | **1.97 ms** = 176/128 + 0.570 + 2.8/128 | **4.15 KB** = 531/128 | **2** | STARK verify 非本机 |
| Ours (tables online) | **1.97 ms** (same compute path) | **~209 KB** = 4.15 + 204.78 | **2** | tables dominate |

Server offline prove (Mac ~5.2 s/circuit) **not re-measured** here (no STARK).

---

## 4. Gold — PR-OPRF PQ malicious (this host)

Repo: `deps/PR-OPRF` (`gconeice/PR-OPRF`), built with `ENABLE_PQ`, `ENABLE_MALICIOUS`, `ENABLE_FINEGRAIN`, SoftSpoken VOLE (`ENABLE_SS`), emp-tool **0.1.0**.

Loopback: party `1` = ALICE/server, party `2` = BOB/client, NetIO on `PORT+1`, libOTe Asio on `PORT`.

### 4.1 Single eval (`test_oprf_test_single_malicious_oprf`, n=1)

| | Server (ALICE) | Client (BOB) |
|---|---|---|
| offline_us | 469644 (~470 ms) | 470167 (~470 ms) |
| offline emp B | 179792 | 28592 |
| offline libOT sent B | 440869 | 341541 |
| **online_us** | **629** | **471** |
| **online emp B** | **2640** | **240** |
| check | — | **pass** |

- **Online client/eval:** **0.471 ms**
- **Online server/eval:** **0.629 ms**
- **Online comm/eval (emp both dirs):** 2640+240 = **2880 B ≈ 2.81 KB** (libOT online delta ≈ 0 after setup)
- **Online rounds:** interactive online ≈ **3–4** (msg / response / χ / opening); paper FS-style **3** after Fiat–Shamir packaging

Logs: `results/raw/gold_single_client_ok.txt`, `gold_single_server_ok.txt` (also latest `gold_single_*.txt`).

### 4.2 Batch (`test_oprf_test_malicious_oprf`, `ENABLE_SMALLN` → **n=1000**)

`setup` + `setup_malicious` timed as offline; first `batch_eval` still runs **lazy `malicious_offline`** before the FINEGRAIN “Offline point”. **True online** is timed **after** that checkpoint.

| | Server | Client |
|---|---|---|
| offline (setup*) | ~7.48 s | ~7.48 s |
| lazy offline inside first eval (emp Δ to Offline point) | large (~2.2 MB server) | small |
| **true_online_us / eval** | **1.28 µs** | **15.14 µs** |
| **true_online emp B / eval** | **48.1** | **48.0** |
| check | — | **pass** |

- **Online wall/eval ≈ max(sides) ≈ 15 µs** (interactive; client-bound here)
- **Online emp both dirs ≈ 96.1 B/eval** (~0.094 KB/eval)
- Amortized offline is **huge** at n=1000 on this 2-vCPU / 2 GiB VM (~7.5 s + multi-MB)

Logs: `results/raw/gold_batch_*.txt`

### 4.3 Classic (non-PQ) Gold

**Not run** in this pass (PQ path was the blocker on macOS; classic deferred). Do not mix paper AWS classic numbers into the same-machine table without a new run.

---

## 5. Same-machine final comparison table

**Ours working point:** m=128 (OT n=32768 amortized).  
**Gold working points:** single n=1; batch n=1000.

| Work | Online rounds | Online comm/eval | Online client/eval | Online server/eval | Verifiability | Notes/source |
|---|---|---|---|---|---|---|
| Ours (tables offline) | 2 | **4.15 KB** | **1.97 ms** | (GC+OT server share; STARK prove offline) | public STARK verify | This host OT+GC; STARK verify **Mac** |
| Ours (tables online) | 2 | **~209 KB** | **1.97 ms** | same | public STARK | tables 204.8 KB/eval |
| Gold malicious PQ (single) | ~3–4 | **~2.81 KB** (emp) | **0.47 ms** | **0.63 ms** | designated VOLE-ZK | This host, official PR-OPRF |
| Gold malicious PQ (batch n=1000) | ~3–4 | **~0.094 KB** (emp true-online) | **~0.015 ms** | **~0.001 ms** | designated VOLE-ZK | True-online after Offline point; offline ~7.5 s |

CSV: `results/comparison_table.csv`

---

## 6. Short analysis (for paper discussion)

1. **Rounds:** Ours stays **2**; Gold online remains **multi-message (~3–4)** even when amortized.
2. **Small-batch amortization:** Ours quotes **m=128**. Gold’s sub-KB / ~15 µs online at **n=1000** still sits on **multi-second + multi-MB offline** on this host; do **not** compare Gold’s 1.9 KB paper figure (large-n AWS) to Ours m=128 without stating n.
3. **Verifiability:** Ours = **public** STARK verify; Gold = **designated** VOLE-ZK verifier.
4. **Honest disadvantages (Ours):** tables-online communication (~209 KB/eval); server STARK prove offline (Mac ~5.2 s/circuit, not re-run here).
5. **vs Mac baseline:** OT time ~31× slower; GC eval ~8.6× slower; OT bytes match. **Do not** drop Mac numbers into this table as “same machine.”

### Can these replace paper Table V Ours/Gold rows?

**Yes, for a Linux/x86 same-machine column**, with footnotes:

- STARK verify (Ours) still Mac unless `stark-mmo` is rebuilt here;
- Gold classic optional row missing;
- This VM is **not** representative of a high-end client (2 vCPU / 2 GiB); for a “laptop-class” claim prefer Mac Ours + this Gold, or re-run on a larger Linux box.

---

## 7. Raw artifacts

| File | Content |
|---|---|
| `results/raw/machine.txt` | uname / lscpu / memory |
| `results/raw/garble_bench.txt` | GC bench |
| `results/raw/ot_sweep_final.txt` | OT sweep + Kyber |
| `results/raw/gold_single_*_ok.txt` | Gold single |
| `results/raw/gold_batch_*.txt` | Gold batch n=1000 |
| `results/comparison_table.csv` | Final table |

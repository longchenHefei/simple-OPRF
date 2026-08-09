# GC-VOPRF Route B — True Fig.9–10 E2E (AES datapath + half-gate STARK)

**Date:** 2026-08-09  
**Host:** `cl` (Ubuntu, QEMU Virtual CPU 2.5+)  
**Status:** **True E2E** — client \(y_i = F_k(x_i) = H_2(x_i,\mathrm{AES}_k(H_1(x_i)))\) matches plaintext for full batch \(m=128\).

> This supersedes the earlier Fib-placeholder / component-synthesis numbers.  
> Fib stub moved to `stark-mmo-fib-stub/`. New AIR: `stark-garble/` (half-gate + key-cm binding).

---

## 1. Machine

| Item | Value |
|---|---|
| Kernel | Linux 7.0.0-27-generic x86_64 |
| CPU | QEMU Virtual CPU 2.5+, **64 vCPUs** |
| ISA | SSE4.2 + AES-NI; **no AVX2 on host** |
| RAM | 192 GiB |
| Workaround | SoftSpoken / KyberOT binaries run under `qemu-x86_64-static -cpu Haswell` |
| Compiler | conda g++ 15.2.0; rustc 1.97.1 |

Raw: `results/raw/machine.txt`

---

## 2. Protocol (paper Fig.9–10)

- \(F_k(x)=H_2(x,\mathrm{AES}_k(H_1(x)))\), AES-128  
- \(H_1,H_2\): **SHA-256** (\(H_1\) truncated to 128 bits)  
- Circuit: Bristol Fashion `aes_128.txt` (**6400 AND / 30263 XOR**, bit order BErev)  
- Half-gates + fixed-key AES MMO; KeySchedule local for \(cm\); key bits as garbler wires  
- Probe-resilient: \(s=2\), \(n=256\) shares / eval; SoftSpokenMal \(m\cdot n=32768\)  
- Base OT: MasnyRindalKyber (offline)  
- STARK: winterfell half-gate bit AIR + public binding \((cm,H(GC),R,out)\); **not Fib**

---

## 3. Reproduce

```bash
cd voprf-bench
# deps: conda env voprf-bench + setup libOTe SoftSpoken+MR_KYBER (AVX2 build)
# Host without AVX2: scripts use qemu-x86_64-static (deps/bin/)

bash build_e2e_linux.sh   # or manual g++ link as in RESULTS history
bash scripts/run_e2e_loopback.sh offline 19000
bash scripts/run_e2e_loopback.sh online  19001

# Unit: plaintext + GC == AES-NI
AES_CIRCUIT=../MP-SPDZ-master/Programs/Circuits/aes_128.txt ./build/test_aes_gc
```

**AsioSocket:** do not enable `COPROTO_ASIO_DEBUG` (race → terminate).

---

## 4. STARK (Fig.10-style, this host)

| Metric | Value |
|---|---|
| AIR | half-gate Tg/Te bit constraints + cm/H(GC)/R binding |
| Field | winterfell f64::BaseElement |
| Params | queries=27, blowup=8, grinding=16, FRI fold=8 |
| Trace | \(6400\times 128 \to 2^{20}\) rows |
| Prove | **~30.7 s** / circuit-0 witness |
| Verify | **~0.74 ms** |
| Proof size | **~80 KiB** (~80525 B) |

Negative: tampering embedded `H(GC)` in proof blob → binding check fails.  
Logs: `results/raw/stark_prove_one.txt`, `stark_verify_one.txt`

Paper Mac reference (~5 s prove / ~3 ms verify / circuit): same order of magnitude for verify; prove slower here (bit-expanded AIR + different params).

---

## 5. Loopback E2E (\(m=128\)) — this host via qemu

### tables offline

| Side | offline_ms | online_ms | online_ms/eval | online_B | online_B/eval |
|---|---|---|---|---|---|
| client | 32950 | 616 | 4.81 | 1667342 | 13026 |
| server | (same session) | | | | |

- `plaintext_Fk_match: 128/128`  
- `stark_ok: 1`, `bind_ok: 1`, `check: pass`  
- Logs: `results/raw/e2e_loopback_offline_{server,client}.txt`

### tables online

| Side | online_ms | online_ms/eval | notes |
|---|---|---|---|
| client/server | 745 | 5.82 | tables + OT + proof online |

- `plaintext_Fk_match: 128/128`, `check: pass`  
- Logs: `results/raw/e2e_loopback_online_{server,client}.txt`

Online ≈ **2 rounds**; Kyber base OT counted in offline.

---

## 6. Cut from Fib / synthesis

| Old (Fib E2E) | New (Route B) |
|---|---|
| Synthetic AND chain | Bristol AES-128 GC |
| OT touched only | OT pads → share labels → EvalGC |
| Fib AIR | half-gate garbling AIR |
| `check: pass` = Fib verify | `check: pass` = STARK + \(y=F_k(x)\) |

---

## 7. Notes

- Bristol gate counts differ slightly from paper’s ~6553 AND / 24000 XOR; correctness vs AES-NI verified.  
- Host CPU lacks AVX2; timings include qemu TCG overhead for OT/GC path. STARK prove/verify run as native Rust (spawned) but may be invoked from qemu parent.  
- `stark-mmo-fib-stub/` retained for archaeology only.

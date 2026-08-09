# stark-garble — Fig.10-style half-gate garbling STARK

This crate proves **half-gate garbling correctness** (Tg/Te identities w.r.t. MMO
witness) and binds public `(cm, H(GC), R_root, out_decode)`. It is **not** the
Fibonacci placeholder formerly in `stark-mmo/` (now `../stark-mmo-fib-stub/`).

## Prove / verify

```bash
cargo build --release
./target/release/stark-garble prove -w witness.bin -o proof.bin
./target/release/stark-garble verify -i proof.bin [--public public.bin]
```

Witness format is documented in `src/main.rs`.

## Parameters (RESULTS)

- Field: winterfell `f64::BaseElement`
- queries=27, blowup=8, grinding=16, FRI folding=8
- Trace: one row per (AND gate, bit); AES-128 Bristol ≈ 6400 AND → 2^20 rows

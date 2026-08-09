# stark-mmo

Minimal [winterfell](https://github.com/facebook/winterfell) STARK prove/verify CLI for GC-VOPRF E2E.

## Statement

Fibonacci-style iterative AIR (`fib_small`, 2 terms/row), sequence length `--n` (power of two).
Used as a **public-verify prototype** standing in for the paper’s MMO/AES-garbling STARK — not a full AES-circuit AIR.

## Build / run

```bash
source "$HOME/.cargo/env"   # after rustup
CARGO_TARGET_DIR=target cargo build --release
./target/release/stark-mmo prove -o proof.bin --n 16384
./target/release/stark-mmo verify -i proof.bin
```

Integrated via `../build_e2e_linux.sh` and `../voprf_e2e.cpp` (shells out to this binary).

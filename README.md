# simple-OPRF

Oblivious Pseudorandom Function (OPRF) research code built on top of [MP-SPDZ](https://github.com/data61/MP-SPDZ) Yao garbled circuits.

This repository contains a modified MP-SPDZ Yao stack and patch-style source files for OPRF evaluation / reconstruction (inspired by PPSS-style share reconstruction with OPRF masks).

## Repository layout

```text
.
├── MP-SPDZ-master/          # Modified MP-SPDZ tree (Yao GC + OT)
├── YaoGarbler.*.cpp         # Garbler-side patch variants (init / oprf / reconstruct)
├── YaoEvaluator.*.cpp       # Evaluator-side patch variants (init / oprf / reconstruct)
├── OTExtensionWithMatrix.cpp
└── maven.sh                 # Local Java/Maven environment helper (optional)
```

| Path | Role |
|------|------|
| `MP-SPDZ-master/` | Full MP-SPDZ codebase with Yao / OT changes used by this project |
| `YaoGarbler.init.cpp` / `YaoGarbler.oprf.cpp` / `YaoGarbler.reconstruct.cpp` | Garbler-side working copies for different protocol phases |
| `YaoEvaluator.init.cpp` / `YaoEvaluator.cpp.oprf.cpp` / `YaoEvaluator.reconstruct.cpp` | Evaluator-side working copies (OPRF + share reconstruction) |
| `OTExtensionWithMatrix.cpp` | OT extension related changes |

The active Yao sources used by the build live under `MP-SPDZ-master/Yao/` (for example `YaoGarbler.cpp`, `YaoEvaluator.cpp`). The top-level `Yao*.cpp` files are patch / experiment snapshots that can be copied into that directory when switching phases.

## What the OPRF path does

At a high level, the modified evaluator path:

1. Obtains garbled-circuit related values / shares from the Yao protocol.
2. Derives OPRF masks (`rou_i`) via hashing (SHA-256 over combined inputs).
3. Forms masked values `e_i = s_i XOR rou_i` and reconstructs shares as `s_i = e_i XOR rou_i`.

See comments in `YaoEvaluator.reconstruct.cpp` for the PPSS-style reconstruction sketch.

## Build & run (MP-SPDZ Yao)

Dependencies and build steps follow upstream MP-SPDZ. From the MP-SPDZ tree:

```bash
cd MP-SPDZ-master

# Install dependencies as required by your platform, then build Yao party
make -j yao-party.x

# Example Yao run script (after compiling a circuit / program)
./Scripts/yao.sh <program>
```

For general setup, compilation, and networking options, see the upstream docs:

- https://mp-spdz.readthedocs.io/
- `MP-SPDZ-master/README.md`

> Note: this repository is research / experiment oriented. Exact flags, programs, and patch application steps may depend on your local experiment setup.

## Applying patches

Typical workflow:

1. Copy the desired top-level variant into `MP-SPDZ-master/Yao/`, e.g.:

   ```bash
   cp YaoGarbler.oprf.cpp MP-SPDZ-master/Yao/YaoGarbler.cpp
   cp YaoEvaluator.cpp.oprf.cpp MP-SPDZ-master/Yao/YaoEvaluator.cpp
   ```

2. Rebuild:

   ```bash
   cd MP-SPDZ-master
   make -j yao-party.x
   ```

Backup copies of intermediate Yao sources also exist under `MP-SPDZ-master/Yao/*.backup`.

## Attribution

- Base framework: [MP-SPDZ](https://github.com/data61/MP-SPDZ) (Data61 / CSIRO and contributors)
- OT / circuit dependencies under `MP-SPDZ-master/deps/` follow their respective upstream licenses

## License

MP-SPDZ and bundled dependencies retain their original licenses (see `MP-SPDZ-master/License.txt` and files under `MP-SPDZ-master/bin/`). Project-specific modifications in this repository are provided for research use unless otherwise stated.

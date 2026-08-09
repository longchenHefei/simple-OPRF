# Patches applied for Linux/x86 Gold + libOTe benches

Apply against upstream clones (see `results/RESULTS.md`):

```bash
# Gold
git clone https://github.com/gconeice/PR-OPRF deps/PR-OPRF
cd deps/PR-OPRF && git apply ../../patches/pr-oprf-linux-bench.patch
cp ../../patches/FindlibOTe.cmake cmake/
# optional: FindGMP.cmake

# libOTe / coproto AsioSocket: remove unconditional COPROTO_ASIO_DEBUG
# (races with 2 io_context threads). See asiosocket-disable-debug.patch
```


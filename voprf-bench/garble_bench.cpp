// Half-gates + fixed-key AES-128 (MMO) garble/eval microbench.
#include "gc_mmo.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>

using namespace gc_mmo;

static double ms_since(std::chrono::steady_clock::time_point t0) {
    using namespace std::chrono;
    return duration<double, std::milli>(steady_clock::now() - t0).count();
}

int main(int argc, char** argv) {
    int trials = 64;
    if (argc > 1) trials = std::atoi(argv[1]);
    if (trials < 1) trials = 1;

    Circuit c;
    std::mt19937_64 rng{42};
    Block key = random_block(rng);
    FixedKeyAES aes(key);

    {
        auto gr = garble(c, aes, rng);
        (void)evaluate(c, aes, gr, true, false);
    }

    double garble_ms = 0, eval_ms = 0;
    u64 tables_b = 0;
    volatile u8 sink = 0;
    for (int t = 0; t < trials; ++t) {
        auto t0 = std::chrono::steady_clock::now();
        auto gr = garble(c, aes, rng);
        garble_ms += ms_since(t0);
        tables_b = tables_bytes(gr);

        t0 = std::chrono::steady_clock::now();
        auto out = evaluate(c, aes, gr, (t & 1) != 0, (t & 2) != 0);
        eval_ms += ms_since(t0);
        sink ^= out.b[0];
    }
    printf("sink: %u\n", (unsigned)sink);

    printf("garble_bench (half-gates + MMO AES-128)\n");
    printf("AES backend: %s\n", aes_backend_name());
    printf("circuit: AND=%llu XOR=%llu (synthetic AES-128 scale)\n",
           (unsigned long long)c.n_and, (unsigned long long)c.n_xor);
    printf("trials: %d\n", trials);
    printf("garble_ms_per_circuit: %.6f\n", garble_ms / trials);
    printf("eval_ms_per_circuit: %.6f\n", eval_ms / trials);
    printf("tables_bytes: %llu (%.2f KiB)\n",
           (unsigned long long)tables_b, tables_b / 1024.0);
    printf("tables_KB: %.3f\n", tables_b / 1024.0);
    return 0;
}

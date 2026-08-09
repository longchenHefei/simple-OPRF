// Microbench: Bristol AES-128 half-gate garble/eval.
#include "gc_mmo.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <random>
#include <string>

using namespace gc_mmo;

int main(int argc, char** argv) {
    int trials = argc > 1 ? std::atoi(argv[1]) : 8;
    const char* circ_path = std::getenv("AES_CIRCUIT");
    std::string path = circ_path && *circ_path
                           ? circ_path
                           : "../MP-SPDZ-master/Programs/Circuits/aes_128.txt";
    auto circ = load_bristol(path);
    std::mt19937_64 rng{1};
    Block mmo_key = random_block(rng);
    FixedKeyAES aes(mmo_key);

    double garble_ms = 0, eval_ms = 0;
    u64 tables = 0;
    for (int t = 0; t < trials; ++t) {
        auto t0 = std::chrono::steady_clock::now();
        auto gr = garble_circuit(circ, mmo_key, aes, rng);
        auto t1 = std::chrono::steady_clock::now();
        std::vector<u8> bits(256);
        for (int i = 0; i < 256; ++i) bits[i] = static_cast<u8>(rng() & 1);
        std::vector<Block> labs(256);
        for (int i = 0; i < 256; ++i)
            labs[i] = label_for_bit(gr.wire0[i], gr.delta, bits[i]);
        auto t2 = std::chrono::steady_clock::now();
        auto outs = eval_circuit_labels(circ, aes, gr, labs);
        auto t3 = std::chrono::steady_clock::now();
        (void)decode_outputs(gr, outs);
        garble_ms += std::chrono::duration<double, std::milli>(t1 - t0).count();
        eval_ms += std::chrono::duration<double, std::milli>(t3 - t2).count();
        tables = tables_bytes(gr);
        (void)t2;
    }
    std::cout << "circuit: " << path << "\n";
    std::cout << "and: " << circ.n_and << " xor: " << circ.n_xor << "\n";
    std::cout << "aes_backend: " << aes_backend_name() << "\n";
    std::cout << "garble_ms_per_circuit: " << (garble_ms / trials) << "\n";
    std::cout << "eval_ms_per_circuit: " << (eval_ms / trials) << "\n";
    std::cout << "tables_bytes: " << tables << "\n";
    return 0;
}

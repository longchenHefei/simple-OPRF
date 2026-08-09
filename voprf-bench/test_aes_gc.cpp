// Unit test: Bristol AES circuit plaintext + GC eval == AES-NI F_k path.
#include "gc_mmo.hpp"
#include "plaintext_oprf.hpp"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <random>
#include <string>
#include <vector>

using namespace gc_mmo;
using namespace plaintext_oprf;

static std::string default_circuit() {
    const char* env = std::getenv("AES_CIRCUIT");
    if (env && *env) return env;
    return "../MP-SPDZ-master/Programs/Circuits/aes_128.txt";
}

int main() {
    auto circ = load_bristol(default_circuit());
    std::cout << "circuit gates=" << circ.n_gates << " wires=" << circ.n_wires
              << " and=" << circ.n_and << " xor=" << circ.n_xor
              << " in0=" << circ.n_input0 << " in1=" << circ.n_input1
              << " out=" << circ.n_output << "\n";
    std::cout << "aes_backend: " << aes_backend_name() << "\n";

    std::mt19937_64 rng{0xC0FFEE};
    int trials = 8;
    int fail = 0;
    for (int t = 0; t < trials; ++t) {
        Block key = random_block(rng);
        Block pt = random_block(rng);
        Block ct_ref = aes_encrypt(key, pt);

        std::vector<u8> in_bits(256);
        block_to_bits128(key, in_bits.data());
        block_to_bits128(pt, in_bits.data() + 128);
        auto out_bits = eval_circuit_plain(circ, in_bits);
        Block ct_circ = bits128_to_block(out_bits.data());
        if (!blocks_eq(ct_ref, ct_circ)) {
            std::cerr << "FAIL plain circuit vs AES-NI trial " << t << "\n";
            fail++;
            continue;
        }

        Block mmo_key = random_block(rng);
        FixedKeyAES mmo(mmo_key);
        auto gr = garble_circuit(circ, mmo_key, mmo, rng);
        std::vector<Block> labels(256);
        for (int i = 0; i < 128; ++i)
            labels[i] = label_for_bit(gr.wire0[i], gr.delta, in_bits[i]);
        for (int i = 0; i < 128; ++i)
            labels[128 + i] = label_for_bit(gr.wire0[128 + i], gr.delta, in_bits[128 + i]);
        auto out_labs = eval_circuit_labels(circ, mmo, gr, labels);
        auto decoded = decode_outputs(gr, out_labs);
        Block ct_gc = bits128_to_block(decoded.data());
        if (!blocks_eq(ct_ref, ct_gc)) {
            std::cerr << "FAIL GC eval vs AES-NI trial " << t << "\n";
            fail++;
            continue;
        }

        // F_k check
        std::vector<u8> x = {static_cast<u8>(t), 1, 2, 3, 4, 5};
        auto y = F_k(key, x);
        Block xp = H1(x);
        Block z = aes_encrypt(key, xp);
        auto y2 = H2(x, z);
        if (y != y2) {
            std::cerr << "FAIL F_k internal trial " << t << "\n";
            fail++;
        }
        std::cout << "trial " << t << " ok y=" << hex32(y).substr(0, 16) << "...\n";
    }
    if (fail) {
        std::cerr << "FAILED " << fail << "/" << trials << "\n";
        return 1;
    }
    std::cout << "check: pass (" << trials << " trials)\n";
    return 0;
}

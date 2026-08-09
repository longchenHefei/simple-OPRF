// Dump STARK witness from one real AES garbling (for stark-garble prove).
#include "gc_mmo.hpp"
#include "plaintext_oprf.hpp"
#include "voprf_ser.hpp"

#include <fstream>
#include <iostream>
#include <random>
#include <string>

int main(int argc, char** argv) {
    std::string circ_path = argc > 1 ? argv[1]
        : "../MP-SPDZ-master/Programs/Circuits/aes_128.txt";
    std::string out_path = argc > 2 ? argv[2] : "/tmp/garble_witness.bin";
    std::string pub_path = argc > 3 ? argv[3] : "/tmp/garble_public.bin";

    auto circ = gc_mmo::load_bristol(circ_path);
    std::mt19937_64 rng{42};
    gc_mmo::Block mmo_key = gc_mmo::random_block(rng);
    gc_mmo::FixedKeyAES mmo(mmo_key);
    auto gr = gc_mmo::garble_circuit(circ, mmo_key, mmo, rng);

    gc_mmo::Block k = gc_mmo::random_block(rng);
    auto cm = plaintext_oprf::key_commitment(k, 128);
    auto wit = voprf_ser::serialize_stark_witness(gr, cm);
    auto pub = voprf_ser::serialize_public_binding(gr, cm);

    std::ofstream(out_path, std::ios::binary).write(reinterpret_cast<const char*>(wit.data()), wit.size());
    std::ofstream(pub_path, std::ios::binary).write(reinterpret_cast<const char*>(pub.data()), pub.size());
    std::cout << "n_and: " << gr.and_wit.size() << "\n";
    std::cout << "witness_bytes: " << wit.size() << "\n";
    std::cout << "wrote " << out_path << " and " << pub_path << "\n";
    return 0;
}

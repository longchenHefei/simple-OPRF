// s-probe-resilient XOR sharing for evaluator input bits (paper: s=2, n=2λ).
#pragma once

#include "gc_mmo.hpp"

#include <random>
#include <vector>

namespace probe_resilient {

using gc_mmo::Block;
using gc_mmo::u8;
using gc_mmo::u64;
using gc_mmo::xor_block;
using gc_mmo::label_for_bit;

// For each of `bits` logical bits, produce 2 shares (s=2) with share0 XOR share1 = bit.
inline std::vector<u8> encode_shares(const std::vector<u8>& bits, std::mt19937_64& rng) {
    std::vector<u8> shares(bits.size() * 2);
    for (size_t i = 0; i < bits.size(); ++i) {
        u8 r = static_cast<u8>(rng() & 1);
        shares[2 * i] = r;
        shares[2 * i + 1] = static_cast<u8>(r ^ (bits[i] & 1));
    }
    return shares;
}

// Server: for each logical input wire with zero-label W0, create two share wire zero-labels
// S0_0 random (LSB-cleared), S1_0 = W0 XOR S0_0 so S0_b0 XOR S1_b1 = W_{b0⊕b1}.
struct ShareLabelPair {
    Block s0_0, s1_0;
};

inline ShareLabelPair make_share_labels(const Block& wire0, const Block& delta, std::mt19937_64& rng) {
    ShareLabelPair p;
    p.s0_0 = gc_mmo::random_block(rng);
    if (gc_mmo::lsb(p.s0_0)) p.s0_0 = xor_block(p.s0_0, delta);
    p.s1_0 = xor_block(wire0, p.s0_0);
    // s1_0 may have LSB 1; OT still uses (s1_0, s1_0⊕delta)
    return p;
}

// Client reconstructs active input label from two OT outputs.
inline Block reconstruct_label(const Block& lab0, const Block& lab1) {
    return xor_block(lab0, lab1);
}

} // namespace probe_resilient

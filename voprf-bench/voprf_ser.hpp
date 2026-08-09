// Serialization helpers for GC tables / STARK witness / protocol messages.
#pragma once

#include "gc_mmo.hpp"
#include "plaintext_oprf.hpp"

#include <vector>

namespace voprf_ser {

using gc_mmo::Block;
using gc_mmo::GarbleResult;
using gc_mmo::u8;
using gc_mmo::u64;

inline void push_u64(std::vector<u8>& o, u64 x) {
    for (int i = 0; i < 8; ++i) o.push_back(static_cast<u8>((x >> (8 * i)) & 0xff));
}

inline void push_bytes(std::vector<u8>& o, const u8* p, size_t n) {
    o.insert(o.end(), p, p + n);
}

inline void push_block(std::vector<u8>& o, const Block& b) { push_bytes(o, b.b, 16); }

inline void push_arr32(std::vector<u8>& o, const std::array<u8, 32>& a) {
    push_bytes(o, a.data(), 32);
}

// Compact online tables blob for one circuit.
inline std::vector<u8> serialize_tables(const GarbleResult& gr) {
    std::vector<u8> o;
    push_block(o, gr.aes_key);
    push_block(o, gr.delta);
    push_u64(o, gr.tables.size());
    for (auto& t : gr.tables) {
        push_block(o, t.T0);
        push_block(o, t.T1);
    }
    // key-wire zero labels (first 128 wires) for client to combine with OT? 
    // Client gets evaluator labels via OT; key labels sent explicitly (δ_rk / key input labels).
    push_u64(o, 128);
    for (u64 i = 0; i < 128; ++i) push_block(o, gr.wire0[i]);
    // out_decode
    push_u64(o, gr.out_decode.size());
    push_bytes(o, gr.out_decode.data(), gr.out_decode.size());
    push_arr32(o, gr.gc_hash);
    push_arr32(o, gr.R_root);
    return o;
}

struct TablesMsg {
    Block aes_key{}, delta{};
    std::vector<gc_mmo::AndGateTable> tables;
    std::vector<Block> key_wire0; // 128
    std::vector<u8> out_decode;
    std::array<u8, 32> gc_hash{}, R_root{};
};

inline u64 take_u64(const std::vector<u8>& in, size_t& off) {
    u64 x = 0;
    for (int i = 0; i < 8; ++i) x |= (u64)in[off++] << (8 * i);
    return x;
}

inline Block take_block(const std::vector<u8>& in, size_t& off) {
    Block b{};
    memcpy(b.b, in.data() + off, 16);
    off += 16;
    return b;
}

inline TablesMsg deserialize_tables(const std::vector<u8>& in) {
    size_t off = 0;
    TablesMsg m;
    m.aes_key = take_block(in, off);
    m.delta = take_block(in, off);
    u64 n = take_u64(in, off);
    m.tables.resize(n);
    for (u64 i = 0; i < n; ++i) {
        m.tables[i].T0 = take_block(in, off);
        m.tables[i].T1 = take_block(in, off);
    }
    u64 nk = take_u64(in, off);
    m.key_wire0.resize(nk);
    for (u64 i = 0; i < nk; ++i) m.key_wire0[i] = take_block(in, off);
    u64 nd = take_u64(in, off);
    m.out_decode.resize(nd);
    memcpy(m.out_decode.data(), in.data() + off, nd);
    off += nd;
    memcpy(m.gc_hash.data(), in.data() + off, 32);
    off += 32;
    memcpy(m.R_root.data(), in.data() + off, 32);
    return m;
}

// STARK witness for one garbled circuit (+ key commitment).
inline std::vector<u8> serialize_stark_witness(const GarbleResult& gr,
                                               const std::vector<u8>& cm) {
    std::vector<u8> o;
    push_u64(o, gr.and_wit.size());
    push_bytes(o, cm.data(), cm.size());
    push_arr32(o, gr.gc_hash);
    push_arr32(o, gr.R_root);
    auto out_hash = gc_mmo::sha256_bytes(gr.out_decode.data(), gr.out_decode.size());
    push_arr32(o, out_hash);
    push_block(o, gr.delta);
    for (auto& w : gr.and_wit) {
        push_block(o, w.a0);
        push_block(o, w.b0);
        push_block(o, w.Tg);
        push_block(o, w.Te);
        push_block(o, w.Ha0);
        push_block(o, w.Ha1);
        push_block(o, w.Hb0);
        push_block(o, w.Hb1);
        o.push_back(w.pa);
        o.push_back(w.pb);
    }
    return o;
}

inline std::vector<u8> serialize_public_binding(const GarbleResult& gr,
                                                const std::vector<u8>& cm) {
    std::vector<u8> o;
    push_arr32(o, gr.gc_hash);
    push_arr32(o, gr.R_root);
    auto out_hash = gc_mmo::sha256_bytes(gr.out_decode.data(), gr.out_decode.size());
    push_arr32(o, out_hash);
    push_bytes(o, cm.data(), cm.size());
    return o;
}

} // namespace voprf_ser

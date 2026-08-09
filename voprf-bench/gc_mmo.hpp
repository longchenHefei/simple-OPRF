// Bristol Fashion AES-128 datapath GC with half-gates + fixed-key AES MMO.
// Circuit: MP-SPDZ aes_128.txt (key||pt -> ct). KeySchedule is inside Bristol;
// server still computes local KeySchedule for STARK key-wire / cm binding.
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(__AES__) || defined(__AES)
#include <wmmintrin.h>
#include <immintrin.h>
#define GC_MMO_HAVE_AESNI 1
#else
#define GC_MMO_HAVE_AESNI 0
#endif

namespace gc_mmo {

using u64 = uint64_t;
using u32 = uint32_t;
using u8 = uint8_t;

struct Block {
    alignas(16) u8 b[16];
};

inline Block xor_block(const Block& a, const Block& b) {
    Block r;
    for (int i = 0; i < 16; ++i) r.b[i] = a.b[i] ^ b.b[i];
    return r;
}

inline bool lsb(const Block& x) { return (x.b[0] & 1) != 0; }

inline Block make_delta(std::mt19937_64& rng) {
    Block d;
    for (int i = 0; i < 16; ++i) d.b[i] = static_cast<u8>(rng() & 0xff);
    d.b[0] |= 1;
    return d;
}

inline Block random_block(std::mt19937_64& rng) {
    Block d;
    for (int i = 0; i < 16; ++i) d.b[i] = static_cast<u8>(rng() & 0xff);
    return d;
}

inline bool blocks_eq(const Block& a, const Block& b) {
    return memcmp(a.b, b.b, 16) == 0;
}

#if GC_MMO_HAVE_AESNI
struct FixedKeyAES {
    __m128i rk[11];

    static __m128i key_expand_assist(__m128i key, __m128i assist) {
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_shuffle_epi32(assist, 0xff));
        return key;
    }

    FixedKeyAES(const Block& key) {
        rk[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.b));
        rk[1] = key_expand_assist(rk[0], _mm_aeskeygenassist_si128(rk[0], 0x01));
        rk[2] = key_expand_assist(rk[1], _mm_aeskeygenassist_si128(rk[1], 0x02));
        rk[3] = key_expand_assist(rk[2], _mm_aeskeygenassist_si128(rk[2], 0x04));
        rk[4] = key_expand_assist(rk[3], _mm_aeskeygenassist_si128(rk[3], 0x08));
        rk[5] = key_expand_assist(rk[4], _mm_aeskeygenassist_si128(rk[4], 0x10));
        rk[6] = key_expand_assist(rk[5], _mm_aeskeygenassist_si128(rk[5], 0x20));
        rk[7] = key_expand_assist(rk[6], _mm_aeskeygenassist_si128(rk[6], 0x40));
        rk[8] = key_expand_assist(rk[7], _mm_aeskeygenassist_si128(rk[7], 0x80));
        rk[9] = key_expand_assist(rk[8], _mm_aeskeygenassist_si128(rk[8], 0x1B));
        rk[10] = key_expand_assist(rk[9], _mm_aeskeygenassist_si128(rk[9], 0x36));
    }

    Block encrypt(const Block& in) const {
        __m128i m = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in.b));
        m = _mm_xor_si128(m, rk[0]);
        for (int i = 1; i < 10; ++i) m = _mm_aesenc_si128(m, rk[i]);
        m = _mm_aesenclast_si128(m, rk[10]);
        Block out;
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out.b), m);
        return out;
    }
};
#else
static const u8 SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const u8 RCON[11] = {0,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};

struct FixedKeyAES {
    u8 rk[11][16];
    FixedKeyAES(const Block& key) {
        memcpy(rk[0], key.b, 16);
        for (int r = 1; r <= 10; ++r) {
            u8 t[4];
            t[0] = SBOX[rk[r - 1][13]] ^ RCON[r];
            t[1] = SBOX[rk[r - 1][14]];
            t[2] = SBOX[rk[r - 1][15]];
            t[3] = SBOX[rk[r - 1][12]];
            for (int i = 0; i < 4; ++i) rk[r][i] = rk[r - 1][i] ^ t[i];
            for (int i = 4; i < 16; ++i) rk[r][i] = rk[r - 1][i] ^ rk[r][i - 4];
        }
    }
    Block encrypt(const Block& in) const {
        u8 s[16];
        memcpy(s, in.b, 16);
        for (int i = 0; i < 16; ++i) s[i] ^= rk[0][i];
        auto sub_bytes = [](u8 st[16]) { for (int i = 0; i < 16; ++i) st[i] = SBOX[st[i]]; };
        auto shift_rows = [](u8 st[16]) {
            u8 t;
            t = st[1]; st[1] = st[5]; st[5] = st[9]; st[9] = st[13]; st[13] = t;
            t = st[2]; st[2] = st[10]; st[10] = t; t = st[6]; st[6] = st[14]; st[14] = t;
            t = st[15]; st[15] = st[11]; st[11] = st[7]; st[7] = st[3]; st[3] = t;
        };
        auto xtime = [](u8 x) -> u8 { return static_cast<u8>((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); };
        auto mix_columns = [&](u8 st[16]) {
            for (int c = 0; c < 4; ++c) {
                u8* col = st + 4 * c;
                u8 a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                u8 t = a0 ^ a1 ^ a2 ^ a3;
                col[0] ^= t ^ xtime(a0 ^ a1);
                col[1] ^= t ^ xtime(a1 ^ a2);
                col[2] ^= t ^ xtime(a2 ^ a3);
                col[3] ^= t ^ xtime(a3 ^ a0);
            }
        };
        for (int r = 1; r < 10; ++r) {
            sub_bytes(s);
            shift_rows(s);
            mix_columns(s);
            for (int i = 0; i < 16; ++i) s[i] ^= rk[r][i];
        }
        sub_bytes(s);
        shift_rows(s);
        for (int i = 0; i < 16; ++i) s[i] ^= rk[10][i];
        Block out;
        memcpy(out.b, s, 16);
        return out;
    }
};
#endif

inline Block mmo_hash(const FixedKeyAES& aes, const Block& x) {
    return xor_block(aes.encrypt(x), x);
}

inline Block tweak(const Block& x, u64 gid, u8 t) {
    Block y = x;
    y.b[8] ^= static_cast<u8>(gid);
    y.b[9] ^= static_cast<u8>(gid >> 8);
    y.b[10] ^= static_cast<u8>(gid >> 16);
    y.b[11] ^= static_cast<u8>(gid >> 24);
    y.b[12] ^= t;
    return y;
}

enum class GateType : u8 { XOR = 0, AND = 1, INV = 2 };

struct Gate {
    GateType type;
    u32 in0 = 0, in1 = 0, out = 0;
};

struct Circuit {
    u64 n_gates = 0;
    u64 n_wires = 0;
    u64 n_input0 = 0; // garbler / key bits
    u64 n_input1 = 0; // evaluator / plaintext bits
    u64 n_output = 0;
    u64 n_and = 0;
    u64 n_xor = 0;
    std::vector<Gate> gates;
    std::vector<u32> output_wires;
};

inline Circuit load_bristol(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open circuit: " + path);
    Circuit c;
    in >> c.n_gates >> c.n_wires;
    u64 nin = 0;
    in >> nin >> c.n_input0 >> c.n_input1;
    if (nin != 2) throw std::runtime_error("expected 2 input bundles");
    u64 nout = 0;
    in >> nout >> c.n_output;
    if (nout != 1) throw std::runtime_error("expected 1 output bundle");
    c.gates.reserve(c.n_gates);
    std::string line;
    std::getline(in, line); // rest of line
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ss(line);
        int nin_g = 0, nout_g = 0;
        ss >> nin_g >> nout_g;
        if (!ss) continue;
        Gate g{};
        if (nin_g == 2 && nout_g == 1) {
            u32 a, b, o;
            std::string op;
            ss >> a >> b >> o >> op;
            g.in0 = a;
            g.in1 = b;
            g.out = o;
            if (op == "XOR" || op == "xor") {
                g.type = GateType::XOR;
                c.n_xor++;
            } else if (op == "AND" || op == "and") {
                g.type = GateType::AND;
                c.n_and++;
            } else {
                throw std::runtime_error("unknown gate: " + op);
            }
        } else if (nin_g == 1 && nout_g == 1) {
            u32 a, o;
            std::string op;
            ss >> a >> o >> op;
            g.in0 = a;
            g.in1 = a;
            g.out = o;
            if (op == "INV" || op == "NOT" || op == "inv" || op == "not") {
                g.type = GateType::INV;
                c.n_xor++; // free NOT via XOR delta
            } else {
                throw std::runtime_error("unknown unary gate: " + op);
            }
        } else {
            throw std::runtime_error("unsupported gate arity in: " + line);
        }
        c.gates.push_back(g);
    }
    if (c.gates.size() != c.n_gates)
        throw std::runtime_error("gate count mismatch");
    u64 out_start = c.n_wires - c.n_output;
    c.output_wires.resize(c.n_output);
    for (u64 i = 0; i < c.n_output; ++i) c.output_wires[i] = static_cast<u32>(out_start + i);
    return c;
}

// Plaintext boolean evaluation of Bristol circuit.
inline std::vector<u8> eval_circuit_plain(const Circuit& c, const std::vector<u8>& in_bits) {
    if (in_bits.size() != c.n_input0 + c.n_input1)
        throw std::runtime_error("plain eval: bad input size");
    std::vector<u8> w(c.n_wires, 0);
    for (size_t i = 0; i < in_bits.size(); ++i) w[i] = in_bits[i] & 1;
    for (const auto& g : c.gates) {
        if (g.type == GateType::XOR) w[g.out] = w[g.in0] ^ w[g.in1];
        else if (g.type == GateType::AND) w[g.out] = w[g.in0] & w[g.in1];
        else w[g.out] = w[g.in0] ^ 1;
    }
    std::vector<u8> out(c.n_output);
    for (u64 i = 0; i < c.n_output; ++i) out[i] = w[c.output_wires[i]];
    return out;
}

// Bristol Fashion AES bit order: wire 0 = LSB of 128-bit big-endian block
// (MSB of byte0 is wire 127). Empirically matches aes_128.txt vs AES-NI.
inline Block bits128_to_block(const u8* bits /*128*/) {
    u8 be_bits[128];
    for (int i = 0; i < 128; ++i) be_bits[i] = bits[127 - i] & 1;
    Block out{};
    for (int i = 0; i < 128; ++i) {
        if (be_bits[i]) out.b[i / 8] |= static_cast<u8>(1u << (7 - (i % 8)));
    }
    return out;
}

inline void block_to_bits128(const Block& bl, u8* bits /*128*/) {
    u8 be_bits[128];
    for (int i = 0; i < 128; ++i) be_bits[i] = (bl.b[i / 8] >> (7 - (i % 8))) & 1;
    for (int i = 0; i < 128; ++i) bits[i] = be_bits[127 - i];
}

struct AndGateTable {
    Block T0, T1;
};

struct HalfGateWitness {
    Block a0, b0;     // zero labels of AND inputs
    Block Tg, Te;     // table
    Block Ha0, Ha1, Hb0, Hb1;
    u8 pa = 0, pb = 0;
};

struct GarbleResult {
    std::vector<AndGateTable> tables;
    std::vector<HalfGateWitness> and_wit; // for STARK
    std::vector<Block> wire0;             // zero-label per wire
    Block delta;
    Block aes_key; // fixed-key for MMO
    std::vector<u8> out_decode;           // LSB of zero-label for each output wire (point-and-permute decode)
    std::array<u8, 32> gc_hash{};         // H(GC tables)
    std::array<u8, 32> R_root{};          // Merkle root of evaluator input label pairs
};

inline std::array<u8, 32> sha256_bytes(const u8* data, size_t len); // defined after include guard helper

} // namespace gc_mmo

#include <openssl/sha.h>

namespace gc_mmo {

inline std::array<u8, 32> sha256_bytes(const u8* data, size_t len) {
    std::array<u8, 32> out{};
    SHA256(data, len, out.data());
    return out;
}

inline std::array<u8, 32> merkle_root_pairs(const std::vector<std::array<Block, 2>>& pairs) {
    if (pairs.empty()) {
        return sha256_bytes(nullptr, 0);
    }
    std::vector<std::array<u8, 32>> level;
    level.reserve(pairs.size());
    for (auto& p : pairs) {
        u8 buf[32];
        memcpy(buf, p[0].b, 16);
        memcpy(buf + 16, p[1].b, 16);
        level.push_back(sha256_bytes(buf, 32));
    }
    while (level.size() > 1) {
        if (level.size() & 1) level.push_back(level.back());
        std::vector<std::array<u8, 32>> next;
        next.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            u8 buf[64];
            memcpy(buf, level[i].data(), 32);
            memcpy(buf + 32, level[i + 1].data(), 32);
            next.push_back(sha256_bytes(buf, 64));
        }
        level.swap(next);
    }
    return level[0];
}

inline GarbleResult garble_circuit(const Circuit& c, const Block& mmo_key, const FixedKeyAES& aes,
                                   std::mt19937_64& rng) {
    GarbleResult gr;
    gr.delta = make_delta(rng);
    gr.aes_key = mmo_key;
    gr.wire0.assign(c.n_wires, Block{});
    for (u64 i = 0; i < c.n_input0 + c.n_input1; ++i) {
        gr.wire0[i] = random_block(rng);
        if (lsb(gr.wire0[i])) gr.wire0[i] = xor_block(gr.wire0[i], gr.delta);
    }
    gr.tables.reserve(c.n_and);
    gr.and_wit.reserve(c.n_and);
    u64 and_id = 0;
    for (const auto& g : c.gates) {
        if (g.type == GateType::XOR) {
            gr.wire0[g.out] = xor_block(gr.wire0[g.in0], gr.wire0[g.in1]);
        } else if (g.type == GateType::INV) {
            // Free-NOT: swap labels so evaluator is a no-op (w_out = w_in).
            gr.wire0[g.out] = xor_block(gr.wire0[g.in0], gr.delta);
        } else { // AND half-gates
            Block a0 = gr.wire0[g.in0];
            Block b0 = gr.wire0[g.in1];
            Block a1 = xor_block(a0, gr.delta);
            Block b1 = xor_block(b0, gr.delta);
            bool pa = lsb(a0);
            bool pb = lsb(b0);
            Block Ha0 = mmo_hash(aes, tweak(a0, and_id, 0));
            Block Ha1 = mmo_hash(aes, tweak(a1, and_id, 0));
            Block Tg = xor_block(Ha0, Ha1);
            if (pb) Tg = xor_block(Tg, gr.delta);
            Block wg0 = Ha0;
            if (pa) wg0 = xor_block(wg0, Tg);

            Block Hb0 = mmo_hash(aes, tweak(b0, and_id, 1));
            Block Hb1 = mmo_hash(aes, tweak(b1, and_id, 1));
            Block Te = xor_block(Hb0, Hb1);
            Te = xor_block(Te, a0);
            Block we0 = Hb0;
            if (pb) we0 = xor_block(we0, xor_block(Te, a0));

            Block w0 = xor_block(wg0, we0);
            gr.wire0[g.out] = w0;

            AndGateTable tab{Tg, Te};
            gr.tables.push_back(tab);
            HalfGateWitness wit;
            wit.a0 = a0;
            wit.b0 = b0;
            wit.Tg = Tg;
            wit.Te = Te;
            wit.Ha0 = Ha0;
            wit.Ha1 = Ha1;
            wit.Hb0 = Hb0;
            wit.Hb1 = Hb1;
            wit.pa = pa ? 1 : 0;
            wit.pb = pb ? 1 : 0;
            gr.and_wit.push_back(wit);
            and_id++;
        }
    }

    gr.out_decode.resize(c.n_output);
    for (u64 i = 0; i < c.n_output; ++i) {
        gr.out_decode[i] = lsb(gr.wire0[c.output_wires[i]]) ? 1 : 0;
    }

    std::vector<u8> gc_bytes;
    gc_bytes.reserve(gr.tables.size() * 32);
    for (auto& t : gr.tables) {
        gc_bytes.insert(gc_bytes.end(), t.T0.b, t.T0.b + 16);
        gc_bytes.insert(gc_bytes.end(), t.T1.b, t.T1.b + 16);
    }
    gr.gc_hash = sha256_bytes(gc_bytes.data(), gc_bytes.size());

    std::vector<std::array<Block, 2>> pairs(c.n_input1);
    for (u64 i = 0; i < c.n_input1; ++i) {
        Block z = gr.wire0[c.n_input0 + i];
        pairs[i] = {z, xor_block(z, gr.delta)};
    }
    gr.R_root = merkle_root_pairs(pairs);
    return gr;
}

inline Block label_for_bit(const Block& wire0, const Block& delta, u8 bit) {
    return bit ? xor_block(wire0, delta) : wire0;
}

// Evaluate GC given active labels on all input wires.
inline std::vector<Block> eval_circuit_labels(const Circuit& c, const FixedKeyAES& aes,
                                              const GarbleResult& gr,
                                              const std::vector<Block>& input_labels) {
    if (input_labels.size() != c.n_input0 + c.n_input1)
        throw std::runtime_error("eval: bad input label count");
    std::vector<Block> w(c.n_wires);
    for (size_t i = 0; i < input_labels.size(); ++i) w[i] = input_labels[i];
    u64 and_id = 0;
    for (const auto& g : c.gates) {
        if (g.type == GateType::XOR) {
            w[g.out] = xor_block(w[g.in0], w[g.in1]);
        } else if (g.type == GateType::INV) {
            w[g.out] = w[g.in0]; // free-NOT: labels pre-swapped at garble
        } else {
            const AndGateTable& T = gr.tables[and_id];
            Block wa = w[g.in0];
            Block wb = w[g.in1];
            bool sa = lsb(wa);
            bool sb = lsb(wb);
            Block Hg = mmo_hash(aes, tweak(wa, and_id, 0));
            Block wg = Hg;
            if (sa) wg = xor_block(wg, T.T0);
            Block He = mmo_hash(aes, tweak(wb, and_id, 1));
            Block we = He;
            if (sb) we = xor_block(we, xor_block(T.T1, wa));
            w[g.out] = xor_block(wg, we);
            and_id++;
        }
    }
    std::vector<Block> outs(c.n_output);
    for (u64 i = 0; i < c.n_output; ++i) outs[i] = w[c.output_wires[i]];
    return outs;
}

// Decode output bits using point-and-permute vs out_decode (LSB of zero label).
inline std::vector<u8> decode_outputs(const GarbleResult& gr, const std::vector<Block>& out_labels) {
    std::vector<u8> bits(out_labels.size());
    for (size_t i = 0; i < out_labels.size(); ++i) {
        u8 p = lsb(out_labels[i]) ? 1 : 0;
        bits[i] = p ^ gr.out_decode[i];
    }
    return bits;
}

// Compatibility stubs for old synthetic API used by garble_bench.
struct CircuitCompat {
    u64 n_and = 6553;
    u64 n_xor = 24000;
};

inline u64 tables_bytes(const GarbleResult& gr) {
    return gr.tables.size() * sizeof(AndGateTable);
}

inline const char* aes_backend_name() {
    return GC_MMO_HAVE_AESNI ? "AES-NI" : "portable";
}

} // namespace gc_mmo

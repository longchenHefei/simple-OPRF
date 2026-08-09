// Plaintext GC-VOPRF reference: F_k(x) = H2(x, AES_k(H1(x))).
// H1, H2 instantiated with SHA-256 (H1 truncated to 128 bits).
#pragma once

#include "gc_mmo.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <openssl/sha.h>

namespace plaintext_oprf {

using gc_mmo::Block;
using gc_mmo::FixedKeyAES;
using gc_mmo::u8;
using gc_mmo::xor_block;

inline std::array<u8, 32> sha256(const u8* data, size_t len) {
    std::array<u8, 32> out{};
    SHA256(data, len, out.data());
    return out;
}

// H1: {0,1}* -> {0,1}^128 via SHA-256 truncated to 16 bytes.
inline Block H1(const u8* x, size_t len) {
    auto h = sha256(x, len);
    Block out{};
    memcpy(out.b, h.data(), 16);
    return out;
}

inline Block H1(const std::vector<u8>& x) { return H1(x.data(), x.size()); }

// H2: (x, z) -> SHA-256(x || z) full 32 bytes.
inline std::array<u8, 32> H2(const u8* x, size_t xlen, const Block& z) {
    std::vector<u8> buf;
    buf.reserve(xlen + 16);
    buf.insert(buf.end(), x, x + xlen);
    buf.insert(buf.end(), z.b, z.b + 16);
    return sha256(buf.data(), buf.size());
}

inline std::array<u8, 32> H2(const std::vector<u8>& x, const Block& z) {
    return H2(x.data(), x.size(), z);
}

inline Block aes_encrypt(const Block& key, const Block& pt) {
    FixedKeyAES aes(key);
    return aes.encrypt(pt);
}

// Local KeySchedule: round keys rk[0..10] (same as FixedKeyAES).
inline void key_schedule(const Block& key, Block rk[11]) {
    FixedKeyAES aes(key);
#if GC_MMO_HAVE_AESNI
    for (int i = 0; i < 11; ++i) {
        _mm_storeu_si128(reinterpret_cast<__m128i*>(rk[i].b), aes.rk[i]);
    }
#else
    for (int i = 0; i < 11; ++i) memcpy(rk[i].b, aes.rk[i], 16);
#endif
}

// F_k(x) = H2(x, AES_k(H1(x)))
inline std::array<u8, 32> F_k(const Block& k, const u8* x, size_t xlen) {
    Block xp = H1(x, xlen);
    Block z = aes_encrypt(k, xp);
    return H2(x, xlen, z);
}

inline std::array<u8, 32> F_k(const Block& k, const std::vector<u8>& x) {
    return F_k(k, x.data(), x.size());
}

// Key commitment cm = (H(k), AES(k,0), ..., AES(k,T-1)), T=128.
inline std::vector<u8> key_commitment(const Block& k, size_t T = 128) {
    std::vector<u8> cm;
    cm.reserve(32 + T * 16);
    auto hk = sha256(k.b, 16);
    cm.insert(cm.end(), hk.begin(), hk.end());
    FixedKeyAES aes(k);
    for (size_t i = 0; i < T; ++i) {
        Block pt{};
        pt.b[0] = static_cast<u8>(i & 0xff);
        pt.b[1] = static_cast<u8>((i >> 8) & 0xff);
        Block ct = aes.encrypt(pt);
        cm.insert(cm.end(), ct.b, ct.b + 16);
    }
    return cm;
}

inline std::string hex32(const std::array<u8, 32>& a) {
    static const char* hexd = "0123456789abcdef";
    std::string s;
    s.resize(64);
    for (int i = 0; i < 32; ++i) {
        s[2 * i] = hexd[a[i] >> 4];
        s[2 * i + 1] = hexd[a[i] & 0xf];
    }
    return s;
}

} // namespace plaintext_oprf

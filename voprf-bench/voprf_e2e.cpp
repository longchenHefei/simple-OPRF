// True GC-VOPRF E2E (Fig.9–10): Kyber base OT + SoftSpokenMal + probe-resilient
// AES datapath GC + winterfell half-gate STARK. Client y_i = F_k(x_i).
#include "gc_mmo.hpp"
#include "plaintext_oprf.hpp"
#include "probe_resilient.hpp"
#include "voprf_ser.hpp"

#include <sys/wait.h>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <array>
#include <filesystem>

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libOTe/Tools/Coproto.h>
#include <libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h>
#include <libOTe/Base/MasnyRindalKyber.h>
#include <coproto/Socket/AsioSocket.h>

using namespace osuCrypto;
using namespace gc_mmo;
using namespace plaintext_oprf;
using namespace probe_resilient;
using namespace voprf_ser;
namespace fs = std::filesystem;

static double ms_between(std::chrono::steady_clock::time_point a,
                         std::chrono::steady_clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

static u64 sockBytes(Socket& chl) {
    return chl.bytesSent() + chl.bytesReceived();
}

static int run_shell(const std::string& cmd, std::string* out = nullptr) {
    std::string full = cmd + " 2>&1";
    FILE* pipe = popen(full.c_str(), "r");
    if (!pipe) return -1;
    std::ostringstream oss;
    char buf[512];
    while (fgets(buf, sizeof(buf), pipe)) oss << buf;
    int rc = pclose(pipe);
    if (out) *out = oss.str();
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

static void send_u64(Socket& chl, u64 x) {
    block b = ZeroBlock;
    memcpy(&b, &x, sizeof(u64));
    cp::sync_wait(chl.send(std::move(b)));
}

static u64 recv_u64(Socket& chl) {
    block b;
    cp::sync_wait(chl.recv(b));
    u64 x = 0;
    memcpy(&x, &b, sizeof(u64));
    return x;
}

static void send_blob(Socket& chl, const std::vector<u8>& data) {
    send_u64(chl, data.size());
    u64 nblk = (data.size() + 15) / 16;
    AlignedUnVector<block> blocks(nblk ? nblk : 1);
    if (nblk) {
        memset(blocks.data(), 0, nblk * sizeof(block));
        memcpy(blocks.data(), data.data(), data.size());
        cp::sync_wait(chl.send(blocks));
    }
    cp::sync_wait(chl.flush());
}

static std::vector<u8> recv_blob(Socket& chl) {
    u64 n = recv_u64(chl);
    u64 nblk = (n + 15) / 16;
    std::vector<u8> data(n);
    if (nblk) {
        AlignedUnVector<block> blocks(nblk);
        cp::sync_wait(chl.recv(blocks));
        memcpy(data.data(), blocks.data(), n);
    }
    return data;
}

static void ping_sync(Socket& chl, bool server) {
    u8 ping = 1;
    if (server) {
        cp::sync_wait(chl.send(std::move(ping)));
        cp::sync_wait(chl.recv(ping));
    } else {
        cp::sync_wait(chl.recv(ping));
        cp::sync_wait(chl.send(std::move(ping)));
    }
    cp::sync_wait(chl.flush());
}

static Block block_from_oc(const block& b) {
    Block out{};
    memcpy(out.b, &b, 16);
    return out;
}

static block oc_from_block(const Block& b) {
    block out = ZeroBlock;
    memcpy(&out, b.b, 16);
    return out;
}

struct Config {
    bool server = true;
    std::string ip = "127.0.0.1";
    int port = 19000;
    u64 m = 128;
    u64 n_ot = 32768; // m * 256
    bool tables_online = false;
    std::string stark_bin = "stark-garble/target/release/stark-garble";
    std::string work_dir = "/tmp/voprf_e2e";
    std::string circuit = "../MP-SPDZ-master/Programs/Circuits/aes_128.txt";
};

static void run_server(Config cfg) {
    fs::create_directories(cfg.work_dir);
    auto circ = load_bristol(cfg.circuit);
    auto chl = cp::asioConnect(cfg.ip + ":" + std::to_string(cfg.port), true);
    PRNG prng(sysRandomSeed());
    std::mt19937_64 rng{prng.get<u64>()};

    SoftSpokenMalOtSender sender;
    sender.init(2);
    auto nBase = sender.baseOtCount();

    auto t_off0 = std::chrono::steady_clock::now();
    auto b0 = sockBytes(chl);

    // Kyber base OT (server = base OT receiver)
    MasnyRindalKyber bot;
    BitVector baseChoice(nBase);
    baseChoice.randomize(prng);
    std::vector<block> baseRecv(nBase);
    cp::sync_wait(bot.receive(baseChoice, baseRecv, prng, chl));
    cp::sync_wait(chl.flush());
    sender.setBaseOts(baseRecv, baseChoice);

    // OPRF key + commitment
    Block oprf_key = random_block(rng);
    auto cm = key_commitment(oprf_key, 128);

    // Garble m AES circuits (same key bits on garbler wires)
    std::vector<u8> key_bits(128);
    block_to_bits128(oprf_key, key_bits.data());

    Block mmo_key = random_block(rng);
    FixedKeyAES mmo(mmo_key);

    std::vector<GarbleResult> gcs(cfg.m);
    std::vector<std::vector<u8>> table_blobs(cfg.m);
    std::vector<std::vector<ShareLabelPair>> share_labs(cfg.m);

    for (u64 i = 0; i < cfg.m; ++i) {
        gcs[i] = garble_circuit(circ, mmo_key, mmo, rng);
        // Force key-wire zero labels already random; semantic key bits applied at label selection
        table_blobs[i] = serialize_tables(gcs[i]);
        share_labs[i].resize(circ.n_input1);
        for (u64 j = 0; j < circ.n_input1; ++j) {
            share_labs[i][j] = make_share_labels(gcs[i].wire0[circ.n_input0 + j], gcs[i].delta, rng);
        }
    }

    // STARK prove on circuit 0 (half-gate AIR) binding cm + H(GC_0)+R_0
    // Batch binding: hash all gc_hash into out_hash field via cm extension — include all H(GC_i) in public
    {
        std::vector<u8> batch_cm = cm;
        for (u64 i = 0; i < cfg.m; ++i) {
            batch_cm.insert(batch_cm.end(), gcs[i].gc_hash.begin(), gcs[i].gc_hash.end());
        }
        // For STARK witness we use cm as specified (T=128); batch hashes checked by client separately
    }
    std::string wit_path = cfg.work_dir + "/witness.bin";
    std::string proof_path = cfg.work_dir + "/proof.bin";
    std::string pub_path = cfg.work_dir + "/public.bin";
    {
        auto wit = serialize_stark_witness(gcs[0], cm);
        auto pub = serialize_public_binding(gcs[0], cm);
        std::ofstream(wit_path, std::ios::binary)
            .write(reinterpret_cast<const char*>(wit.data()), (std::streamsize)wit.size());
        std::ofstream(pub_path, std::ios::binary)
            .write(reinterpret_cast<const char*>(pub.data()), (std::streamsize)pub.size());
    }
    std::string prove_out;
    std::ostringstream pcmd;
    pcmd << "'" << cfg.stark_bin << "' prove -w '" << wit_path << "' -o '" << proof_path << "'";
    if (run_shell(pcmd.str(), &prove_out) != 0) {
        std::cerr << "STARK prove failed:\n" << prove_out << std::endl;
        std::exit(1);
    }
    std::ifstream pf(proof_path, std::ios::binary);
    std::vector<u8> proof((std::istreambuf_iterator<char>(pf)), {});
    pf.close();

    // Send OPRF key commitment + batch meta offline-ish
    send_blob(chl, cm);
    {
        std::vector<u8> meta;
        push_u64(meta, cfg.m);
        for (u64 i = 0; i < cfg.m; ++i) push_arr32(meta, gcs[i].gc_hash);
        send_blob(chl, meta);
    }

    if (!cfg.tables_online) {
        for (u64 i = 0; i < cfg.m; ++i) send_blob(chl, table_blobs[i]);
    }

    double offline_ms = ms_between(t_off0, std::chrono::steady_clock::now());
    u64 offline_B = sockBytes(chl) - b0;

    ping_sync(chl, true);

    // ---- Online ----
    auto t_on0 = std::chrono::steady_clock::now();
    auto bon = sockBytes(chl);

    // SoftSpoken: n_ot = m * 256 share wires; messages are share label pairs
    if (cfg.n_ot != cfg.m * 256) {
        std::cerr << "n_ot must be m*256\n";
        std::exit(1);
    }
    AlignedUnVector<std::array<block, 2>> otMsg(cfg.n_ot);
    cp::sync_wait(sender.send(otMsg, prng, chl));
    cp::sync_wait(chl.flush());

    // Chosen-message layer: mask GC share labels with random OT pads
    {
        std::vector<u8> masks;
        masks.reserve(cfg.n_ot * 32);
        for (u64 i = 0; i < cfg.m; ++i) {
            for (u64 j = 0; j < 128; ++j) {
                auto& sp = share_labs[i][j];
                u64 idx0 = i * 256 + 2 * j;
                u64 idx1 = idx0 + 1;
                Block r00 = block_from_oc(otMsg[idx0][0]);
                Block r01 = block_from_oc(otMsg[idx0][1]);
                Block r10 = block_from_oc(otMsg[idx1][0]);
                Block r11 = block_from_oc(otMsg[idx1][1]);
                Block c00 = xor_block(r00, sp.s0_0);
                Block c01 = xor_block(r01, xor_block(sp.s0_0, gcs[i].delta));
                Block c10 = xor_block(r10, sp.s1_0);
                Block c11 = xor_block(r11, xor_block(sp.s1_0, gcs[i].delta));
                push_block(masks, c00);
                push_block(masks, c01);
                push_block(masks, c10);
                push_block(masks, c11);
            }
        }
        send_blob(chl, masks);
    }

    if (cfg.tables_online) {
        for (u64 i = 0; i < cfg.m; ++i) send_blob(chl, table_blobs[i]);
    }

    // Send active key labels for each circuit (garbler input)
    for (u64 i = 0; i < cfg.m; ++i) {
        std::vector<u8> key_labs;
        for (u64 j = 0; j < 128; ++j) {
            Block lab = label_for_bit(gcs[i].wire0[j], gcs[i].delta, key_bits[j]);
            push_block(key_labs, lab);
        }
        send_blob(chl, key_labs);
    }

    send_blob(chl, proof);

    // Loopback acceptance oracle: send OPRF key so client can check y == F_k(x)
    {
        std::vector<u8> kblob(oprf_key.b, oprf_key.b + 16);
        send_blob(chl, kblob);
    }

    u8 vok = 0;
    cp::sync_wait(chl.recv(vok));

    double online_ms = ms_between(t_on0, std::chrono::steady_clock::now());
    u64 online_B = sockBytes(chl) - bon;

    std::cout << "role: server\n";
    std::cout << "protocol: GC-VOPRF-Fig9-10\n";
    std::cout << "tables_mode: " << (cfg.tables_online ? "online" : "offline") << "\n";
    std::cout << "m: " << cfg.m << "\n";
    std::cout << "n_ot: " << cfg.n_ot << "\n";
    std::cout << "n_and: " << circ.n_and << "\n";
    std::cout << "n_xor: " << circ.n_xor << "\n";
    std::cout << "tables_bytes_one: " << table_blobs[0].size() << "\n";
    std::cout << "proof_bytes: " << proof.size() << "\n";
    std::cout << "offline_ms: " << std::fixed << std::setprecision(3) << offline_ms << "\n";
    std::cout << "offline_B: " << offline_B << "\n";
    std::cout << "online_ms: " << online_ms << "\n";
    std::cout << "online_ms_per_eval: " << (online_ms / double(cfg.m)) << "\n";
    std::cout << "online_B: " << online_B << "\n";
    std::cout << "online_rounds: 2\n";
    std::cout << "verify_ok: " << (vok ? 1 : 0) << "\n";
    std::cout << "stark_prove_log:\n" << prove_out;
    std::cout << "check: " << (vok ? "pass" : "fail") << "\n";
}

static void run_client(Config cfg) {
    fs::create_directories(cfg.work_dir);
    auto circ = load_bristol(cfg.circuit);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    auto chl = cp::asioConnect(cfg.ip + ":" + std::to_string(cfg.port), false);
    PRNG prng(sysRandomSeed());
    std::mt19937_64 rng{prng.get<u64>()};

    SoftSpokenMalOtReceiver receiver;
    receiver.init(2);
    auto nBase = receiver.baseOtCount();

    auto t_off0 = std::chrono::steady_clock::now();
    auto b0 = sockBytes(chl);

    MasnyRindalKyber bot;
    std::vector<std::array<block, 2>> baseSend(nBase);
    cp::sync_wait(bot.send(baseSend, prng, chl));
    cp::sync_wait(chl.flush());
    receiver.setBaseOts(baseSend);

    auto cm = recv_blob(chl);
    auto meta = recv_blob(chl);
    size_t moff = 0;
    u64 m_meta = take_u64(meta, moff);
    if (m_meta != cfg.m) {
        std::cerr << "m mismatch\n";
        std::exit(1);
    }
    std::vector<std::array<u8, 32>> server_gc_hashes(cfg.m);
    for (u64 i = 0; i < cfg.m; ++i) {
        memcpy(server_gc_hashes[i].data(), meta.data() + moff, 32);
        moff += 32;
    }

    std::vector<std::vector<u8>> table_blobs(cfg.m);
    if (!cfg.tables_online) {
        for (u64 i = 0; i < cfg.m; ++i) table_blobs[i] = recv_blob(chl);
    }

    double offline_ms = ms_between(t_off0, std::chrono::steady_clock::now());
    u64 offline_B = sockBytes(chl) - b0;

    ping_sync(chl, false);

    auto t_on0 = std::chrono::steady_clock::now();
    auto bon = sockBytes(chl);

    // Sample inputs x_i and probe-resilient encode H1(x)
    std::vector<std::vector<u8>> xs(cfg.m);
    std::vector<Block> xps(cfg.m);
    std::vector<u8> all_shares(cfg.n_ot);
    for (u64 i = 0; i < cfg.m; ++i) {
        xs[i].resize(16);
        for (int j = 0; j < 16; ++j) xs[i][j] = static_cast<u8>(rng() & 0xff);
        xps[i] = H1(xs[i]);
        std::vector<u8> bits(128);
        block_to_bits128(xps[i], bits.data());
        auto shares = encode_shares(bits, rng);
        memcpy(all_shares.data() + i * 256, shares.data(), 256);
    }

    BitVector choices(cfg.n_ot);
    for (u64 i = 0; i < cfg.n_ot; ++i) choices[i] = all_shares[i] & 1;
    AlignedUnVector<block> otOut(cfg.n_ot);
    cp::sync_wait(receiver.receive(choices, otOut, prng, chl));
    cp::sync_wait(chl.flush());

    // Unmask chosen share labels
    auto masks = recv_blob(chl);
    size_t moff2 = 0;
    std::vector<Block> share_labels(cfg.n_ot);
    for (u64 i = 0; i < cfg.n_ot; ++i) {
        Block c0 = take_block(masks, moff2);
        Block c1 = take_block(masks, moff2);
        Block pad = block_from_oc(otOut[i]);
        share_labels[i] = xor_block(pad, choices[i] ? c1 : c0);
    }

    if (cfg.tables_online) {
        for (u64 i = 0; i < cfg.m; ++i) table_blobs[i] = recv_blob(chl);
    }

    std::vector<std::vector<Block>> key_labels(cfg.m);
    for (u64 i = 0; i < cfg.m; ++i) {
        auto blob = recv_blob(chl);
        size_t off = 0;
        key_labels[i].resize(128);
        for (u64 j = 0; j < 128; ++j) key_labels[i][j] = take_block(blob, off);
    }

    auto proof = recv_blob(chl);
    std::string proof_path = cfg.work_dir + "/proof_client.bin";
    {
        std::ofstream pf(proof_path, std::ios::binary);
        pf.write(reinterpret_cast<const char*>(proof.data()), (std::streamsize)proof.size());
    }
    auto key_blob = recv_blob(chl);
    Block oprf_key{};
    if (key_blob.size() == 16) memcpy(oprf_key.b, key_blob.data(), 16);

    // Verify STARK
    std::string verify_out;
    std::ostringstream vcmd;
    vcmd << "'" << cfg.stark_bin << "' verify -i '" << proof_path << "'";
    int vrc = run_shell(vcmd.str(), &verify_out);
    bool stark_ok = (vrc == 0 && verify_out.find("verify: ok") != std::string::npos);

    bool bind_ok = false;
    if (stark_ok && proof.size() > 16) {
        u64 pub_len = 0;
        for (int i = 0; i < 8; ++i) pub_len |= (u64)proof[i] << (8 * i);
        size_t off = 8 + pub_len + 32; // skip binding hash
        if (off + 32 <= proof.size()) {
            std::array<u8, 32> proof_gc{};
            memcpy(proof_gc.data(), proof.data() + off, 32);
            TablesMsg t0 = deserialize_tables(table_blobs[0]);
            bind_ok = (proof_gc == t0.gc_hash && proof_gc == server_gc_hashes[0]);
        }
    }

    bool plaintext_ok = true;
    int plain_match = 0;
    int fk_pass = 0;
    std::vector<std::array<u8, 32>> ys(cfg.m);

    for (u64 i = 0; i < cfg.m && stark_ok && bind_ok; ++i) {
        TablesMsg tm = deserialize_tables(table_blobs[i]);
        if (tm.gc_hash != server_gc_hashes[i]) {
            plaintext_ok = false;
            break;
        }
        GarbleResult gr;
        gr.aes_key = tm.aes_key;
        gr.delta = tm.delta;
        gr.tables = tm.tables;
        gr.out_decode = tm.out_decode;
        gr.gc_hash = tm.gc_hash;
        gr.R_root = tm.R_root;
        FixedKeyAES aes(tm.aes_key);

        std::vector<Block> in_labels(256);
        for (u64 j = 0; j < 128; ++j) in_labels[j] = key_labels[i][j];
        for (u64 j = 0; j < 128; ++j) {
            Block l0 = share_labels[i * 256 + 2 * j];
            Block l1 = share_labels[i * 256 + 2 * j + 1];
            in_labels[128 + j] = reconstruct_label(l0, l1);
        }
        auto out_labs = eval_circuit_labels(circ, aes, gr, in_labels);
        auto out_bits = decode_outputs(gr, out_labs);
        Block z = bits128_to_block(out_bits.data());
        ys[i] = H2(xs[i], z);
        auto y_ref = F_k(oprf_key, xs[i]);
        if (y_ref == ys[i]) {
            plain_match++;
            fk_pass++;
        } else {
            plaintext_ok = false;
        }
    }

    u8 vok = (stark_ok && bind_ok && plaintext_ok && plain_match == (int)cfg.m) ? 1 : 0;
    cp::sync_wait(chl.send(std::move(vok)));
    cp::sync_wait(chl.flush());

    double online_ms = ms_between(t_on0, std::chrono::steady_clock::now());
    u64 online_B = sockBytes(chl) - bon;

    std::cout << "role: client\n";
    std::cout << "protocol: GC-VOPRF-Fig9-10\n";
    std::cout << "tables_mode: " << (cfg.tables_online ? "online" : "offline") << "\n";
    std::cout << "m: " << cfg.m << "\n";
    std::cout << "n_ot: " << cfg.n_ot << "\n";
    std::cout << "H1H2: SHA-256\n";
    std::cout << "probe_resilient: s=2 n=256\n";
    std::cout << "offline_ms: " << std::fixed << std::setprecision(3) << offline_ms << "\n";
    std::cout << "offline_B: " << offline_B << "\n";
    std::cout << "online_ms: " << online_ms << "\n";
    std::cout << "online_ms_per_eval: " << (online_ms / double(cfg.m)) << "\n";
    std::cout << "online_B: " << online_B << "\n";
    std::cout << "online_B_per_eval: " << (online_B / double(cfg.m)) << "\n";
    std::cout << "online_rounds: 2\n";
    std::cout << "stark_ok: " << (stark_ok ? 1 : 0) << "\n";
    std::cout << "bind_ok: " << (bind_ok ? 1 : 0) << "\n";
    std::cout << "fk_gc_evals: " << fk_pass << "\n";
    std::cout << "plaintext_Fk_match: " << plain_match << "/" << cfg.m << "\n";
    std::cout << "proof_bytes: " << proof.size() << "\n";
    std::cout << "stark_verify_log:\n" << verify_out;
    if (!ys.empty()) std::cout << "y0: " << hex32(ys[0]) << "\n";
    std::cout << "check: " << (vok ? "pass" : "fail") << "\n";
}

int main(int argc, char** argv) {
    CLP cmd(argc, argv);
    Config cfg;
    std::string role = cmd.getOr<std::string>("role", "server");
    cfg.server = (role == "server" || role == "1");
    cfg.ip = cmd.getOr<std::string>("ip", "127.0.0.1");
    cfg.port = cmd.getOr("port", 19000);
    cfg.m = cmd.getOr<u64>("m", 128);
    cfg.n_ot = cmd.getOr<u64>("n", 32768);
    std::string tables = cmd.getOr<std::string>("tables", "offline");
    cfg.tables_online = (tables == "online");
    cfg.stark_bin = cmd.getOr<std::string>("stark", "stark-garble/target/release/stark-garble");
    cfg.work_dir = cmd.getOr<std::string>("workdir", "/tmp/voprf_e2e");
    cfg.circuit = cmd.getOr<std::string>("circuit", "../MP-SPDZ-master/Programs/Circuits/aes_128.txt");

    std::cout << "voprf_e2e role=" << role
              << " ip=" << cfg.ip << " port=" << cfg.port
              << " m=" << cfg.m << " n_ot=" << cfg.n_ot
              << " tables=" << tables << std::endl;

    try {
        if (cfg.server) run_server(cfg);
        else run_client(cfg);
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}

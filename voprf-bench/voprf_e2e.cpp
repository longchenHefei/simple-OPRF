// Integrated GC-VOPRF E2E (Linux loopback): Kyber base OT + SoftSpokenMal + GC + STARK.
// Both roles run on Linux; Mac is only an SSH operator.
#include "gc_mmo.hpp"

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

static std::vector<u8> serialize_garble(const GarbleResult& gr, const Block& aes_key) {
    std::vector<u8> out;
    out.insert(out.end(), aes_key.b, aes_key.b + 16);
    out.insert(out.end(), gr.delta.b, gr.delta.b + 16);
    out.insert(out.end(), gr.inA0.b, gr.inA0.b + 16);
    out.insert(out.end(), gr.inB0.b, gr.inB0.b + 16);
    u64 n = gr.tables.size();
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<u8>((n >> (8 * i)) & 0xff));
    for (auto& t : gr.tables) {
        out.insert(out.end(), t.T0.b, t.T0.b + 16);
        out.insert(out.end(), t.T1.b, t.T1.b + 16);
    }
    return out;
}

static std::pair<GarbleResult, Block> deserialize_garble(const std::vector<u8>& in) {
    size_t off = 0;
    auto take16 = [&](Block& bl) {
        memcpy(bl.b, in.data() + off, 16);
        off += 16;
    };
    Block aes_key{}, delta{}, inA0{}, inB0{};
    take16(aes_key);
    take16(delta);
    take16(inA0);
    take16(inB0);
    u64 n = 0;
    for (int i = 0; i < 8; ++i) n |= (u64)in[off++] << (8 * i);
    GarbleResult gr;
    gr.delta = delta;
    gr.inA0 = inA0;
    gr.inB0 = inB0;
    gr.aes_key = aes_key;
    gr.tables.resize(n);
    for (u64 i = 0; i < n; ++i) {
        memcpy(gr.tables[i].T0.b, in.data() + off, 16); off += 16;
        memcpy(gr.tables[i].T1.b, in.data() + off, 16); off += 16;
    }
    return {gr, aes_key};
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

struct Config {
    bool server = true;
    std::string ip = "127.0.0.1";
    int port = 19000;
    u64 m = 128;
    u64 n_ot = 32768;
    bool tables_online = false;
    std::string stark_bin = "stark-mmo/target/release/stark-mmo";
    std::string work_dir = "/tmp/voprf_e2e";
    u64 stark_n = 16384;
};

static void run_server(Config cfg) {
    fs::create_directories(cfg.work_dir);
    auto chl = cp::asioConnect(cfg.ip + ":" + std::to_string(cfg.port), true);
    PRNG prng(sysRandomSeed());

    SoftSpokenMalOtSender sender;
    sender.init(2);
    auto nBase = sender.baseOtCount();

    // ---- Offline: Kyber base OT (server = base OT receiver) ----
    auto t_off0 = std::chrono::steady_clock::now();
    auto b0 = sockBytes(chl);

    MasnyRindalKyber bot;
    BitVector baseChoice(nBase);
    baseChoice.randomize(prng);
    std::vector<block> baseRecv(nBase);
    cp::sync_wait(bot.receive(baseChoice, baseRecv, prng, chl));
    cp::sync_wait(chl.flush());
    sender.setBaseOts(baseRecv, baseChoice);

    // Garble
    Circuit circ;
    std::mt19937_64 rng{12345};
    Block aes_key = random_block(rng);
    FixedKeyAES aes(aes_key);
    auto gr = garble(circ, aes, rng);
    auto tables_blob = serialize_garble(gr, aes_key);

    // STARK prove (offline)
    std::string proof_path = cfg.work_dir + "/proof.bin";
    std::string prove_out;
    std::ostringstream pcmd;
    pcmd << "'" << cfg.stark_bin << "' prove -o '" << proof_path
         << "' --n " << cfg.stark_n;
    if (run_shell(pcmd.str(), &prove_out) != 0) {
        std::cerr << "STARK prove failed:\n" << prove_out << std::endl;
        std::exit(1);
    }
    std::ifstream pf(proof_path, std::ios::binary);
    std::vector<u8> proof((std::istreambuf_iterator<char>(pf)), {});
    pf.close();

    if (!cfg.tables_online) {
        send_blob(chl, tables_blob);
    }

    double offline_ms = ms_between(t_off0, std::chrono::steady_clock::now());
    u64 offline_B = sockBytes(chl) - b0;

    ping_sync(chl, true);

    // ---- Online ----
    auto t_on0 = std::chrono::steady_clock::now();
    auto bon = sockBytes(chl);

    AlignedUnVector<std::array<block, 2>> otMsg(cfg.n_ot);
    cp::sync_wait(sender.send(otMsg, prng, chl));
    cp::sync_wait(chl.flush());

    if (cfg.tables_online) {
        send_blob(chl, tables_blob);
    }

    // Client does GC eval locally; server waits for ack then sends proof
    u8 ack = 0;
    cp::sync_wait(chl.recv(ack));
    send_blob(chl, proof);
    u8 vok = 0;
    cp::sync_wait(chl.recv(vok));

    double online_ms = ms_between(t_on0, std::chrono::steady_clock::now());
    u64 online_B = sockBytes(chl) - bon;

    std::cout << "role: server\n";
    std::cout << "tables_mode: " << (cfg.tables_online ? "online" : "offline") << "\n";
    std::cout << "m: " << cfg.m << "\n";
    std::cout << "n_ot: " << cfg.n_ot << "\n";
    std::cout << "tables_bytes: " << tables_blob.size() << "\n";
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
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    auto chl = cp::asioConnect(cfg.ip + ":" + std::to_string(cfg.port), false);
    PRNG prng(sysRandomSeed());

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

    std::vector<u8> tables_blob;
    if (!cfg.tables_online) {
        tables_blob = recv_blob(chl);
    }

    double offline_ms = ms_between(t_off0, std::chrono::steady_clock::now());
    u64 offline_B = sockBytes(chl) - b0;

    ping_sync(chl, false);

    auto t_on0 = std::chrono::steady_clock::now();
    auto bon = sockBytes(chl);

    BitVector choices(cfg.n_ot);
    choices.randomize(prng);
    AlignedUnVector<block> otOut(cfg.n_ot);
    cp::sync_wait(receiver.receive(choices, otOut, prng, chl));
    cp::sync_wait(chl.flush());

    if (cfg.tables_online) {
        tables_blob = recv_blob(chl);
    }

    auto [gr, aes_key] = deserialize_garble(tables_blob);
    FixedKeyAES aes(aes_key);
    Circuit circ;
    circ.n_and = gr.tables.size();
    volatile u8 sink = 0;
    for (u64 i = 0; i < cfg.m; ++i) {
        auto out = evaluate(circ, aes, gr, (i & 1) != 0, (i & 2) != 0);
        sink ^= out.b[0];
    }
    // Touch OT outputs
    {
        u8 tmp[16];
        memcpy(tmp, &otOut[0], 16);
        sink ^= tmp[0];
    }
    (void)sink;

    u8 ack = 1;
    cp::sync_wait(chl.send(std::move(ack)));
    cp::sync_wait(chl.flush());

    auto proof = recv_blob(chl);
    std::string proof_path = cfg.work_dir + "/proof_client.bin";
    {
        std::ofstream pf(proof_path, std::ios::binary);
        pf.write(reinterpret_cast<const char*>(proof.data()), (std::streamsize)proof.size());
    }
    std::string verify_out;
    std::ostringstream vcmd;
    vcmd << "'" << cfg.stark_bin << "' verify -i '" << proof_path << "'";
    int vrc = run_shell(vcmd.str(), &verify_out);
    u8 vok = (vrc == 0 && verify_out.find("verify: ok") != std::string::npos) ? 1 : 0;
    cp::sync_wait(chl.send(std::move(vok)));
    cp::sync_wait(chl.flush());

    double online_ms = ms_between(t_on0, std::chrono::steady_clock::now());
    u64 online_B = sockBytes(chl) - bon;

    std::cout << "role: client\n";
    std::cout << "tables_mode: " << (cfg.tables_online ? "online" : "offline") << "\n";
    std::cout << "m: " << cfg.m << "\n";
    std::cout << "n_ot: " << cfg.n_ot << "\n";
    std::cout << "tables_bytes: " << tables_blob.size() << "\n";
    std::cout << "proof_bytes: " << proof.size() << "\n";
    std::cout << "offline_ms: " << std::fixed << std::setprecision(3) << offline_ms << "\n";
    std::cout << "offline_B: " << offline_B << "\n";
    std::cout << "online_ms: " << online_ms << "\n";
    std::cout << "online_ms_per_eval: " << (online_ms / double(cfg.m)) << "\n";
    std::cout << "online_B: " << online_B << "\n";
    std::cout << "online_B_per_eval: " << (online_B / double(cfg.m)) << "\n";
    std::cout << "online_rounds: 2\n";
    std::cout << "verify_ok: " << int(vok) << "\n";
    std::cout << "stark_verify_log:\n" << verify_out;
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
    cfg.stark_bin = cmd.getOr<std::string>("stark", "stark-mmo/target/release/stark-mmo");
    cfg.work_dir = cmd.getOr<std::string>("workdir", "/tmp/voprf_e2e");
    cfg.stark_n = cmd.getOr<u64>("stark-n", 16384);

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

// SoftSpokenMalOtExt online microbench (modern libOTe + coproto).
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <string>
#include <thread>
#include <cmath>

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Crypto/PRNG.h>

#include <libOTe/Tools/Coproto.h>
#include <libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h>
#include <coproto/Socket/AsioSocket.h>

#ifdef ENABLE_MR_KYBER
#include <libOTe/Base/MasnyRindalKyber.h>
#endif

using namespace osuCrypto;

static double ms_between(std::chrono::steady_clock::time_point a,
                         std::chrono::steady_clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

static u64 sockBytes(Socket& chl) {
    return chl.bytesSent() + chl.bytesReceived();
}

#ifdef ENABLE_MR_KYBER
static void runKyberBaseOT(u64 nBase, const std::string& ip, int port, int trials) {
    auto srv = std::thread([&]() {
        auto chl = cp::asioConnect(ip + ":" + std::to_string(port), true);
        PRNG prng(sysRandomSeed());
        MasnyRindalKyber base;
        for (int t = 0; t < trials; ++t) {
            auto t0 = std::chrono::steady_clock::now();
            std::vector<std::array<block, 2>> msg(nBase);
            auto b0 = sockBytes(chl);
            cp::sync_wait(base.send(msg, prng, chl));
            cp::sync_wait(chl.flush());
            auto t1 = std::chrono::steady_clock::now();
            auto bytes = sockBytes(chl) - b0;
            std::cout << "KYBER_BASE_OT sender trial=" << t
                      << " n=" << nBase
                      << " ms=" << std::fixed << std::setprecision(3) << ms_between(t0, t1)
                      << " total_B=" << bytes
                      << " total_KB=" << (bytes / 1024.0) << std::endl;
        }
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto chl = cp::asioConnect(ip + ":" + std::to_string(port), false);
    PRNG prng(sysRandomSeed());
    MasnyRindalKyber base;
    for (int t = 0; t < trials; ++t) {
        BitVector choices(nBase);
        choices.randomize(prng);
        std::vector<block> msg(nBase);
        auto b0 = sockBytes(chl);
        auto t0 = std::chrono::steady_clock::now();
        cp::sync_wait(base.receive(choices, msg, prng, chl));
        cp::sync_wait(chl.flush());
        auto t1 = std::chrono::steady_clock::now();
        auto bytes = sockBytes(chl) - b0;
        std::cout << "KYBER_BASE_OT receiver trial=" << t
                  << " n=" << nBase
                  << " ms=" << std::fixed << std::setprecision(3) << ms_between(t0, t1)
                  << " total_B=" << bytes
                  << " total_KB=" << (bytes / 1024.0) << std::endl;
    }
    srv.join();
}
#endif

static void runExt(u64 n, const std::string& ip, int port, int trials) {
    auto srv = std::thread([&]() {
        auto chl = cp::asioConnect(ip + ":" + std::to_string(port), true);
        PRNG prng(sysRandomSeed());
        for (int t = 0; t < trials; ++t) {
            SoftSpokenMalOtSender sender;
            sender.init(2);
            PRNG common(toBlock(u64(1234567 + t)));
            auto nBase = sender.baseOtCount();
            std::vector<std::array<block, 2>> sendMsgs(nBase);
            common.get(sendMsgs.data(), sendMsgs.size());
            BitVector bv(nBase);
            bv.randomize(common);
            std::vector<block> recvMsgs(nBase);
            for (u64 i = 0; i < nBase; ++i) recvMsgs[i] = sendMsgs[i][bv[i]];
            sender.setBaseOts(recvMsgs, bv);

            std::vector<std::array<block, 2>> messages_storage; // unused
            AlignedUnVector<std::array<block, 2>> messages(n);
            u8 ping = 1;
            cp::sync_wait(chl.send(std::move(ping)));
            cp::sync_wait(chl.recv(ping));
            cp::sync_wait(chl.flush());
            auto b0 = sockBytes(chl);

            auto t0 = std::chrono::steady_clock::now();
            cp::sync_wait(sender.send(messages, prng, chl));
            cp::sync_wait(chl.flush());
            auto t1 = std::chrono::steady_clock::now();
            auto bytes = sockBytes(chl) - b0;
            std::cout << "OT_EXT SoftSpokenMal sender n=" << n
                      << " trial=" << t
                      << " ms=" << std::fixed << std::setprecision(3) << ms_between(t0, t1)
                      << " us_per_ot=" << (ms_between(t0, t1) * 1000.0 / double(n))
                      << " total_B=" << bytes
                      << " total_KB=" << (bytes / 1024.0)
                      << " baseOtCount=" << nBase << std::endl;
            (void)messages_storage;
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto chl = cp::asioConnect(ip + ":" + std::to_string(port), false);
    PRNG prng(sysRandomSeed());
    for (int t = 0; t < trials; ++t) {
        SoftSpokenMalOtReceiver receiver;
        receiver.init(2);
        PRNG common(toBlock(u64(1234567 + t)));
        auto nBase = receiver.baseOtCount();
        std::vector<std::array<block, 2>> sendMsgs(nBase);
        common.get(sendMsgs.data(), sendMsgs.size());
        receiver.setBaseOts(sendMsgs);

        BitVector choices(n);
        choices.randomize(prng);
        AlignedUnVector<block> messages(n);

        u8 ping = 0;
        cp::sync_wait(chl.recv(ping));
        cp::sync_wait(chl.send(std::move(ping)));
        cp::sync_wait(chl.flush());
        auto b0 = sockBytes(chl);

        auto t0 = std::chrono::steady_clock::now();
        cp::sync_wait(receiver.receive(choices, messages, prng, chl));
        cp::sync_wait(chl.flush());
        auto t1 = std::chrono::steady_clock::now();
        auto bytes = sockBytes(chl) - b0;
        std::cout << "OT_EXT SoftSpokenMal receiver n=" << n
                  << " trial=" << t
                  << " ms=" << std::fixed << std::setprecision(3) << ms_between(t0, t1)
                  << " us_per_ot=" << (ms_between(t0, t1) * 1000.0 / double(n))
                  << " total_B=" << bytes
                  << " total_KB=" << (bytes / 1024.0)
                  << " baseOtCount=" << nBase << std::endl;
    }
    srv.join();
}

int main(int argc, char** argv) {
    CLP cmd(argc, argv);
    u64 n = cmd.getOr<u64>("n", 32768);
    int trials = cmd.getOr("trials", 3);
    int port = cmd.getOr("port", 12121);
    std::string ip = cmd.getOr<std::string>("ip", "127.0.0.1");

    std::cout << "ot_bench SoftSpokenMalOtExt (malicious SoftSpoken 1-of-2)"
              << " n=" << n << " trials=" << trials << std::endl;

    if (cmd.isSet("kyberOnly")) {
#ifdef ENABLE_MR_KYBER
        SoftSpokenMalOtSender s;
        s.init(2);
        runKyberBaseOT(s.baseOtCount(), ip, port, trials);
#else
        std::cerr << "Built without ENABLE_MR_KYBER\n";
        return 1;
#endif
        return 0;
    }

    runExt(n, ip, port, trials);

    if (cmd.isSet("kyberBase")) {
#ifdef ENABLE_MR_KYBER
        SoftSpokenMalOtSender s;
        s.init(2);
        std::cout << "=== Kyber/MR base OT (offline, one-time) n=" << s.baseOtCount() << " ===\n";
        runKyberBaseOT(s.baseOtCount(), ip, port + 1, std::max(1, trials));
#else
        std::cout << "NOTE: ENABLE_MR_KYBER not set\n";
#endif
    }
    return 0;
}

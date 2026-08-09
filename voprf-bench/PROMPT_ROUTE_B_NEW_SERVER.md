# Prompt: 在新服务器上按路线 B 实现论文级 GC-VOPRF 真 E2E

把下面整段复制给新机器上的 Cursor/Agent 即可。目标机建议：**≥16 GiB RAM、≥4 vCPU、Ubuntu/Debian x86_64**（完整 AES-garbling STARK prove 在 2 GiB 机器上很容易 OOM）。

---

## 你的任务

在仓库 `https://github.com/longchenHefei/simple-OPRF` 的 `voprf-bench/` 上，**按论文协议从零实现真正的端到端 GC-VOPRF**（路线 B），验收标准：

1. **协议对齐论文**（PDF：`Post_Quantum_OPRF_from_garbled_circuit__new.pdf`，重点 §V Fig.9–10、§VII）  
2. **真 STARK AIR**：证明 **half-gate garbling 正确性**（及 key commitment），**禁止**再用 Fibonacci 占位  
3. **正确性**：client 输出 \(y = F_k(x) = H_2(x,\mathrm{AES}(k,H_1(x)))\)，与明文计算逐条一致；验证失败则 `⊥`  
4. Linux loopback 跑通 `tables offline` / `tables online`，写清 online/offline 时间与通信，提交 GitHub  

不要改 Overleaf；只改本仓库代码与 `voprf-bench/results/`。

---

## 论文协议摘要（必须遵守）

### 功能

- \(F_k(x) := H_2(x, \mathrm{AES}_{k}(H_1(x)))\)，AES-128，\(\lambda=128\)  
- \(H_1,H_2\)：实现用 **SHA-256**（或论文声明的 RO 实例化），写进 RESULTS  

### 电路

- Garble **AES datapath** \(C\)：garbler 输入 round keys \(rk_0,\ldots,rk_{10}\)（server 本地 KeySchedule(\(k\))），evaluator 输入 \(x'=H_1(x)\in\{0,1\}^\lambda\)  
- Half-gates + **fixed-key AES (MMO)** gate hash  
- 规模约 **6553 AND / 24000 XOR**（与论文实现一致；优先 Bristol AES datapath 拓扑，或可验证等价电路）  

### Probe-resilient

- \(x'\) 用 **s-probe-resilient** XOR 分享，论文实测 \(n=2\lambda\)（\(s=2\)）  
- Batch \(m=128\) → OT 次数 \(m\cdot n = 32768\)（SoftSpokenMal）  

### STARK（Fig.10，真 AIR——本路线核心）

**一次性 key commitment** \(\pi_k\)：  
公开 \(cm=(H(k), \mathrm{AES}(k,0),\ldots,\mathrm{AES}(k,T-1))\)，\(T=128\)；证明知 \(k\)。

**每 batch 正确 garbling 证明** \(\pi\)：  
- Public：\(cm\)、各电路 input-wire label 对的 Merkle 根 \(\{R_i\}\)、\(\{H(GC_i)\}\)、key-wire labels \(\{\delta_{i,rk}\}\)、输出解码信息  
- Witness：\(k\)、全部 wire labels / garbling 随机性  
- Constraints：（i）\(cm\) 打开到 \(k\) 且 \(rk=\mathrm{KeySchedule}(k)\)；（ii）每个 AND 的 half-gate 密文相对 MMO gate-hash 正确；（iii）各电路 key-wires 编码同一 \(rk\)；（iv）Merkle 根承诺与 (ii) 一致的 input label pairs  

论文实现：winterfell、约 62-bit 域、LogUp/S-box lookup 风格（Table IV）；Mac 量级 prove ~5 s/circuit、verify ~3 ms。参数尽量对齐（queries/blowup/grinding），RESULTS 写明实际参数。

**禁止**：与 GC 无关的 Fib/toy AIR 冒充论文 STARK。

### Online（2 rounds）

1. Client→Server：对每个 \(x_i\)，\(x'=H_1(x)\)，probe-resilient 编码 → OT 选择比特 → OT₁  
2. Server→Client：OT₂（input labels）+ \(\{GC_i,\delta_{i,rk},R_i\}\) + \(\pi\)（tables offline 时可提前发 tables，但仍须与 \(\pi\) 绑定）  
3. Client：Verify \(\pi\)；检查 OT labels ∈ \(R_i\)；EvalGC → \(z_i\)；\(y_i=H_2(x_i,z_i)\) 或 `⊥`

Base OT：Kyber/MR（PQ），离线一次性。OT 扩展：libOTe SoftSpokenMal。

---

## 仓库里已有（可复用，勿推倒重来）

Clone：

```bash
git clone --recurse-submodules git@github.com:longchenHefei/simple-OPRF.git
cd simple-OPRF/voprf-bench
```

| 已有 | 路径 | 用法 |
|---|---|---|
| Half-gates MMO 微基准 | `gc_mmo.hpp` | **替换/扩展**为真 AES datapath + 真实 wire 标签语义 |
| SoftSpoken + Kyber bench | `ot_bench.cpp`, `setup_libote_modern_linux.sh` | 接入协议，**OT 输出必须成为 GC 输入标签** |
| 假 E2E 管线 | `voprf_e2e.cpp` | 重写协议逻辑；可保留 asio 会话/计量骨架 |
| Fib 占位 STARK | `stark-mmo/` | **删除或移到 `stark-mmo-fib-stub/`**，新建真 AIR crate |
| Gold 对照 | `deps/PR-OPRF`, RESULTS | 可选保留，非本任务重点 |
| 论文 PDF | 仓库根目录 | 以 Fig.9–10 / §VII 为准 |

注意：`deps/` 通常 gitignore，需按 `setup_libote_modern_linux.sh` 重建 libOTe（clang-19、SoftSpoken、MR_KYBER）。**不要**在 AsioSocket 里打开 `COPROTO_ASIO_DEBUG`（双线程竞态 terminate）。

---

## 建议实现顺序

1. **明文参考**：`F_k(x)` 与 AES datapath 明文 eval；固定测试向量  
2. **真 GC**：Bristol（或等价）AES datapath；garble/eval；key wires 本地、input wires 经 OT  
3. **Probe-resilient + SoftSpoken**：\(m=128,n=256\) 每 eval（或总 32768）；labels 与 Merkle \(R_i\) 一致  
4. **STARK AIR（winterfell）**：先单电路 Fig.10 核心约束，再 batch \(m\)；key commitment \(\pi_k\)  
5. **绑定**：\(\pi\) 的 public input 含 \(H(GC_i),R_i,cm\)；改 GC 或 labels 必须导致 verify 失败（负例测试）  
6. **E2E driver**：重写 `voprf_e2e`；offline/online 计时；`tables offline|online`  
7. **验收测试**：随机 \((k,x)\)，\(y\) 与明文 \(F_k(x)\) 全等；篡改 tables/proof → abort  
8. **RESULTS.md**：机器信息、复现命令、真 prove/verify/proof size、与旧 Fib 占位明确切割  
9. **Commit + push** `main`

---

## 验收清单

- [ ] Client \(y_i = H_2(x_i,\mathrm{AES}_k(H_1(x_i)))\) 对 batch 全通过  
- [ ] STARK 证明对象是 **garbling/key**，不是 Fib；负例（改 GC）verify fail  
- [ ] OT labels 参与 EvalGC（不是 “touch 一下 OT 输出”）  
- [ ] Probe-resilient \(n=2\lambda\)（或 RESULTS 写明实际 \(s\)）  
- [ ] Online ≈ 2 rounds；Kyber base OT 计 offline  
- [ ] loopback `tables offline` + `tables online` 日志入库  
- [ ] 推送到 GitHub  

---

## 环境与风险

- 需要：`build-essential`, `cmake`, `clang-19`, `libssl-dev`, `libgmp-dev`, `libsodium-dev`, `libboost-*`, `rustup`  
- **RAM**：完整 prove 建议 ≥16 GiB；若 OOM，减小 batch 做正确性证明，或加大机器，勿退回 Fib  
- 本任务是 **从零实现 Fig.10 AIR**（仓库无 Mac 真 STARK 源码可抄）  
- 不要把组件合成公式或 Fib E2E 数字当成论文最终 STARK 行  

---

## 成功时的简报（中文）

完成后用中文说明：是否跑通、\(F_k(x)\) 测试向量是否通过、STARK prove/verify/proof size、与论文 Mac 量级对比、GitHub commit。

# DiskGenius 6.2.0.1829 X86IL VM —— 运行期证据汇总（v5/v6 Actions 实证）

> 2026-11-18。所有结论均来自 Actions 运行期产物实查（artifact3/artifact5/artifact6），
> 非猜测。产物本地位置：`/workspace/dgwork/artifact{3,5,6}/`。

## 1. 已确证事实

| # | 事实 | 证据 |
|---|------|------|
| 1 | 运行期把镜像基址（0x140000000）补进 .vmp 段内全部指针 | v5 t0 vs 静态脱壳产物 diff：494 区 / 47 KB，典型 `0x01a2b588 → 0x141a2b588` |
| 2 | **5 张真 VM 表**（明文 VA，全部落保护段，项间隔主导 5 字节 = jmp rel32 桩） | 0x141a3048a(149 项)、0x141da2b42(49)、0x14208b29b(1662)、0x1421080ab(661)、0x141d8df04(1096)。v3 的 table_0x39 就是其中之一，"假阳性"是 resolve_map 错误 sub 变换造成的误判 |
| 3 | VM 描述符（ctx）真实槽位 | rbp 现场（hot 期抓的活 ctx）：**+0x73 = IP 指针**、**+0xC4 = 表指针（1096 表）**、+0xF5 = 表指针（661 表）、+0x20 = 链接的下一描述符 |
| 4 | **加密无名节运行期 99.6% 解密** | v6 dump enc1/2/3（0x14062f000/0x1407be000/0x1409a3000）与 exe 原文仅 0.4-0.6% 字节相同 |
| 5 | 活 VM 的字节码在 .vmp 内 | 活 ctx +0x73 = 0x141df1de2（IP），执行期字节码在内存中明文（handler 直接 movzx 读） |
| 6 | handler 结构确认 | 共享取指链：`mov rdx,[rbp+0x73]; add rdx,8; movzx ecx,word[rdx]` → **opcode 在 IP+8 处的 u16**；字段散布于 IP+2(byte)/+3(u16)/+5(u16)/+7(u16)/+0xa/+0xb/+0xd/+0x13；且 **每个 VM 实例字段布局变异** |
| 7 | 指令含±4 条件调整（分支类） | op0 handler：`cmp flag@IP+13 & 0x400; sub/add qword [ctx[u16@IP+7]], 4` |
| 8 | 派发不走静态表引用 | 派发器从 ctx+0xC4 读表指针，rip 相对/movabs 静态引用只有 movabs 一处（恰好落在 ctx 槽位置，即表槽本身） |

## 2. 迭代史（三轮 Actions）

- **v3 run（44255020457）**：三轮全假阳性——表项 100% 落原生 .text（resolve_map 错误变换）、ctx.bin 51/2048 非零。教训：槽位猜测路线失败。
- **v5 run（44257362614）**：整段 dump .vmp+.boot → 发现基址重定位差 + table_0x50 真表 + .boot 不变。
- **v6 run（44266090291）**：dump 全部关键段（含三段加密节）→ enc 节解密证实、活 ctx 密钥槽暴露。

## 3. 剩余工作（明确、无未知数）

1. **派发器 ABI 建模**：handler 入口寄存器由派发器设置（rdx/r10/r15 等语义），需从 VM 入口 trampoline 顺着找到派发器，或在 unicorn 中从 native 调用点起模拟。
2. **handler 语义自动提取**：unicorn 每handler 沙箱模拟 + ctx 页 diff → 得到每 opcode 的 (读字段, 写寄存器, IP 步长, 核心运算)。
3. **字节流解析**：已知实例的流位于 0x141df1dea 起（IP+8 为首 opcode），用 #2 的结果线性解码。
4. **授权算法还原**：对 LA_Init_AR / LA_Init_SM 对应的 VM 实例（ctx @0x141c50d31 的 1096-op 表 / @0x1420c0e5f 的 661-op 表）解码到高级伪代码。

## 4. 关键产物文件

- `artifact6/prot_t0_*.bin`：运行期解密内存（.vmp/.boot/enc1-4 等 10 段）
- `artifact6/rbp_t0_*.bin`：活 VM ctx 4KB 快照 ×2
- `artifact6/ip_advance.txt`：handler IP 步长扫描（空——证明步长不在 handler 内直接写回，需派发器 ABI）
- `artifact5/handlers_vm0.txt`：VM 实例 0（49 op）handler 反汇编
- 仓库新增：dump_runtime.py v6（全段 dump）、analyze_v6.py（离线 diff+扫描工具）

# VM 指令级探针：Wine 本机实证（2026-11-19）

目标：在不依赖 GitHub Actions 的前提下，于本机 Wine 环境里对 DiskGenius 6.2.0.1829 的
Themida 派发器做**指令级追踪**，为还原授权校验那段虚拟化代码铺路。

结论先说：**探针成立**——改派发表 + 注入记录桩 + 影子表回跳这条链路在本机跑通了，
能在 VM 执行瞬间拿到「VM 上下文 IP + 该地址 8 字节」。但**还没抓到授权校验的完整字节码序列**，
卡点见 §6，原因已定位到具体假设。

---

## 1. 环境复现（本机，非 Actions）

| 项 | 值 |
|---|---|
| Wine | 9.0（Ubuntu repack），prefix 为 win64 |
| 目标 | `vendor/DGEng6201829_x64.zip` → `DiskGenius/DiskGenius.exe` |
| 显示 | Xvfb `1280x900x24` |
| 启动方式 | 直接用 `/usr/lib/wine/wine64 DiskGenius.exe`（不走 `wine` 包装脚本，避免进程变成孙进程导致 attach 不到） |

运行期镜像 dump 成功：`0x140000000` 起 `0x2FF3000`（50,278,400 字节），熵与代码特征正常：

```
dos_header  0x140000000  entropy=1.34  (MZ)
dispatch    0x141a35366  entropy=6.36  non-zero 77.8%
.vmp        0x141d34000  entropy=5.49
bytecode    0x142150000  entropy=5.97
```

`.vmp` 段在运行期是 **RWX**，范围 `0x1419d4000 – 0x142780000`（约 13.7 MB）：

```
rwxp 1419d4000-142780000 00000000 00:00 0
```

（另有 ntdll 一小段 rwxp，无关。）

---

## 2. 派发表实测（运行期）

三张已知表在运行期都是**绝对 VA**（RVA 风格只在静态产物里成立）：

| 表地址 | 项数 | 前 4 项 |
|---|---|---|
| `0x1421080ab` | 661 | `141cf832a 141fc35d4 141fc35d9 141e6e631` |
| `0x141da2b42` | 49 | `141c9db1a 141c9db1f 141ccff11 141ccff16` |
| `0x141d8df04` | 1096 | `1419ddfdf 1419ddfe4 141a4af30 141a4af35` |

成对规律 `v[2k+1] = v[2k] + 5` 在三张表上都成立（与 v22 报告一致）。

---

## 3. 实验一：改表 → 程序立刻退出（表在热路径）

把 `0x1421080ab` 前 4 项改写成指向代码段里的 `0xCC` 填充洞（`0x14167cffc`）：

```
attached 893
T[0]=0x141cf832a
table poisoned
exited code 1        ← 3 秒内退出
```

说明这张表在启动完成后仍在被读取并用于 `jmp`，**改表 = 直接命中派发路径**。
（也说明这条表不适合用「改成非法目标」的方式做断点，见 §4。）

顺带一个坑：`ptrace` 的 `restype` 默认是 `c_int`，会把 64 位地址截断成
`0x41cf832a`（少了 `0x100000000`）。必须显式 `libc.ptrace.restype = c_long`。

---

## 4. 实验二：int3 填充洞不可用

把表项指向代码段的 `CC CC CC...` 填充洞：程序**没有把 SIGTRAP 交给 tracer**，
而是自己退出（`exited code 1`）。原因：PE 进程里的 `int3` 走 Windows 异常分发
（`EXCEPTION_BREAKPOINT`），没有 Windows 调试器接管时由 SEH/崩溃路径吃掉，
ptrace 层拿不到干净的断点。

→ **int3 路线在这份二进制上不成立**，与仓库里「inline hook 会劈开 `jmp rsi` 后 3 字节活代码」是同一类坑。

---

## 5. 实验三：记录桩 + 影子表（成立）

### 5.1 做法

1. 在 `.vmp`（RWX）里找一段连续零洞（本机实测最大 **14,797 字节**，位置 `0x1420f53b0` 附近，
   每次运行需重新扫描）。
2. 写入一个**共享记录桩**（99 字节），把整张 661 项的表全部指向它。
3. 另存一份**影子表**（原始 661 项），桩里用 `r15`（派发器设好的 `op*8`）查影子表拿回真正的 handler。
4. 桩尾部 `jmp rsi`，回到原 handler，语义等价。

桩的汇编（机器码见 `tools/vmp_tracer.py`）：

```
pushfq
push rax; push rcx; push rdx; push rbx
push r10; push r11
mov  rax, [rbp+0xBC]     ; VM 上下文里的 IP 槽（派发器同款）
mov  rdx, BUF
mov  rcx, CNT
mov  r10, [rcx]          ; 记录下标
mov  r11, r10; shl r11,4
mov  rbx, [rax]          ; ★ 该时刻 IP 处的 8 字节
mov  [rdx+r11],   rax    ; 记录 IP
mov  [rdx+r11+8], rbx    ; 记录字节
inc  r10; and r10, 0x1FF; mov [rcx], r10
mov  r10, SHADOW
mov  rsi, [r10+r15]      ; 影子表 → 真正的 handler
pop r11; pop r10; pop rbx; pop rdx; pop rcx; pop rax
popfq
jmp  rsi
```

关键编码（踩过的坑）：
- `mov rsi,[r10+r15]` = `4F 8B 34 3A`（W=1、X=1、B=1，SIB scale=0 index=r15 base=r10）。
  写成 `49 8B 34 47` 会变成 `[r15+rax*2]`，直接跑飞。
- 记录区、计数器、影子表**必须错开**：第一次把影子表放在 `zone+0`，直接盖掉了 `zone+0x10`
  的计数器，读回来是 `5402015193`（其实是 `0x1420f...` 之类的地址被当成了计数）。

### 5.2 结果

```
attached
T[0..3] ['0x141cf832a', '0x141fc35d4', '0x141fc35d9', '0x141e6e631']
zone 0x1420f53b0
stub len 99
hooked 661
recorded 2
IP 0x142160496 bytes ec26000031011200
```

- **桩确实进了 VM 热路径**（不是自旋、不是没命中），拿到了 IP 和该地址的 8 字节。
- 抓到的地址 `0x142160496` 落在 `0x14216xxxx` —— 正是之前「删文件调用链穿越的字节码区」。

### 5.3 但只有 1 条，而且判读有疑点

1. **只有 1 条**：不同 attach 时机（2/3/4/7 秒）都只记到 1 条，第 2 槽为空。
   说明这个 661 表实例被 hook 后**只再派发一次就停了**。
2. **字节形态可疑**：`ec260000 31011200` 在 dump 出来的运行期镜像里**一模一样**
   （`0x142160496` 处同样是 `ec26000031011200`，上下文 `5b00 7b00 4701 ec26 0000 3101 1200 6e9b 8e41 ...`
   更像 UTF-16/结构数据，不像指令流）。若按 `[u16 op][i32 rel]` 解：`op=0x26EC(9964)`、
   `rel=0x00012013`，**都不在合理区间**（表只有 661 项）。

→ 所以要么 `[rbp+0xBC]` 在这一刻不是 IP（rbp 不是 ctx），要么这个地址根本不是指令开头。
**这条必须在下一步证伪/证实，不能当成结论用。**

---

## 6. 另外两张表 hook 后直接崩（与 v24 一致）

```
=== table 0x141d8df04 n=1096 ===  dead at 0
=== table 0x141da2b42 n=49   ===  dead at 0
```

印证 v24 的结论：49/1096 两张表被**非派发路径**引用，钩表即停摆。
只有 661 表可以安全改。

---

## 7. 下一步（按性价比排）

1. **证伪 rb+0xBC 假设**：在桩里同时记录 `rbp`、`[rbp+0xBC]`、`[rbp+0xF5]`（表基址），
   并与派发器 `0x141a35366–0x141a353d7` 现场对比。如果 `[rbp+0xF5]` != 表地址，
   说明 rbp 不是 ctx，改用 `[rbp+偏移]` 或直接从 `rsi` 反查。
2. **解决「只 1 条」**：怀疑 661 实例是「按次调用」的叶子 VM（进入→一条→退出）。
   验证办法：桩里额外记录**进入时的 rsp 与返回地址**，看是不是同一次调用。
3. **换成「进入点」而不是「表项」来插桩**：在派发器 `0x141a353d7` 之后（`jmp rsi` 目标处）
   不行，但在**每个实例的初始化代码**里找 `mov [ctx+0xBC], imm` 的赋值点，
   拿到 ctx 结构后再决定用哪个槽位读 IP。
4. 拿到可信 IP 流后：按 `[u16 op][i32 rel]` 逐条对齐（用「本条 IP + rel == 下条 IP」自校验），
   再叠 handler 语义，就能线性反编译授权函数。

---

## 8. 复现

```bash
python3 tools/vmp_tracer.py --wait 4 --table 0x1421080ab --count 661 --seconds 6
```

输出：`vm_trace_local.txt`（每行 `IP bytes`）。

依赖：本机 Wine 9.0、Xvfb、`/proc/<pid>/mem` 读写权限（ptrace attach 后）。
不需要 unicorn / capstone，桩是裸机器码。

---

## 9. 本轮修掉的错误认知

| 旧 | 新 |
|---|---|
| int3 填充洞可以当断点 | 不行，PE 异常分发会吃掉 SIGTRAP |
| 静态 `.vmp` 里 RVA 风格表是运行期形态 | 运行期全是绝对 VA |
| `ptrace` 直接可用 | 必须设 `restype=c_long`，否则地址截断 |
| 零洞按 256KB 找 | 本机最大只有 ~14.8KB，布置要精打细算 |

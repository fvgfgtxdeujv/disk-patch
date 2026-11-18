# 运行期取数清单 —— handler 表指针的静态定位

日期：本轮（承接 `REPORT_ipslot.md` 第七节第 7.3 条）
状态：**表指针所在上下文槽已定位，运行期 dump 脚本已生成，可直接拿去拼 opcode→handler**

---

## 一、结论

第六形态的 `table` 不是静态常量，而是从 VM 上下文里取出来的二级指针。静态回溯后确认它落在**三个槽位**：

| ctx 槽偏移 | 派发点 | 占比 |
|---|---|---|
| `ctx + 0x4` | 611 | 32.2% |
| `ctx + 0x8` | 534 | 28.1% |
| `ctx + 0xF5` | 532 | 28.0% |
| `ctx + 0x110` | 49 | 2.6% |
| `ctx + 0x1F4` | 32 | 1.7% |

前三个槽位占 **88%**。也就是说：在运行期把 `ctx+0x4 / ctx+0x8 / ctx+0xF5` 三个 qword 读出来，
就是全部 handler 表的基址；`table[opcode]` 即 handler。

**已定位 1898 / 3314 个派发点（57.3%）**，其余在 junk 干扰下反向走链失败。

---

## 二、怎么定位的

### 2.1 上下文指针装载惯用法

真实代码里取上下文字段的形态是固定的三连（中间允许 junk 插入）：

```asm
mov  r10, rbp
add  r10, 4
mov  r10, qword ptr [r10]     ; r10 = ctx[4]   ← 表指针
```

外加直接形态 `mov rA, qword ptr [rbp+K]`。

全载荷扫出 **23335 处**这类装载，记成 `(指令地址, 寄存器, 槽偏移)` 表。

### 2.2 派发点对齐

对每个派发点反向走链，找到 `mov rD, [rA]`（表项读取），再用 `rA` 去上面那张表里找
**最近的、在前 400 字节内**的同寄存器装载，它的槽偏移就是表指针槽。

实例（0x141D34F54 这个派发点）：

```asm
141D34E77  mov  r10, rbp
141D34E8F  add  r10, 4
141D34EB3  mov  r10, qword ptr [r10]      ; r10 = ctx[4]
...
141D34EEE  and  r12, 0xffff                 ; 16 位 opcode
141D34EFC  shl  r12, 3                      ; *8
141D34F0A  add  r10, r12                    ; ctx[4] + opcode*8
141D34F0D  mov  r11, qword ptr [r10]        ; handler = table[opcode]
...
141D34F4B  add  qword ptr [rbx], r10        ; IP += 步长
141D34F54  jmp  r11
```

### 2.3 IP 槽要排除

`ctx+0x18 / 0x55 / 0x92 / 0x120 / 0x17A` 是 IP 槽（见 `REPORT_ipslot.md` 第三节），
它们的装载形态和表指针一模一样，会误配。本轮排除了 **140 个**这类碰撞。

---

## 三、运行期怎么用

### 3.1 Frida

```bash
python3 tableresolve.py DiskGenius_unpacked_vmp.bin --ipslots ipslots.json \
        --emit-frida dump_tables.js --emit-x64dbg dump_tables.x64dbg
```

`dump_tables.js` 里已经写死：

```js
const CTX = "rbp";
const SLOTS = [0x4, 0x8, 0xF5, 0x110, 0x1F4];
const DISPATCH = [0x141D345C0, 0x141D356F4, ...];   // 前 64 个派发点
```

在任意一个派发点命中时调用 `dumpTables.call(this)`，会逐槽打印
`ctx+0x4 -> table 0x...` 以及 `opcode 0xNN -> handler 0x...`（每张表读 64 项）。

### 3.2 x64dbg

`dump_tables.x64dbg` 是纯日志脚本，在 `rbp = VM 上下文基址` 时运行即可。

### 3.3 拿到表之后

把 `table[opcode]` 的 256 项（16 位 opcode 则按实际项数）读出来，配 `REPORT_ipslot.md`
的 3244 个派发点，就能把 `opcode → handler` 填满；再喂给 `x86il_deobf_v2.py --batch`
逐条做语义提升。

---

## 四、数字与限制

| 项 | 值 |
|---|---|
| 上下文装载惯用法 | 23335 处 |
| 派发点总数 | 3314 |
| 表指针槽位可定位 | **1898（57.3%）** |
| 其中误配到 IP 槽（已剔除） | 140 |
| 三大槽位占比 | 88% |
| 分析耗时 | 1 分 47 秒（含穷举兜底） |

**一个被本地自测揪出来的认知修正**：

`ctx+0x4` 与 `ctx+0x8` 作为 8 字节指针**在内存上是重叠的**（0x4..0xB 与 0x8..0xF 有 4 字节交集）。
所以在同一个上下文里，这两个槽不可能同时成立 —— 它们更像是「不同上下文基址」下的同一个表指针
（即某些派发器以 `rbp+4`、另一些以 `rbp+8` 当上下文起点），或者其中一个是错配。
写扫描器时按「各槽独立判定、只取命中的那个」处理；合成内存自测（`winactions/local_selftest.py`）
就是按这个约束建模的。

**限制（必须说清楚）**：

1. **42.7% 的派发点没解出来**。真实代码 junk 密度太高，反向走链会断。
   数字方向上只会偏保守 —— 但具体缺哪些、是否系统性偏向某类派发器，没验证。
2. **槽偏移的含义仍未证实**。`0x4` 和 `0x8` 相隔 4 字节，像是两个相邻的指针字段
   （可能是两张表：一张给 16 位 opcode、一张给别的用途），但没有运行期证据。
3. **`ctx` 基址按 rbp 假设**。整条链都是从 `mov rX, rbp` 起算的；如果存在用别的
   寄存器当上下文基址的路径，这些会被漏掉。`dump_tables.js` 里 `CTX` 是可改的。
4. **脚本没在真实 Windows 上跑过**。本环境是 Linux 分析容器，没有 DiskGenius 运行实例，
   所以只验证了「脚本生成正确、地址与槽位来自实测数据」，**没有验证运行期输出**。
   这一点不能含糊。
5. 所有结论来自这一份 13.9MB 载荷；换保护版本后槽偏移要重新标定。

---

## 五、交付

| 文件 | 说明 |
|---|---|
| `tableresolve.py` | 表指针定位 + 运行期取数清单 + 脚本生成 |
| `tableres.json` | 1898 个派发点的 `(地址, 表基址寄存器, 槽偏移)` |
| `dump_tables.js` | Frida 脚本 |
| `dump_tables.x64dbg` | x64dbg 脚本 |

```bash
python3 tableresolve.py payload.bin --ipslots ipslots.json --json tableres.json
python3 tableresolve.py payload.bin --ipslots ipslots.json \
        --emit-frida dump_tables.js --emit-x64dbg dump_tables.x64dbg
```

---

## 六、版本与坐标系（本轮新增，重要）

把官网的绿色版拉下来核对后，发现两件事：

### 6.1 下载的是**加壳原版**，这正是我们要的

DiskGenius 6.2.0.1829 x64 的 PE 段表：

| 段 | VAddr | VSize | RawSize |
|---|---|---|---|
| `.vmp` | **0x19D4000** | 0xDAC000 | **0x0** |
| `.boot` | 0x2780000 | 0x872000 | 0x872000 |

`.vmp` 的 `RawSize = 0` —— 磁盘文件里这一段的**数据是零**，运行时才由壳解密填充。
所以静态从 exe 里读不到 VM 代码；要在内存里读，这就是 `ReadProcessMemory` 方案的依据。
`image_base = 0x140000000`，`SizeOfImage = 0x2FF3000`。

### 6.2 dump 的坐标系和真实 RVA 差了 0x360000

| | 起点 | 大小 |
|---|---|---|
| 静态 dump（`DiskGenius_unpacked_vmp.bin`） | RVA **0x1D34000** | 0xDDE000 |
| 这一版 PE 的 `.vmp` 段 | RVA **0x19D4000** | 0xDAC000 |

差 0x360000；而且 dump 比段大 0x32000（推测是 .vmp 之后 .boot 的头部一起被 dump 了）。

**dump 内部几乎没有自引用**：把 `0x141D34000` 当作 8 字节常量在 dump 里搜，只命中 1 处；
把整个 `[0x141D34000, 0x141D34000+0xDDE000)` 区间当值统计，对齐命中也只有 1 处。
说明这份 dump 里没有指向自身的绝对地址，**基址 0x141D34000 只是一个任选的坐标系**，
本身自洽（所有 handler 地址都相对它表示）。

### 6.3 所以合并时必须换算

运行期抓到的 handler 是绝对 VA：`module_base + 真实RVA`。
要跟静态 dump 对齐，得换算：

```
dump_va = 0x140000000 + 0x1D34000 + (runtime_va - module_base - 真实.vmp.RVA)
```

`dump_ctx.py` 现在会自己解析 PE 段表，把 `module_base` / `vmp_rva` / `vmp_vsize`
写进 `tables.json`；`merge_tables.py` 读这些字段自动换算，并把换算偏移打印出来。
实测（模拟 `module_base = 0x7FF6A0000000`）：`0x7FF6A19D4000` → `0x141D34000`，正确。

**如果跳过这步，抓回来的 handler 地址跟 dump 差 0x360000 加随机基址，`--batch` 会全部落空。**

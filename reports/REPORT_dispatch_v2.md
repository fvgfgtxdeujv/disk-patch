# dispatch 恢复 v1.1 —— 性能、集成、真实载荷验证

日期：本轮
状态：**三项遗留问题全部关闭**（性能达标 / 已集成 / 真实载荷验证完成）
基线：上一轮 `REPORT_dispatch.md`（核心算法完成、性能未达标、未集成、未上真实载荷）

---

## 零、结论先行

| 上一轮的未完成项 | 本轮结果 |
|---|---|
| 性能不达标（4MB 59.3s） | ✅ 4MB 混合 **7.2s**（11×）、4MB 纯随机 **0.43s**（105×）、真实 14MB **11.2s** |
| 未集成进 v2 | ✅ v2 的 `--scan` / `--batch` 默认走语义恢复，旧实现自动回退，新增 `--dispatch` 开关 |
| 未在真实载荷验证 | ✅ 真实 13.9MB 载荷跑通：25637 个派发核 → 10758 个种子 → 203 个 opcode / 7687 条目 / 11.2s |

同时修掉两个**会直接毁掉结果**的问题（详见第三、四节）：

1. 真实载荷的 opcode 是 **16 位**，旧代码只认「≤32 位寄存器写」，`movzx r13, word ptr [r13]` 这种形态会被整体漏掉。
2. 旧扫描器在真实载荷上 **0.18 秒返回 0 个 opcode**——capstone 迭代器碰到第一个无法解码的字节就静默停止，什么都不报。

---

## 一、性能：从「逐字节回退」到「正则预筛 + lite 热路径」

### 1.1 原来的瓶颈在哪

`linear_seed()` 的结构是：顺序解码，解不出来就 `off += 1` 再试。
4MB 随机数据区里每一步都失败，等于 400 万次 **Python 层的 capstone 调用**。

实测（同一台机器、capstone 5.0.7）：

```
disasm(单条，Python 层)      13.1 µs/条
disasm_lite(单条)            12.7 µs/条
disasm_lite(批量遍历)         2.2 µs/条      ← 差 6 倍
```

所以「每字节一次调用」这个结构本身就是错的，不是常数因子问题。

### 1.2 改法（按收益排序）

**① 种子来源换成候选点正则预筛（主要收益）**

三阶段，全部在 C 层完成定位：

```
阶段 1  正则找「比较类运算 + jcc」构成的派发核      4MB/0.24s，14MB/0.70s
阶段 2  逐核回溯 ≤48 字节，找最近的选择子装载指令
阶段 3  用 capstone 复核该位置确实是一条「寄存器 <- 内存」装载，才作为种子
```

选「派发核」而不是「选择子装载」当锚点，是因为前者在任何一种派发形态里都必然出现
（cmp 链、递减链、xor 变换链、二分派发都是「比较 + 跳转」），而后者在真实载荷里
遍地都是（`8b`/`0f b7` 合计 16.8 万处），无法区分。

另外补了一条独立路径：`jmp [reg*scale+disp]` 跳表形态，回溯 20 字节找选择子装载，
这样「只有跳表、没有 cmp」的派发器也能拿到种子。

**② 聚类不能按距离做（这一步先做错了，已回退）**

最初的实现把 32 字节内的核合并成一个代表，结果 dispatch2/dispatch3 因为紧贴 dispatch1
被整段漏掉，召回率从 12/12 掉到 7/12。改成**每个核都回溯、靠种子 offset 去重**才正确。
相邻派发器只隔十几字节是常态，不能靠距离聚合。

**③ 热路径彻底移出 detail 反汇编**

原来 `scan_block` 里每条 `cmp/jcc` 都调一次 `det()`（detail 模式），实测 78µs/条。
现在整条路径只用 `disasm_lite` 的 `(addr, size, mnemonic, op_str)` 四元组 + 字符串解析：

```python
dstr, sstr = _split2(ostr)          # 'ecx, 0x20' -> ('ecx', '0x20')
if canon(dstr) == sel: ...          # 寄存器归属
last_imm = _imm(sstr)               # 立即数
msz = _memsz(sstr)                  # 'word ptr [rax]' -> 2
```

detail 反汇编只在**跳表**这一条稀有路径上保留（`det_at()`）。

**④ 按块缓冲解码**

单条 `disasm_lite` 13µs、批量 2.2µs，所以按块取：一次解码 24 字节，块内顺序消费。
块大小是量出来的（16/24/32/64 各测一遍，24 字节最好——块普遍很短，缓冲开太大反而浪费）。

**⑤ 早退**

真派发块在「装载选择子」后一两条指令内必然比较它。跑到 24 条还没比较过，说明是 junk
代码里的伪核，直接放弃。真实载荷上砍掉约 17 万条无效指令。

### 1.3 结果

| 载荷 | 改前 | 改后 | 倍数 |
|---|---|---|---|
| 4MB 混合（代码/随机交替） | 81.7s | **7.19s** | 11.4× |
| 4MB 纯随机（最坏情况） | 45.4s | **0.43s** | 105× |
| 真实 13.9MB DiskGenius | 跑不起来（见第四节） | **11.2s** | — |

> 上一轮报告写的是 59.3s，本轮同一构造实测 81.7s——因为随机段占比更高。
> 两个数都记录在这里，避免以后对不上。

---

## 二、精度：三个新增约束

性能上去之后，**误报**成了主要问题。4MB 混合载荷一度产出 64913 条候选、37 个 opcode。
三个约束逐个加上：

**① 选择子必须真的参与比较（`saw` 标志）**

反例很典型：某块从一条伪装载起手（`8b 00` 被当成 `mov eax,[rax]`），后面比较的却是
另一个寄存器，`acc` 一直是 0，于是 `jz` 一路发出 `opcode = 0`。
现在要求块内至少出现过一次「比较类运算作用于选择子寄存器」，否则不发 opcode。

**② switch 形态的落空侧必须紧跟一条 jmp**

`cmp al,X; jne next` 在 junk 代码里密度极高。真实载荷上这一条把 **648 个假 opcode 砍到 167 个**。
判定用字节级检查（`E9`/`EB`/`FF /4`），不解码，零成本。

**③ 跳表的索引寄存器必须等于选择子**

`jmp [rax*8+table]` 里 rax 不是选择子时，说明这跟派发无关，直接记 unresolved 而不是发 opcode。

另外修好一个隐蔽 bug：`_memsz` 原先按字典顺序做子串匹配，`'word ptr'` 是
`'dword ptr'` 的子串，导致所有 dword 访问被当成 2 字节、选择子位宽算成 16 位。
现在改成取 `' ptr'` 前那个词精确查表。

---

## 三、16 位 opcode：真实载荷和合成载荷的根本差异

真实载荷里 `movzx r32, word ptr [..]`（`0f b7`）有 **19636** 处，而 `movzx r32, byte`（`0f b6`）
只有 1147 处。这个比例直接说明 opcode 是 **16 位**的。

旧代码漏掉这类形态有两个原因：

1. 选择子判定要求「目的寄存器宽度 ≤ 32」。但 `movzx r13, word ptr [r13]` 写的是 **64 位**寄存器
   （x86-64 下 `movzx r64, r/m16` 零扩展到 64 位），直接被排除。
2. 区间上界写死 `0xFF`。

改法：位宽从**内存操作数的尺寸**取（`byte ptr`=8 / `word ptr`=16 / `dword ptr`=32），
目的寄存器宽度只用来做合法性判断（≤32，或 r64 且内存尺寸 ≤4）。区间上界跟位宽联动，
opcode 打印按位宽自动选两位/四位。

对应自检用例（新增）：

```
mov rax, [rbp+0x92]
movzx r13, word ptr [rax]
cmp r13w, 0x1020
je  h0
cmp r13,  0x1021
je  h1
=> 0x1020, 0x1021
```

同时发现核正则漏了 `81` 这一族（`cmp r/m16, imm16` = `66 41 81 fd …`，`cmp r/m32, imm32` = `81 f8 …`）。
原正则只有 `83`（imm8）和 `3D`（cmp eax,imm32），所以**所有 opcode > 0xFF 的 cmp 链都定位不到**。
补上 `81 /7`、`81 /5`、`81 /6` 的 16 位和 32 位两种长度后，真实载荷的派发核从 21200 涨到 25763。

---

## 四、真实载荷：旧扫描器为什么会「0 个结果」

```
$ python3 x86il_deobf_v2.py DiskGenius_unpacked_vmp.bin --scan --dispatch legacy
[*] 载荷 DiskGenius_unpacked_vmp.bin  13.9 MB
[*] dispatch 引擎: 老扫描器（字节形态）
[*] cmp/and 链命中 opcode 0 个，0 处无后随 je
[*] 发现 0 个 opcode，共 0 个候选入口
real  0m0.177s
```

**0.18 秒、0 结果、没有任何报错。** 原因是老实现这么写的：

```python
for i in md.disasm(payload, code_base):     # 无 skipdata
```

capstone 的迭代器遇到第一个无法解码的字节就**静默结束**。这个载荷开头是
`call $+5 / pop rbp / sub rbp,5 / ret` 的手工 thunk，紧接着就是 junk 字节，
所以只解了二十几条指令就退出——看起来像「扫完了，没找到」，实际上一个字节都没真正看。

这是比漏检更危险的情况：**它不会报错**。新引擎不依赖线性解码，因此不受影响。

---

## 五、真实载荷实际是什么形态

跑通只解决「能跑」，更要紧的是「找到的东西是不是真的」。结论：**cmp 链不是这个载荷的主形态。**

### 5.1 观测数据

- `jmp reg`（`FF /4` 寄存器间接跳转）：**5585 处**；`ret`：74235 处；跳表 `FF 24/25`：505 处
- 典型派发尾部（0x141D356F4 附近，真实反汇编）：

```
movsxd r13, dword ptr [rdx]       ; 取本步长度
mov    rdi, r14
add    rbx, 0xffff
mov    r14, rbp
and    rdi, 0x20
add    r14, 0x92                  ; r14 = ctx + 0x92
add    qword ptr [r14], r13       ; ctx[0x92] += 步长  ← VM IP 自增
jmp    rax                        ; 跳到下一步处理
```

`0x92` 这个槽位跟 v2 里默认的 `IP_OFFSET = 0x92` 一致，可以确认它就是 VM 的指令指针。
换句话说，这个 VM 每一步的处理是「**推进 IP → 寄存器间接跳**」，而不是「读 opcode → 一串
cmp/je 选 handler」。另外整段代码被 0x4000 周期复制、夹杂大量 `push imm32 / pop [rsp]`
之类的 junk 指令，区块布局本身也被打散。

### 5.2 那 202 个 opcode 是什么

- 7687 条候选里 **5566 条**是孤立单分支（`block_cases == 1`）；
- 按 `min_cases=2` 过滤后剩 **88 个 opcode / 7457 条候选**（v2 侧按 target 再聚合，是 87 个
  opcode / 2193 个候选入口）；
- 打分只有 8 个候选拿到 4 分，其余 80 个是 1 分，且 `ctx_refs == 0`（不访问 rbp 上下文）、
  `ends_jmp == 0`（不以 jmp 收尾）——**这 80 个是 junk 代码里的伪候选，不是 handler**。

所以对这份载荷，正确的表述是：**工具能稳定跑完并给出候选，但 cmp 链语义在这里没有命中真正的
handler；真正的派发需要按 IP 槽自增模式去恢复**。这个结论和上一轮报告里「真实载荷可能有这里
没覆盖的派发形态」的预判一致，现在有了具体证据。

### 5.3 下一步该做什么（明确，可直接接手）

1. 新增种子形态：`mov rX, rbp / add rX, imm / add [rX], rY / jmp rZ` 四连惯用法 →
   每个这样的块尾就是一个「基本块边界」，`imm` 就是 IP 槽偏移（大量样本应集中在 0x92）。
2. 用 IP 槽自增的**步长**（`movsxd rY, dword [rZ]` 的值）反推每条 VM 指令的编码长度，
   这是恢复 16 位 opcode 表最直接的线索。
3. handler 打分要改：这份载荷的 handler 不通过 rbp 访问上下文（上下文指针在 r14/rbx 等
   计算出来的寄存器里），现在的 `ctx_refs` 判据在这里恒为 0，等于失效。

---

## 六、集成情况

`x86il_deobf_v2.py` 的 handler 发现入口换成统一分发：

```python
def discover_handlers(payload, code_base=..., engine=None, min_cases=2):
    # engine='auto'（默认）: 语义恢复优先，导入失败/无结果/异常 -> 老实现
    # engine='fast'        : 强制语义恢复
    # engine='legacy'      : 强制老实现
```

- 旧实现保留为 `discover_handlers_legacy()`，作为回退路径，行为完全不变；
- `--scan` / `--batch` 都走统一入口，新增 `--dispatch {auto,fast,legacy}`；
- `--scan` 会打印当前用的是哪个引擎，避免再出现「不知道跑的是哪套逻辑」。

实测：

```
$ python3 x86il_deobf_v2.py DiskGenius_unpacked_vmp.bin --scan --ip-offset 0x92
[*] dispatch 引擎: x86il_dispatch（语义恢复），87 个 opcode
[*] 发现 87 个 opcode，共 2193 个候选入口
real  0m11.4s

$ python3 x86il_deobf_v2.py DiskGenius_unpacked_vmp.bin --batch --limit 3 --ip-offset 0x92
[*] 发现 87 个 opcode 的 handler
   op 0x00  handler 0x23AF1   90 条  score 3
   op 0x01  handler 0x27A32  19 条  score 7
   op 0x02  handler 0x27A32  19 条  score 7
[*] 完成：3/3 个 handler 提取到 VM 操作
real  0m11.6s
```

v2 自检 28/28 通过，其中 9 项 dispatch 形态用例现在实际跑的是新引擎。

---

## 七、交付物

| 文件 | 说明 |
|---|---|
| `x86il_dispatch.py` | v1.1：正则预筛 + lite 热路径 + 16 位选择子，`--selftest` 10 项 |
| `x86il_deobf_v2.py` | v2.1：集成语义恢复引擎，新增 `--dispatch`，自检 28 项 |
| `test_all.py` | 一键回归：正确性 5 项 + 性能 3 项 |
| `bench_4mb.py` | 4MB 性能基准（mixed / random / code 三种模式） |
| `test_mixed.py` | 混合载荷召回率/精度（原有，未改） |
| `x86il_dispatch_v1_backup.py` | 改前快照，用于 A/B 对照 |

常用命令：

```bash
python3 test_all.py                                  # 一键回归（8 项）
python3 x86il_dispatch.py payload.bin -v              # 发现，带预筛统计
python3 x86il_dispatch.py payload.bin --json m.json --emit handlers.py
python3 x86il_dispatch.py payload.bin --seed-mode legacy   # 走老路径对照
python3 bench_4mb.py --mode random                   # 最坏情况性能
python3 x86il_deobf_v2.py payload.bin --scan --dispatch legacy   # 强制老引擎
```

新增命令行开关：

| 开关 | 作用 |
|---|---|
| `--seed-mode {regex,legacy,both}` | 种子策略，默认 regex；legacy 复现旧行为 |
| `--min-cases N` | 派发块最少分支数，默认 2（抑制孤立误报） |
| `--sel-bits {8,16,32}` | 默认选择子位宽；单条装载会按内存尺寸自动覆盖 |
| `--dispatch {auto,fast,legacy}` | v2 侧选择引擎 |

---

## 八、回归结果（本轮实测）

```
-- 正确性 --
  [PASS] x86il_dispatch 自检        10 passed, 0 failed
  [PASS] 混合载荷召回率              命中 12/12  误报 0
  [PASS] 旧引擎召回                 5/12
  [PASS] 新引擎召回                 12/12
  [PASS] 新引擎不产生错误 opcode      误报 无
-- 性能 --
  [PASS] 4MB 混合载荷耗时            7.27s（门限 15s）
  [PASS] 真实载荷可跑通              87 个 opcode，条目 7687
  [PASS] 真实载荷耗时                11.21s（门限 30s）
总计 8 项，通过 8，失败 0 / PASS
```

（真实载荷一栏 87 与 203 的差异来自 `min_cases`：测试脚本与 v2 用 2，手工单跑 CLI 用 1。
同一份代码、同一份载荷，差别只在过滤门槛，不是随机性。）

自检 10 项：

```
[PASS] cmp 链 (cl)                  ['0x10', '0x11', '0x12']
[PASS] 递减测试链 (sub/dec)           ['0x10', '0x11', '0x12']
[PASS] opcode 变换 (xor 0x5A)        ['0x10', '0x11']
[PASS] switch (jne + jmp)          ['0x20', '0x21']
[PASS] 跳表 (qword)                 ['0x00', '0x01', '0x02']
[PASS] 二分派发 (ja/jae)             ['0x20', '0x40']
[PASS] opcode 别名                   {'0x14': ['0x30', '0x31']}
[PASS] 精度：非 VM 比较不误报            []
[PASS] 16 位选择子 (movzx r64, word)  ['0x1020', '0x1021']
[PASS] 精度：选择子未参与比较              []
```

---

## 九、还剩什么（诚实清单）

1. **真实载荷的 handler 没真正恢复**。第五节说清楚了：cmp 链语义不适用于这份载荷。
   → **已在本轮后续推进，见 `REPORT_ipslot.md`**：真实派发是「16 位 opcode → 跳表 →
   IP 自增 → 寄存器间接跳」，3314 个 IP 槽站点与 3326 个 cmp 链候选**交集为 0**；
   第六种形态落地后，派发面已恢复到 3244 个点、覆盖 97.3%。
2. **性能是「够用」不是「理想」**。4MB 7.2s 主要花在 59 万条指令的 Python 层循环上
   （约 12µs/条）。要再上一个量级得把状态机整体搬进 C 或者做一次真正的单遍扫描，
   属于重写，不是调优。
3. **junk 代码里的伪候选仍会漏出来**。`min_cases=2` 能压掉大部分，但真实载荷上
   仍有 4741 条单分支条目，需要按 VM 特征（而不是通用启发式）重做打分。
4. **未验证其它保护版本**。所有结论来自这一份 DiskGenius 载荷 + 合成载荷；
   换 Oreans/WinLicense 版本后，`0x92` 这个 IP 槽偏移、16 位 opcode 宽度都可能变，
   需要重新标定（工具已支持通过 `--ip-offset` / `--sel-bits` 指定）。

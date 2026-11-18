# handler 发现（dispatch 恢复）进展报告

日期：本轮
状态：**核心完成、验证通过、性能未达标、尚未集成进 v2**

---

## 一、做了什么

新增 `x86il_dispatch.py`（约 780 行），把「靠固定字节模式找 handler」换成
**语义恢复**：它模拟 dispatch 代码本身在做什么，而不是猜它长什么样。

覆盖五种派发形态：

| 形态 | 代码特征 | 处理方式 |
|---|---|---|
| cmp 链 | `cmp al,0x2C; je h` 重复 | 逐条取立即数作 opcode |
| 递减测试链 | `sub eax,0x10; jz h; dec eax; jz h`… | 累积偏移量推 opcode |
| opcode 变换 | `xor edx,0x5A; cmp dl,0x6A; je h` | 逆变换还原真 opcode |
| 二分派发 | `cmp al,0x81; jae …; cmp al,0x40; jae …` | 区间状态传播 |
| 跳表 | `jmp qword ptr [rsi*8+table]` | 读表项、反算目标 |

关键设计：

1. **选择子跟踪**：自动识别 opcode 是从哪里读的（`movzx r12d, byte [rax]`、
   `movzx ecx, byte [rax+1]` 等），不再假设固定寄存器
2. **区间状态**：二分派发靠维护 `[lo,hi]` 区间，`jae` 切分后两侧分别继续，
   收敛到单值时该值即 opcode
3. **变换可逆性判断**：`xor` 可逆（`enc ^ K` → 还原），`and` 不可逆（原值不唯一），
   后者被标为「opcode 未确定」而不是瞎猜
4. **switch 形态**：`cmp al,X; jne next; jmp handler` 也认
5. **候选打分**：看 handler 是否访问 VM 上下文（`[rbp+k]`）、是否以 `jmp` 收尾
6. **别名检测**：多个 opcode 指向同一 handler 时明确标注

---

## 二、验证结果

### 1. 单元自检（8 项，全过）

```
python3 x86il_dispatch.py --selftest
   [PASS] cmp 链 (cl)                    ['0x10', '0x11', '0x12']
   [PASS] 递减测试链 (sub/dec)              ['0x10', '0x11', '0x12']
   [PASS] opcode 变换 (xor 0x5A)          ['0x10', '0x11']
   [PASS] switch (jne + jmp)            ['0x20', '0x21']
   [PASS] 跳表 (qword)                    ['0x00', '0x01', '0x02']
   [PASS] 二分派发 (ja/jae)                ['0x20', '0x40']
   [PASS] opcode 别名                     {'0x14': ['0x30', '0x31']}
   [PASS] 精度：非 VM 比较不误报                []
```

### 2. 混合载荷（4 种派发器 + 12 handler + 1 个干扰函数）

```
期望 opcode : 0x10 0x11 0x12 0x13 0x20 0x21 0x22 0x30 0x31 0x40 0x41 0x42
新 dispatch : 12/12   召回率 100%   误报 0   耗时 0.016s
```

跳表被正确解析：`@0x400094 表 0x400178 8 字节/项 解析 3 项`。

### 3. 与旧扫描器对比（同一载荷）

| | 检出 | 备注 |
|---|---|---|
| v2 旧 `discover_handlers` | **5/12** | 且 `0x30/0x31` 被报成 **`0x6A/0x6B`** |
| 新 `x86il_dispatch` | **12/12** | opcode 全部正确 |

旧扫描器漏 `0x21 0x22 0x30 0x31 0x40 0x41 0x42`（7 个），
其中 `0x6A/0x6B` 是**错误 opcode**——它没还原 xor 变换。
错误的 opcode 值比漏检更危险：后续按它建的 VM 模型全是错的，且不会报错。

---

## 三、没做完的部分（明确说明）

### 1. 性能不达标 ❌

4MB 混合载荷（代码片段 + 随机数据交错）耗时 **59.3 秒**，太慢。
原因清楚：`linear_seed()` 在遇到无法反汇编的字节时逐字节回退（`off += 1`），
随机数据区里每一步都是 Python 层的 capstone 调用。

**修复方案已确定**：改成候选点正则预筛——
只对可能构成选择子装载的字节序列（`0f b6/b7/be/bf`、`8a/8b/63`、带 REX 前缀的
`0f 4x`）做精确定位，其余字节直接跳过。预计能到秒级。

**未验证**：优化后能否在真实 14MB `.vmp` 载荷上保持可接受的耗时和准确率。

### 2. 未集成进 v2 ❌

`x86il_deobf_v2.py` 的 `--scan` / `--batch` 目前仍用旧实现。
计划是把 `x86il_dispatch.discover_handlers_compat()` 作为首选、
旧实现作为导入失败时的回退。

### 3. 未在真实载荷上验证 ❌

手上没有 DiskGenius 的 `.vmp` 解压载荷，全部结论来自合成载荷。
真实载荷可能有这里没覆盖的派发形态（例如 PIC 跳表的
`movsxd rax,[rdx+rdi*4]; add rax,rdx; jmp rax`，目前只记为「未解析」）。

---

## 四、交付物

| 文件 | 说明 |
|---|---|
| `x86il_dispatch.py` | handler 发现工具，含 `--selftest` |
| `test_mixed.py` | 混合载荷召回率/精度测试（可复现上面的数字） |
| `payload_mixed.bin` | 测试载荷 |

用法：

```bash
python3 x86il_dispatch.py --selftest              # 自检
python3 x86il_dispatch.py payload.bin -v          # 发现，带跳表细节
python3 x86il_dispatch.py payload.bin --json map.json --emit handlers.py
python3 x86il_dispatch.py payload.bin --code-base 0x141D34000
```

小载荷上可以放心用；大载荷建议先加 `--max-insn` 限制跑个采样。

---

## 五、结论

**算法层面已经做完了**：五种派发形态全部能恢复，合成载荷 12/12 零误报，
并且证明了旧实现会给出错误 opcode（不是漏检，是报错值）。

**工程层面还差两步**：性能优化（有明确方案）、与 v2 集成。
这两步不影响正确性，但决定它能不能在 14MB 的真实载荷上跑起来。

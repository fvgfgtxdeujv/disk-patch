# opcode 指令布局提取（从运行期镜像，纯静态）

日期：2026-11-19　工具：`tools_local/vm/opsem3.py`　数据：`tools_local/vm/layouts_compact.json`

目标：把 661 项派发表覆盖的每个 opcode 的**指令包布局**（读 packet 的哪些字段、rel 在哪）
从运行期解密镜像里自动解出来，为线性反编译授权函数铺路。

---

## 1. 表项是多一层 trampoline（新发现）

上一轮把表项直接当 handler 反汇编，只能看到一条 `jmp rel32`。实际结构是：

```
table[i] → jmp rel32 → 真 handler 主体（多态生成，每个唯一）
```

`opsem3.resolve()` 会跟 `e9 rel32 / eb rel8 / ff25 rip` 三种跳板，最多 12 层。

| 表 | 项数 | 表项均落在 .vmp | 跟完跳板后的唯一主体 |
|---|---|---|---|
| `0x1421080ab` | 661 | 661 / 661 | 661 |
| `0x141da2b42` | 49 | 49 / 49 | 49 |
| `0x141d8df04` | 1096 | 1096 / 1096 | 1096 |

合计 **1806 个唯一 handler 主体**，两两之间没有字节级重复（多态展开，没法靠聚类收缩）。
所以语义只能逐个提，不能靠模板批量套。

## 2. ctx 布局（代码级确认）

handler 里 `rbp` 就是 VM context 指针，实测访问到的槽：

| 槽 | 语义 | 证据 |
|---|---|---|
| `+0xBC` | **VM 的 IP 指针**（qword） | 所有 handler 都 `mov rX,rbp; add rX,0xbc; mov rX,[rX]` 再按偏移取 packet |
| `+0xF5` | **派发表基址** | 派发尾 `mov r13,[rbp+0xf5]; mov r10,[r13+op*8]; jmp r10` |
| `+0x6D` | 解密密钥（dword） | 参与 op 字段的 xor |
| `+0x178` | 累加器（dword） | `xor/sub/add` 链，用于把 op 混淆成算术式 |
| `+0xA4 / +0x119 / +0x11B / +0x121 / +0x13B / +0x13F` | 5 组变异累加器 | 每个 handler 都在搅 |
| `+0x8` | 派发结果缓存 | 派发器把 `[table+op*8]` 存进去 |

另外 op 297 的 handler 访问到 `+0x7A54 / +0x7A56`，说明 **ctx 至少 0x7A58 字节**，
比之前按 0x200 建模大得多 —— unicorn 沙箱要按 0x8000 映射。

## 3. 派发尾的通用形态（661 个里 649 个一致）

```
op   = u16 @ [IP + op_off]
rX   = [table + op*8]
IP  += i32 @ [IP + rel_off]          ← 注意是「加在 IP 上」，不是加在 IP+rel_off 上
jmp  rX
```

`rel` 字段位置 **每个 opcode 不同**，实测分布：

| rel 偏移 | op 个数 |
|---|---|
| +2 | 129 |
| +0 | 118 |
| +4 | 101 |
| +6 | 82 |
| +7 | 45 |
| +5 | 43 |
| 其它 | 131 |
| **解不出** | 12 |

## 4. 字段布局（packet 结构）

按「handler 读 packet 的哪些字节」统计，出现最多的五种：

```
u16@0  u32@2  u16@6  u16@8     ×53
u16@0  u16@2  u16@4  u32@6     ×42
u16@0  u16@2  u32@4  u16@8     ×39
u32@0  u16@4  u16@6  u16@8     ×28
u16@0  u32@2  u16@6            ×16
```

即：**op 字段恒在 packet 头部（u16），rel 是 i32，其余是操作数**（槽号 u16 / 立即数 u32 混排）。

## 5. 验证（真实轨迹，可复现）

拿 `reports/vm_trace.json` 里 2513 条真实派发记录，用布局表反算 `next_ip = ip + i32@(ip+rel_off)`：

```
自洽（u16@ip == tag）且 rel 算中：6 / 6
```

样本少是因为**取指瞬间字节已回写密文**（2513 条里只有 6 条 IP 处还是明文），
不是布局错。其中 5 条是派发器 `op=547`：

```
ip=0x1422bb76a rel@+2 rel=-8153  next=0x1422b9791  ✓
ip=0x1422b942f rel@+2 rel=+3054  next=0x1422ba01d  ✓
ip=0x1422b8ca8 rel@+2 rel=+13594 next=0x1422bc1c2  ✓
ip=0x1422fa2a5 rel@+2 rel=+2008  next=0x1422faa7d  ✓
ip=0x1422dcf9c rel@+2 rel=+272   next=0x1422dd0ac  ✓
```

`op=547` 的 `rel@+2` 与 v24 报告里反汇编派发器的结论一致，且 5/5 命中。

**存疑项**：`op=407` 解出 `rel@+0`，唯一一条明文样本里 `u32@0` 恰好等于 opcode 本身（407），
`dip` 也等于 407 —— 巧合还是真布局，需要更多明文样本才能定。
这条已标进 `layouts_compact.json` 的 `rel` 字段，用的时候要留意。

## 6. unicorn 差分沙箱（已跑通，但还不能判语义）

`tools_local/vm/lift.py`：把 ctx 每槽预置成可区分哨兵 → 跑 handler 到派发出口 → 看哪些槽被写、
写入值对哪些输入槽敏感，从而反推「add / xor / mov / 栈操作」。

实测结论：

* 沙箱能进 handler、能走到 `call <native helper>`（op 424 会调 `0x141f23d3b`），
* 但**大部分 handler 会把 ctx 里某个槽当指针解引用**，哨兵值一解引用就 `UC_ERR_READ_UNMAPPED`。
* 所以差分必须是「**真实 ctx 快照 + 单槽扰动**」，不能凭空造 ctx。
  下一步要用动态抓到的真实 ctx（v22 的 192 字节记录桩已在存 `rbp`/`[rbp+0xBC]`/`[rbp+0xF5]`，
  扩到整块 ctx 即可）。

## 7. 现在的进度

| 项 | 状态 |
|---|---|
| 派发表 → 真 handler 映射 | ✅ 661 + 49 + 1096，去跳板完成 |
| ctx 布局（IP / 表基址 / 累加器） | ✅ 代码级确认 |
| 每个 opcode 的 packet 字段布局 | ✅ 649/661 自动解出 |
| rel 字段偏移 | ✅ 649/661，547 已用真实轨迹验证 |
| handler 语义（每个 op 干什么） | ⬜ 缺真实 ctx 快照，沙箱已就位 |
| 授权函数的线性反编译 | ⬜ 依赖上一条 |

## 8. 复现

```bash
# 需要运行期镜像（本机 Wine dump，见 tools_local/dyn/dump_image.py）
python3 tools_local/vm/extract_handlers.py     # 表 → 跳板 → handler 清单
python3 tools_local/vm/opsem3.py               # 661 个 op 的布局 → layouts.json
python3 tools_local/vm/opsem3.py 424 407 547   # 单看几个
python3 tools_local/vm/lift.py 424             # unicorn 差分沙箱
```

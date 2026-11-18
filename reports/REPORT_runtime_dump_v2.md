# 运行期抓表实测（2026-11-18，GitHub Actions windows-2025）

这一份记录的是**在真实 GitHub Actions runner 上跑通的过程和实测数据**，
不是设计推演。跑的就是仓库里现在这份 workflow。

---

## 一、这次修掉的坑（都是实测踩出来的）

| # | 现象 | 根因 | 修法 |
|---|---|---|---|
| 1 | 第一步 `local_selftest.py` 直接 exit 1 | runner 控制台默认 **cp1252**，脚本里中文 `print` 抛 `UnicodeEncodeError: 'charmap' codec ...` | workflow 全局 `PYTHONUTF8=1` / `PYTHONIOENCODING=utf-8`，脚本入口再 `reconfigure(encoding='utf-8')` 兜一层 |
| 2 | API 触发的 run 参数是空的 | `workflow_dispatch` 用 API 触发时 `github.event.inputs.*` 返回**空串**，不会回落到 `default` | 加一步 `数值输入兜底` 显式给 `pkg_tag/seconds/min_score` 兜底 |
| 3 | `diskgenius.exe` 起不来（740） | exe 清单里是 `requestedExecutionLevel level="requireAdministrator"`，直接 `CreateProcess` 被拒 | 改走 `ShellExecuteExW(verb='runas')`，用 `SEE_MASK_NOCLOSEPROCESS` 拿 pid |
| 4 | 枚举内存区域恒为空 | `VirtualQueryEx(addr=0)` 直接返回 0，循环一次都没进 | 从 `0x10000` 起枚举，并跳过 `PAGE_GUARD` / `PAGE_NOACCESS` |
| 5 | `NameError: code_lo` | `open_process` 抛异常时 `code_lo` 还没赋值，后面无条件用 | 循环外先初始化为 `None` |
| 6 | 模块名打印成乱码 | `MODULEENTRY32` 字段宽度/对齐不对，靠"第一个 PE 头"猜主模块 | 改用 Toolhelp 快照按 exe 名匹配，`SizeOfImage` 仍从 PE 头解析 |
| 7 | 扫不到就什么也不剩 | 只有在线扫一条路，进程一退证据全没 | 在线扫不到就把可读内存落成 `memimage` 容器，离线用**同一套** `scan_buffer` 再扫一遍 |
| 8 | job 绿着但没产物 | `continue-on-error` + `hashFiles` 只在上传步骤用 | 没拿到 `tables.json` 时单独一步 `throw`，不让 job 假绿 |

---

## 二、真实目标实测数据（DiskGenius 6.2.0.1829 x64）

```
镜像基址   0x140000000      SizeOfImage 0x2FF3000
.vmp       RVA 0x19D4000    VSize 0xDAC000   Raw 0x0   ← 磁盘上没有，运行时才解密
.boot      RVA 0x2780000    VSize 0x872000
可读内存   约 300–320 MB / 506–508 个区域
```

### 结论 1：`.vmp` 在运行期确实解密了

从 300MB 内存镜像里切出 `.vmp`（14,336,000 字节，正好等于 VSize），
熵 5.3–5.7，能线性反汇编（`skipdata` 下有效率 98%），开头就是一串
`E9 xx xx xx xx` 跳板。**所以"读内存拿解密后的段"这条路本身是通的。**

### 结论 2：内存里没有「明文表项 + 上下文槽位」那种结构

把 300MB 全扫了一遍，按 `ctx+0x4 / 0x8 / 0xF5 / 0x110 / 0x1F4`
找「表指针 + 表项全落在代码段」的结构：**0 个命中**。

补充验证（都在镜像上做过）：

| 检查 | 结果 |
|---|---|
| 全镜像指向 `.vmp` 的 qword | 864 个，最长连续段 51 |
| 指向 `.vmp` 的 dword（32 位 RVA 形态） | 命中数 = 随机基线的量级，不是表 |
| 表项按 `xor 0x7F5EF28E` 还原来试 | 最长连续段 1 |
| 按 `xor 0x7F5EF28E` / `sub 0x4E7C4707` 组合还原 | 最长连续段 1 |
| 搜「指向某候选表起始地址」的指针（容忍基址前移 0..16 项） | 0 个 |

派发代码里能看到 `xor rdi, 0x7F5EF28E`、`sub rcx, 0x4E7C4707`、
`sub rcx, qword ptr [rbp+0xF2]` 这类变换 —— **表项不是明文绝对地址**，
这和 README 里"运行期抓明文表"的前提不一致，是这一版最关键的偏差。

### 结论 3：能抓到的是「整段指向 `.vmp` 的指针数组」

在保护器数据段（RVA 0x62F000 起）里有一批数组，**每一项都指向 `.vmp`，
乱序、互不重复、跨度大**，而且没有任何地方以指针形式引用它们
（说明是 `lea rip+` 静态寻址）。这正是派发表该有的样子：

| 表地址 | 项数 |
|---|---|
| 0x140630220 | 51 |
| 0x140630978 | 46 |
| 0x140630100 | 35 |
| 0x14062F3D0 | 29 |
| …共 32 张 | 合计 593 项 |

每一项的落点都以 `E9`（`jmp rel32`）开头 —— 是跳板而不是 handler 本体，
和 VM 派发的形态一致。**但目前只能证明"这是一批指向 VM 代码段的指针数组"，
还不能证明"下标 = opcode"**，所以产物里单独标了 `mode=arrays`。

---

## 三、产物长什么样

`tables.json`

```json
{
  "mode": "arrays",
  "source": "memimage",
  "module_base": "0x140000000",
  "vmp_rva": "0x19D4000",
  "tables": {
    "arr_0x140630220": { "table_va": "0x140630220", "entries": [ ... 51 项 ... ] }
  }
}
```

* `mode=ctx` —— 找到了带槽位的 VM 上下文，`tables` 的键是 `0x8 / 0xF5` 这种槽位，
  按 index 合并成一个 opcode 空间（原来的行为）。
* `mode=arrays` —— 没找到上下文，抓的是上面那种指针数组；`handlers.py` 里
  **只把最大一张当 `HANDLERS`**，其余全部单列进 `TABLES`，不做跨表合并
  （跨表合并会互相打架，实测有 46 个 opcode 冲突）。

---

## 四、下一步该怎么走（按性价比排）

1. **确认 `arrays` 的下标语义**：拿 `x86il_dispatch.py` 在运行时 `.vmp` 上定位
   `mov rD,[tbl+idx*8]; jmp rD` 的具体指令，看 `idx` 是 `and 0xffff` 还是更小的位宽，
   以及 `tbl` 是 `lea rip+` 还是从上下文取 —— 这一步能直接判定 32 张数组里哪张是 opcode 表。
2. **按已知常量反推编码**：派发路径上出现了 `xor 0x7F5EF28E`、`sub 0x4E7C4707`
   和 `[rbp+0xF2]` 这种运行时值，说明可能是"表项 XOR 常量再减上下文值"的两级编码，
   抓运行期 `rbp` 就能解。
3. **抓 rbp**：VM 上下文基址就是 `rbp`（派发代码里大量 `mov rax, rbp; add rax, 0xNN`）。
   在 `nuclei` 式的外部读内存拿不到寄存器，需要一次轻量异常断点或
   `.pdata` 回溯，属于下一步工程。

# disk-patch

DiskGenius VM（Oreans WinLicense / Themida 系）派发结构恢复工具链 + GitHub Actions 抓表方案。

一句话：**静态 dump 里还原了派发结构，但 handler 表在运行期才存在，所以用 Actions 的 Windows runner 跑起来读内存。**

---

## 目录

```
.github/workflows/dump-vm-tables.yml   Windows runner：跑 DiskGenius -> 读内存 -> 抓 handler 表
winactions/
  dump_ctx.py        起进程 / 附加，扫 VM 上下文，dump 表
  local_selftest.py  扫描算法自检（跨平台，合成内存镜像）
  merge_tables.py    tables.json -> handlers.py（含运行期->dump 坐标换算）
  README.md          这套方案怎么用、有哪些坑
vendor/
  DGEng6201829_x64.zip  DiskGenius 6.2.0.1829 绿色版 x64（原版加壳，SHA256 见 pin.txt）
  pin.txt             文件名 / URL / SHA256 / 版本说明
  fetch_vendor.sh|ps1 重新拉取并校验
tools/
  x86il_dispatch.py   派发恢复：6 种形态（cmp 链 / 递减链 / xor 变换 / 二分 / 跳表 / mov+jmp 表）
  x86il_deobf_v2.py   VM handler 语义提升（z3）
  ipslot.py           IP 槽恢复：找「add [ctx+slot],len; jmp reg」
  tableresolve.py     表指针槽位定位 + 生成 Frida/x64dbg dump 脚本
  test_all.py         一键回归（16 项）
  bench_4mb.py        4MB 性能基准
  test_mixed.py       混合载荷召回率
reports/
  REPORT_dispatch.md      v1：五种形态语义恢复
  REPORT_dispatch_v2.md   v1.1：性能 11x、集成进 v2、真实载荷首测
  REPORT_ipslot.md        IP 槽：3314 个派发点、槽 0x18/0x92/0x120
  REPORT_runtime_dump.md  表指针槽 0x4/0x8/0xF5 + 坐标系换算
```

---

## 结论摘要（都是实测）

| 项 | 数字 |
|---|---|
| 真实载荷 | 13.9 MB，代码基址 `0x141D34000`（dump 坐标系） |
| 派发形态 | 16 位 opcode，`and 0xffff` → `shl 3` → `add table` → `mov reg,[..]` → `jmp reg` |
| IP 槽站点 | 3314 个，槽 `0x18 / 0x92 / 0x120`（按地址段分化） |
| cmp 链候选与 IP 站点交集 | **0**（cmp 链在这份载荷上没用） |
| 第六形态派发点 | 3244 个，覆盖 IP 站点 **97.3%** |
| 表指针槽 | `ctx+0x4 / 0x8 / 0xF5`，占 88% |
| 性能 | 4MB 混合 81.7s → **7.2s**；14MB 真实 **11.8s** |

**关键坑**：dump 的 `.vmp` 起点记的是 `0x1D34000`，而 6.2.0.1829 的 PE 里 `.vmp` 在
`0x19D4000`（`RawSize=0`，运行时才解密）。差 `0x360000`。运行期抓到的 handler 必须
换算回 dump 坐标系，`merge_tables.py` 已自动处理。

---

## 跑 Actions

1. Actions → **dump-vm-tables** → Run workflow
2. 安装包三级回退：`vendor/*.zip` → Actions cache → 官网
3. 产物 artifact `vm-tables`：`tables.json` / `handlers.py` / `dump.log` / `dg.dmp`

本地合并：

```bash
python winactions/merge_tables.py tables.json --out handlers.py --json handlers.json
```

---

## 本地跑分析工具

```bash
cd tools
python3 x86il_dispatch.py --selftest          # 12 项
python3 test_all.py --skip-real               # 无真实载荷时
python3 ipslot.py <payload.bin> --json ipslots.json
python3 tableresolve.py <payload.bin> --ipslots ipslots.json
```

真实载荷（`DiskGenius_unpacked_vmp.bin`，14MB）没有入库，`test_all.py` 会跳过依赖它的用例。

---

## 状态

- 静态分析部分：回归 16 项全过
- Actions 方案：脚本、workflow、算法自测都验证过，**但没在真实 GitHub Actions 上跑过**

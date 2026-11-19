# disk-patch

DiskGenius VM（Oreans WinLicense / Themida 系）派发结构恢复工具链 + GitHub Actions 抓表方案。

一句话：**静态 dump 里还原了派发结构，但 handler 表在运行期才存在，所以用 Actions 的 Windows runner 跑起来读内存。**

---

## 目录

```
.github/workflows/dump-vm-tables.yml   Windows runner：跑 DiskGenius -> 读内存 -> 抓 handler 表
winactions/
  dump_ctx.py        起进程 / 附加（自动提权），扫 VM 上下文，dump 表
  memimage.py        进程内存镜像容器 + 离线扫描（在线扫不到时的兜底）
  local_selftest.py  自检（跨平台：扫描算法 / 镜像往返 / 静态数组策略）
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
  REPORT_runtime_dump_v2.md  运行期实测：真机 Actions 跑通记录 + 表项非明文的证据
  REPORT_dispatch.md      v1：五种形态语义恢复
  REPORT_dispatch_v2.md   v1.1：性能 11x、集成进 v2、真实载荷首测
  REPORT_ipslot.md        IP 槽：3314 个派发点、槽 0x18/0x92/0x120
  REPORT_runtime_dump.md  表指针槽 0x4/0x8/0xF5 + 坐标系换算
  REPORT_wine_auth_dynamic.md    Wine 下授权校验的行为实证（纯本地 / key 触发 / 删除出口）
  REPORT_vmp_probe_20261119.md   VM 指令级探针：改派发表 + 记录桩 + 影子表回跳（本机跑通）
  REPORT_opcode_layout_20261119.md  opcode 指令布局：跳板层 / ctx 布局 / 661 个 op 的 packet 字段与 rel 偏移
tools_local/dyn/     运行期动态取证脚本（镜像 dump / 断点回溯 / key 契约二分 / VM 桩）
tools_local/vm/      opcode 布局提取（表→跳板→handler / 字段与 rel 偏移 / unicorn 差分沙箱）
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
- 运行期动态（本机 Wine 9.0 + Xvfb）：授权校验行为实证完成；VM 派发表插桩成立
- VM 结构：1806 个唯一 handler（跳板层已解）、ctx 布局已确认、661 个 op 的 packet 布局解出 650；
  **handler 语义与授权函数反编译仍未完成**（缺真实 ctx 快照做差分）
- Actions 方案：**已在真实 GitHub Actions（windows-2025）上跑通**，job 绿，产物 `vm-tables` 有内容
  - 目标启动、提权、PE 段表解析、`.vmp` 定位、内存镜像落盘全部正常
  - 目前拿到的是 `mode=arrays`：32 张「整段指向 `.vmp`」的指针数组，合计 593 项
  - **没拿到**「表项是明文绝对地址 + 上下文槽位」那种结构（全盘扫 0 命中），
    证据和下一步见 `reports/REPORT_runtime_dump_v2.md`

### 两种 mode

| mode | 含义 | handlers.py |
|---|---|---|
| `ctx` | 找到带 `0x4/0x8/0xF5` 槽位的 VM 上下文，表项是明文 VA | 多表按 index 合并成一个 opcode 空间 |
| `arrays` | 没找到上下文，抓到的是「整段指向 VM 代码区」的指针数组 | 只取最大一张当 `HANDLERS`，其余单列进 `TABLES`（跨表合并会互相打架） |

---

## 授权层（pyauth/）

`pyauth/` 是基于 6.2.0.1829 实测还原的授权层 Python 实现：授权记录结构、Options.ini
（UTF-16/BOM，`[LicenseInfo]` 段）、注册表 `HKCU\Software\Eassos\DiskGenius\Reg\license`、
状态/注册请求串（逐字节对齐运行期实测）、`mid` 编解码、授权门判定模型。

```bash
python -m pyauth.selftest        # 9 组断言，全部字节级
python -m pyauth query           # 打印实测请求串
python -m pyauth code QK7X-M2PV-ZLHD-W8CT-RBNQ
```

结论与证据见 `reports/REPORT_auth_python.md`：**本地只做"存 + 判有无"，签发在服务端**。

---

## 运行期动态实证（Wine，本机）

`tools_local/dyn/` 是不走 Actions 的本机取证线：Wine 里把加壳程序跑起来 → dump 运行期解密镜像 →
断点回溯 → 给 VM 派发表插桩。两份报告：

`reports/REPORT_wine_auth_dynamic.md` —— 授权行为：

- 校验**完全不联网**（全程跟踪系统调用，一次外网连接都没有），是纯本地判定
- 只有 `key` 字段触发校验；`user` 像人名 + `email` 带 `@` 同时满足才进校验分支，否则当没注册数据
- 校验失败 → 整个 `Options.ini` 被 unlink 掉；删除出口精确到 `0x14020b2d1`，打成空操作后配置文件保住
- 删文件那条调用链穿过 `0x14216xxxx` 字节码区 → 判定在 VM 里做
- 主程序没有任何系统验签 API 导入（crypt32 只导了个读证书名的）→ 验签自实现或壳内
- `license` 值长度 1–344 全进校验、不挑长度 → 不像定长 RSA 签名块

`reports/REPORT_vmp_probe_20261119.md` —— VM 探针：

- 三张派发表在运行期都是绝对 VA，`v[2k+1]=v[2k]+5` 规律成立
- 661 项那张表改了就 3 秒退出 → 表在热路径上；49 / 1096 两张被非派发路径引用，钩即死
- int3 填充洞不可用（PE 异常分发吃掉 SIGTRAP）→ 改走「记录桩 + 影子表回跳」，桩在 `.vmp` 零洞里
- 桩进热路径成功，拿到 `IP 0x142160496  bytes ec26000031011200`，地址落在 `0x14216xxxx`
- **但这只 1 条、且字节判读可疑**，`[rbp+0xBC]` 是否真是 VM IP 待证伪，见报告 §5.3 / §7

---

## 状态一览

- 静态分析部分：回归 16 项全过
- 运行期动态（本机 Wine）：授权行为实证完成；VM 派发表插桩成立，**字节码序列尚未拿到**

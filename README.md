# disk-patch

DiskGenius 6.2.0.1829 x64 的两条逆向线：

1. **VM 派发结构恢复**（Oreans WinLicense / Themida 系）：静态还原派发形态 + GitHub Actions 运行期抓 handler 表；
2. **授权协议取证**：请求/响应格式、离线注册容器、本地判定边界（VMP）、以及运行期网络实测。

> 仅用于互操作与安全研究记录；仓库不包含可用的授权绕过实现。

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
tools/                 VM 派发恢复与语义提升（详见下表）
tools_local/dyn/       运行期取证：镜像 dump / 断点回溯 / key 契约二分 / VM 桩
tools_local/vm/        opcode 布局提取（表→跳板→handler / 字段与 rel 偏移 / unicorn 差分沙箱）
tools_local/offline_probe/  离线注册抓包工具（mitm.py / fake_srv.py / winctl.c）
pyauth/                授权层 Python 实现（部分结论已被后续实测修正，见 §2.7）
out/                   本轮所有探针脚本与采样日志（_hk_* / _mem_diff / _hosts_mitm / _dg_dbg …）
reports/
  REPORT_dispatch.md / _v2.md       派发语义恢复（五种形态、性能）
  REPORT_ipslot.md                  IP 槽：3314 个派发点，槽 0x18/0x92/0x120
  REPORT_runtime_dump.md            表指针槽 0x4/0x8/0xF5 + 坐标系换算
  REPORT_runtime_dump_v2.md         真机 Actions 跑通记录 + 表项非明文证据
  REPORT_wine_auth_dynamic.md       Wine 下授权校验行为实证
  REPORT_vmp_probe_20261119.md      VM 指令级探针（记录桩 + 影子表回跳）
  REPORT_opcode_layout_20261119.md  opcode 布局 / ctx / 661 个 op 的 packet 字段
  REPORT_auth_python.md             pyauth 的字节级对齐记录（早期结论）
  REPORT_auth_offline.md            ★ 授权协议最终版：MD5/XOR、离线注册、HKLM 实测、
                                     VMP 反调试、差分内存、hosts MITM（§9–§14 为最新）
```

---

## 1. VM 派发结构（实测）

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

## 2. 授权协议（REPORT_auth_offline.md 的浓缩版）

### 2.1 结论

* **没有 RSA/ECC**，主程序没有 CryptoAPI/CNG 导入；自带一份标准 MD5（`0x1400d62fc`，
  块函数 `0x1400d623c`，K 常量 `0x1400d59e1`）。
* 请求是 **"MD5 摘要 + 固定 XOR 0x0E"** 的完整性信封：
  `check = MD5(payload)`、`encryption = XOR0x0E(payload + "&check=" + hex(check))`。
  该信封**无密钥**，任何人都能算 —— 它不是授权凭证的签名。
* 授权真值在服务端：客户端的 `key` 是不透明 blob，本地只做"存 + 交给 VMP"，
  不会自造、不会验签、失败时静默忽略。

### 2.2 在线注册请求

```
ver=<ver>&code=<regcode>&name=<user>&email=<email>&mid=<机器指纹>&applang=<lang>
&appname=DiskGenius
```
`mid` 由磁盘信息派生：`&diskinfo%ld=%s`、`%04X` 后逐字符 XOR 0x0E，再拼
`&otherinfo=%s&tmp=%s`。`otherinfo` 为空时走明文分支（不带 `check/encryption`）。

### 2.3 启动期真实请求（hosts 劫持 + 本地 TLS 抓到）

公共头：`User-Agent: Eassos Net App/1.2`、`Authorization: Basic`（空）、`Cache-Control: no-cache`。

```http
GET /share/getshareinfo.php?app=dg&ver=6.2.0.1829_x64_pro_chs&code=&shareinfo=N
Host: internal.eassos.com

GET /partitionguru/adbar/adconfig.php?ver=6%2e2%2e0%2e1829prochs
Host: www.eassos.com

POST /update/diskgenius/update.php          (Content-Length: 472)
Host: internal.eassos.com

ver=…&winver=…&winbits=64&reslang=eng&syslang=chs&cpu=64
&mid=<XOR0x0E + %XX>&lid=
&disk1=…&otherinfo=…&iplan=Y&appname=DiskGenius&appcs=328649950
```

* 三组不同 `license` key 下 body **逐字节一致**，`lid=` 始终为空。
* 启动阶段**没有** `register.php` 请求。

### 2.4 离线注册（OfflineReg.dat）

| 项 | 值 |
|---|---|
| 大小 | 固定 **2048** 字节 |
| 前 64 字节 | key |
| 其余 1984 字节 | `plain[j] ^ key[j % 64]` |
| 明文 +0x80 | 完整 URL（`https://internal.eassos.com/register/register.php?…&skey=…`） |

`OfflineReg.exe` 读 dat → host 原样取、**端口固定 443** → query 原样当 POST body →
响应必须以 `appname=DiskGenius` 开头 → 原文写入 `Options.ini`。

### 2.5 Options.ini 真实布局

UTF-16LE + BOM + CRLF，段名是 **`[license]`**（不是 `[LicenseInfo]`）：

```ini
[license]
appname = "DiskGenius"
user = ""
email = "license@eassos.com"
regcode = ""
regver = "6.2.0.1829_x64_pro_eng"
key = "<服务端响应原文，逐字节保存>"
```

### 2.6 安装态：判定入口与本地影响

* 安装态读的是 `HKLM\SOFTWARE\Eassos\DiskGenius\{Reg,CReg}`，`license` 为 REG_BINARY；
  exe 同目录 `Options.ini` 只在便携态生效。
* `key` 消费函数 `0x140199be0`：读取后只看**首字符**，只有 `0/1/2/9` 才
  `SendMessage(hwnd, 0x479, key[0], 0)` 交给 VMP 窗口过程。
* 9 组自造 blob（UTF-16/ASCII、0/1/2/9 开头、带完整 payload）实测：
  **全部静默忽略** —— 不回写、不清空、菜单不变。
* **差分内存**（同 key 噪声 60 页 vs. 换 key）：key 的全部本地影响只有
  `.vmp` 里 **1 个字节**（`0x141AD7F2D`：空 `AC`、`1TEST` `B0`、`aTEST` `A8`）。

### 2.7 响应处理（逐指令，§13）

| 接口 | 谁发 | 响应谁处理 | 是否 VMP |
|---|---|---|---|
| `update.php` | `CMainFrame::SendUpgradeInfo` `0x14019708c` | **无人处理（丢弃）** | 否 |
| `register.php` | 主程序只写进 `OfflineReg.dat` | `OfflineReg.exe` → `Options.ini [license] key` | 否 |
| `browserreg.php` | `ShellExecuteW` 打开浏览器 | 浏览器/服务端；主程序只模态等待 | 否 |

用合法形态响应（`appname=DiskGenius&license=SIG&…`）回给三条请求，`ShowLicense` /
`Improveplan` / `license` 均无变化 —— 与静态结论一致。

> `pyauth/` 里仍是早期假设（`[LicenseInfo]`、`HKCU`、`license` 值的几种候选 codec），
> 以上述 §2.5/§2.6 为准。

---

## 3. 运行期方法（可复现）

### 3.1 Wine（早期）

`tools_local/dyn/`：把加壳程序跑起来 → dump 解密镜像 → 断点回溯 → VM 派发表插桩。
Wine 下授权校验路径**未观察到外网连接**；校验失败会把整个 `Options.ini` unlink，
删除出口 `0x14020b2d1`，打空后文件保留。详见 `REPORT_wine_auth_dynamic.md`。

> 注意：这是 **Wine/便携态** 的行为；Windows 安装态在启动阶段固定有 3 条 443 连接
> （§2.3），但都与 key 无关。

### 3.2 VMP 反调试：调试器下代码不解密

`out/_dg_dbg.py`（ctypes Debug API、清 PEB 的 `BeingDebugged/NtGlobalFlag`、
等目标页解密后写 `0xCC`）实测失败：目标页在调试器下始终是磁盘上的密文
（`3faefff3…`），正常运行时是明文（`ff15c166…`）。软件断点在该进程不可用。

### 3.3 差分内存（替代方案）

`out/_mem_diff.py`：不附加调试器，启动后 12 s 整模块落盘（12275 页），
再按 4 KB 页与"同 key 重复运行"的噪声集合做差。用法：

```bash
python out/_mem_diff.py --seconds 12 --tag 1TEST --key 1TEST
```

### 3.4 hosts 劫持 + 本地 TLS（抓请求）

`out/_hosts_mitm.py`（管理员）：临时 CA → 装进本机根存储 → hosts 指向 127.0.0.1 →
443 起 Python TLS 服务 → 启动目标 → **结束后自动还原 hosts / 删除 CA / 还原注册表**。

```bash
python out/_hosts_mitm.py --key 1TEST --seconds 16
```

---

## 4. 常用命令

```bash
# Actions：dump-vm-tables -> Run workflow；产物 artifact vm-tables
python winactions/merge_tables.py tables.json --out handlers.py --json handlers.json

# 静态工具
cd tools
python3 x86il_dispatch.py --selftest
python3 test_all.py --skip-real
python3 ipslot.py <payload.bin> --json ipslots.json
python3 tableresolve.py <payload.bin> --ipslots ipslots.json

# 授权层（结论以 §2 为准）
python -m pyauth.selftest
python -m pyauth query
python -m pyauth code QK7X-M2PV-ZLHD-W8CT-RBNQ
```

文件体积注意：`vendor/*.zip`（40 MB）与 `out/memdump_*.bin`（每个 ~50 MB，仅本地保留）
不入库；`.gitignore` 已排除 `out/runtime/` 与本地实验私钥/证书。

---

## 5. 状态

**已完成**

- 静态派发：回归 16 项全过；第六形态覆盖 IP 站点 97.3%
- Actions：windows-2025 跑通，产物 `vm-tables`（`mode=arrays`，32 张表 / 593 项）
- 授权协议：请求格式、`check/encryption`、`skey`、离线 dat、Options.ini、注册表落点全部打通
- 网络实测：三条启动请求 + 响应被忽略的结论（静态 + 动态互证）
- 本地判定边界：key 只影响 `.vmp` 1 个字节；无本地验签

**未完成**

- VMP handler 语义（661 个 op 解出 650，语义提升未完成）
- 真实 ctx 快照下的授权函数差分（调试器被反调试阻断，需换方案）
- 服务端 `register.php` / `update.php` 的真实响应样本（需有效授权）

---

## 6. 合规

仓库内容为互操作/安全研究记录，包含对商业软件的静态与运行期分析。
不提供、也不接受用于规避授权的实现；如需使用 DiskGenius 功能请购买正版授权。

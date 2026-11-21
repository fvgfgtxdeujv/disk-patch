# 离线注册流量还原（OfflineReg.dat / 响应 / Options.ini 布局）

日期：2026-11-19　目标：DiskGenius 6.2.0.1829 x64 + 同版本 `OfflineReg.exe`
方法：本机 Wine 64 位前缀里跑真程序，用自建 MITM 代理抓完整 TLS 流量，再用自造 `OfflineReg.dat` 做差分实验。

---

## 0. 一句话结论

离线注册这条链**已经完整打通并可复现**：

```
DiskGenius --(Offline Register)--> OfflineReg.dat (2048B, 64B key + 循环 XOR)
OfflineReg.exe --(读 dat)--> 显示字段 --(POST https://<dat里的URL>:443)--> 服务器
服务器响应 --(必须以 appname=DiskGenius 打头)--> 写入 Options.ini 的 [license] 段
                key = "<响应原文，逐字节保存>"
```

`key` 就是服务端签名的载体；主程序启动时读 `Options.ini`，但**伪造的 key 被静默拒绝**
（不写 `HKCU\Software\Eassos\DiskGenius\Reg\license`）。所以：**签发在服务端，客户端只验签。**

---

## 1. OfflineReg.dat 的容器格式（实测，逐字节可复现）

| 项 | 值 | 证据 |
|---|---|---|
| 文件大小 | **固定 2048 字节**，读不满直接判失败 | `cmp DWORD PTR [ebp-0x434],0x800` @ 0x405b22 |
| 前 64 字节 | key | 解密循环读 `[eax+esi]`，`eax = idx & 0x3f` |
| 其余 1984 字节 | `plain[j] ^ key[j % 64]` | 0x405b32–0x405baf 的 4 路展开循环 |
| 明文 +0x80 | **完整 URL（含 query）** | `lea edx,[esi+0xc0]` 后 `wcsncmp(s,L"http:",5)` |

验证方式：`key` 全 0 时明文即原文，写 2048 字节零文件程序照读（显示 `n/a`），
写入 URL 后程序立刻按该 URL 发请求 —— 双向都成立。

Python：

```python
from pyauth import offline
dat = offline.encode_dat(offline.make_plain("https://host/path?query"))  # 2048B
plain = offline.decode_dat(dat)                                            # 1984B
offline.read_url(plain)                                                    # URL
```

---

## 2. HTTP 请求（MITM 实测抓到的原文）

明文里的 URL 被这样消费：

* host 原样取（**连端口都不拆**：`http://127.0.0.1:8899/reg` 会去连 host `127.0.0.1:8899`）
* port **固定 443**；`cmp si,0x1bb` → 是 443 才加 `WINHTTP_FLAG_SECURE`（0x800100），否则明文 HTTP
  （反汇编 0x40b4ee–0x40b500）
* path 取 URL 的 path
* **query 原样当 POST body**（实测 133 字节 query → Content-Length: 133，内容一字不差）

抓到的真实报文：

```http
CONNECT test.example.com:443 HTTP/1.1
Content-type: application/x-www-form-urlencoded
Authorization: Basic
User-Agent: Eassos Net App/1.0
Host: test.example.com
Connection: Keep-Alive
Pragma: no-cache
Cache-Control: no-cache

POST https://test.example.com:443/reg HTTP/1.1
Content-Length: 133

appname=DiskGenius&ver=6.2.0.1829_x64_pro_eng&code=QK7X-M2PV-ZLHD-W8CT-RBNQ&name=ZakaTest&email=zaka%40example.com&mid=ABCDEF&iplan=Y
```

注意 `Authorization: Basic` 是**空的**（没有凭据），说明鉴权不在这层。

---

## 3. 响应规则（爆破出来的，可判定）

| 规则 | 说明 |
|---|---|
| 开头必须是 `appname=DiskGenius` | 顺序错了就失败（`license=...&appname=...` 实测被拒） |
| 必须非空且能被读回 | 空响应 → 失败 |
| 含 `<html` 且含 `<title>301 Moved Permanently</title>` | 走重定向分支，从 `href=` 取新地址重试 |
| 其它情况 | 弹 `Sorry, registering failed. Please check the internet connection and try again.` |

实测通过的响应样本（能稳定生成 Options.ini）：

```
appname=DiskGenius&license=SIG&user=BOSS&email=boss@x.com
```

**注意**：响应里的 `user` / `email` **不会**进 Options.ini —— 那两个字段仍是默认值
（`""` 和 `license@eassos.com`）。响应被整体塞进 `key`。

---

## 4. Options.ini 的真实布局（这一条修正了旧报告）

旧报告写的段名是 `[LicenseInfo]` —— **错**。实测（UTF-16LE + BOM + CRLF）：

```ini
[license]
appname = "DiskGenius"
user = ""
email = "license@eassos.com"
regcode = ""
regver = "6.2.0.1829_x64_pro_eng"
key = "appname=DiskGenius&license=TEST123&user=ZakaTest&email=zaka@example.com"
```

* 段名是 **`[license]`**
* 字段顺序固定：appname / user / email / regcode / regver / key
* **`key` = 服务端响应原文，逐字节保存，不做任何编码**
* `regver` 来自 dat 请求串里的 `ver`
* `user` / `email` / `regcode` 是本地默认值，不从响应取

Python 生成的产物与真实文件 **逐字节一致**（418 字节全等，已写进自测）。

---

## 5. 主程序这一侧

| 观察 | 手段 | 结论 |
|---|---|---|
| 启动时 `CreateFileW(...\DiskGenius\Options.ini, GENERIC_READ)` | `WINEDEBUG=+file` | 它确实读 Options.ini |
| 读了但 `HKCU\...\DiskGenius` 下**什么都没写** | 启动前后 `reg query` 对比 | 伪造的假 key 被静默丢弃 |
| 手写 `Reg\license` = 假 key，也没有任何效果 | 写注册表后重启对比 | 同上 |

→ 客户端拿到 key 后要做验证，验不过就当没注册。验证逻辑在 VM 壳里（见其余报告）。

---

## 6. 复现步骤

```bash
# 1) 造 dat（key 全 0，明文就是你想让它发的 URL）
python3 -m pyauth offline-dat "https://your.host/reg?appname=DiskGenius&license=X" --out OfflineReg.dat

# 2) 把 OfflineReg.exe 和 OfflineReg.dat 放同一目录，Wine 里跑
WINEPREFIX=~/.wine64 wine OfflineReg.exe

# 3) 点 Register Now（这一步会真发 POST）。要抓报文就把 winhttp 指到自己的代理：
http_proxy=http://127.0.0.1:8888 https_proxy=http://127.0.0.1:8888 wine OfflineReg.exe

# 4) 用响应原文生成 Options.ini
python3 -m pyauth offline-ini "appname=DiskGenius&license=SIG&user=a&email=b@c" --out Options.ini
```

配套抓包/驱动小工具在 `tools_local/offline_probe/`：
`mitm.py`（自签证书 MITM，记录 CONNECT/请求体）、`winctl.c`（跨进程枚举/填表/点按钮，
绕开 X 焦点问题）、`fake_srv.py`（明文 HTTP 版）。

---

## 7. 未解决 / 下一步

1. **dat 里 user/email/regcode 的偏移还没定位**：扫了 0x00–0xA0 的单点、��了 32 字节步长的短串网格，
   OfflineReg 界面仍显示 `n/a`。说明它们不是明文的裸 CString（可能带长度前缀/结构体头，或在
   `+0x64` 那套 CString 之外的另一块）。不定位也不影响发包（URL 就能决定 body）。
2. **key 的签名算法**：见 §9。已确认客户端自带 **MD5**，注册负载用
   `ver=…&code=…&name=…&email=…&mid=…&applang=…` 作为 MD5 输入，摘要拼成 `&check=<hex>`，
   整串再按 UTF-16 逐字符 XOR `0x0E` 后塞进 `encryption=`；本地"读 key → 判定"的分支仍在
   VMP 字节码里（Wine 删除栈 0x142161e81 / 0x142166167），尚未语义还原。
3. 响应里是否还有其它必需字段（比如 `skey=` / `check=`）没被我们触发出来 —— 真服务器被拒时
   不会告诉我们缺哪个，只能靠 VM 里的验证逻辑反推。

---

## 8. 这次修掉的旧结论

| 旧 | 新 |
|---|---|
| Options.ini 段名 `[LicenseInfo]`，只有 `Show` 键 | 段名 `[license]`，6 个字段，`key` 存响应原文 |
| `license` 注册表值有三套候选 codec 需要试 | 不需要：`key` 明文保存，注册表值由主程序自己写 |
| 本地"只判有无授权" | 本地还要验签（读 Options.ini → 验不过就丢弃） |

---

## 9. 授权算法：MD5 + `check=` + XOR 0x0E（2026-11-21 静态定位）

### 9.1 方法：解密后主模块 dump

提权启动目标，`EnumProcessModulesEx` 找到 `DiskGenius.exe`，`GetModuleInformation`
取 `SizeOfImage`，逐页 `ReadProcessMemory` 落盘：

```
out/moddump_140000000.bin   0x140000000 + 0x2FF3000（~50 MB，12275 页）
```

结果 **全部页可读**；`Options.ini`(0x1406a1328)、`license`(0x1406b35f0)、
`appname`(0x1406b3660)、`regver`(0x1406b36a0) 均为明文，说明 12 s 时 .rdata 已完全解密。
原始 exe 文件里这些字符串 **一个都搜不到**（段名也被清零），所以此前静态扫不出来。

有了这份镜像，用 capstone 做 RIP-relative 交叉引用（按 ModRM `mod=00,rm=101` 向量化筛选，
再从候选位置回退 1–6 字节验证指令长度与 `mem.base==RIP`），函数边界用 `.pdata` 的
`RUNTIME_FUNCTION` 表。以下地址都是 VA（模块基址 0x140000000）。

### 9.2 授权字符串池与原生消费者

| 字符串 | 地址 | 引用点 / 函数 | 语义 |
|---|---|---|---|
| `Options.ini` | 0x1406a1328 | 0x140080b49 / 0x140080bbc | 拼配置路径 |
| `[license] email` | 0x1406b3680 | 0x140199ddb | 读 email（缺省 `license@eassos.com`） |
| `[license] key` | `key`@0x1406a8980 | 0x140199e00（`0x1402aeacc`） | 读 key 到栈上 0x1000 缓冲 |
| 六字段写入 | appname/user/email/regcode/regver | 0x1400d7699…0x1400d76e9 | 写 Options.ini 的 `[license]` |
| `VerifyDate` | 0x1406b35d8 | 0x1400d706e | 在线续期/日期校验 |
| `license`/`ShowLicense` | — | 0x1403291bc | 注册表 `SOFTWARE\Eassos\DiskGenius` 读写 |
| `&check=` | 0x1406b37b8 | 0x1400d806a | 注册负载摘要字段 |
| `offlineReg.dat` | — | 0x1400d88xx | 离线注册文件 |

`key` 的消费函数（0x140199be0–0x14019a25a）流程：

1. 读 `[license] email`、`[license] key`（`0x1402aeacc`，通用配置读取器）；
2. `0x1405a3260` 取长度后看 key 的**首字符**：只有 `'0'`、`'1'`、`'2'`、`'9'` 才走
   `call [0x140630538]`（槽值 `0x1420c7945` → `jmp 0x141e2c625`，.vmp 内）；
3. 再读注册表 `ShowLicense`，走 `0x1403291bc` 的注册表分支。

失败删除出口仍是 `0x14020b2a4`（`mov rax,[rcx]; call [rax+0x48]`），Wine 里 patch 掉
这条 call 就不再删 Options.ini。

### 9.3 注册负载格式（代码级，决定性）

函数 `0x1400d7c88–0x1400d8165` 先把注册字段格式化成一段字符串（0x1400d7e38，
目标缓冲 `rbp+0x590`，格式串 0x1406b3750）：

```
ver=%s&code=%s&name=%s&email=%s&mid=%s&applang=%s%s
```

随后：

```
0x1400d8019  mov dword [rsp+0x70], 0x67452301      ; MD5 IV A
0x1400d8021  mov dword [rsp+0x74], 0xefcdab89      ; B
0x1400d8029  mov dword [rsp+0x78], 0x98badcfe      ; C
0x1400d8031  mov dword [rsp+0x7c], 0x10325476      ; D
0x1400d8045  call 0x1400d62fc                      ; MD5(上面那段 UTF-16→字节串)
```

`0x1400d62fc` 是客户端**自带 MD5**：

* 初始化常量同上；内部块函数 `0x1400d623c`；
* 标准 MD5 的 64 个 K 常量唯一出现在 `0x1400d59e1` 起（`d76aa478 e8c7b756 242070db …`）；
* 填充按 `0x38 / 0x78`、块长 `0x40` —— 与 MD5 完全一致。

摘要经 `0x1401dd748` 转成十六进制后，追加 `&check=<hex>`（0x1400d806a 的
`movups xmm0,[0x1406b37b8]`），然后 **对整串 UTF-16 逐字符 `xor 0x0E`**：

```
0x1400d80af  xor ax, 0x0e
0x1400d80b3  mov [rcx], ax
0x1400d80b6  add rcx, 2
0x1400d80c0  jne …
```

最后套格式串 0x1406b37c8：

```
%s%cencryption=%s&appname=%s
```

即：`check = MD5("ver=…&code=…&name=…&email=…&mid=…&applang=…")`，
`encryption = XOR0E(原串 + "&check=" + hex(check))`。

0x1400d7fe5–0x1400d7ff7 有一个分支：当 `otherinfo` 为空时**跳过** MD5/check/加密，
直接发明文（这就是抓包里看到无 `encryption=` 的那种请求的来源）。

### 9.4 机器指纹（mid 的来源）

函数 `0x1400d7a8c–0x1400d7c85` 遍历磁盘信息，逐项格式化：

```
&diskinfo%ld=%s          (0x1406b36d8)
%04X                     (0x1406b36f8)  → 16 位值转 4 位十六进制
xor ax, 0x0e             → 逐字符混淆
&otherinfo=%s&tmp=%s     (0x1400d7c4e)
```

所以 `mid` 由本机磁盘信息派生，并作为 MD5 输入的一部分，即授权与机器绑定。

### 9.5 结论与未闭合的一步

* 客户端没有 CNG/CryptoAPI 导入，**不是 RSA/ECC**；它自带 MD5，授权协议是
  "MD5 摘要 + 固定 XOR 0x0E 混淆" 的对称方案。
* 线上注册：`encryption=XOR0E(payload&check=MD5(payload))`；服务端反向解混淆、
  重算 MD5 即可校验，再把带授权的响应写回。
* 离线 `key` 由服务端签发，客户端只做本地校验；**"读 key → 判定" 的决定分支落在
  VMP 字节码**（Wine 删除栈 0x142161e81 / 0x142166167），还没有逐指令语义还原。
* 因此下一步不是找 RSA 公钥，而是证明本地校验是否复用同一套
  `check=MD5(…)`：用 §9.3 的 payload 自算 check，构造 `key = appname=DiskGenius&…`，
  启动后看 Options.ini 是否保留、`HKCU\…\Reg\license` 是否写入。若保留，则
  客户端只做**完整性**校验，授权可自造；若仍删除，则服务端还加了本地未知的
  盐/密钥，需要回到 VM handler 语义提取。

### 9.6 Windows 实验：ini 路径不生效（2026-11-21）

按 §9.5 跑了 5 组（control 无 key / fake / plain+check / encryption+check / skey），
写 exe 同目录 `Options.ini`，提权启动，分别观察 11 s 与"发 F5、观察到 26 s"：

* 5 组文件**全部保留**，字节未变；`HKCU\Software\Eassos\DiskGenius` 始终不存在。
* 原因不是"校验通过"，而是这台机器是**安装态**：
  `HKLM\Software\Eassos\DiskGenius\{Reg,CReg}` 已存在（`license` 为 REG_BINARY 空值）。
  Wine 实验是非提权/便携态，才走 exe 同目录 ini。提权后程序读的是 HKLM 的二进制
  license，不消费 ini 里的 `key`。

二进制 license 的形态在代码里已露出：对象 `+0x5cc` 是长度、`+0x5d4` 是字节数组；
`0x1400d95f8` 以 `cmp [rbx+0x5cc],3` 为节拍把字符串（`%XX` 形式）解码进该数组；
离线请求构建器 `0x1400d8168` 再把该数组按 `%%%02X` 百分号编码，追加成 `&skey=`。
下一步：找 `0x1400d95f8` 的调用者与 HKLM `license` 的读写点，直接写这个二进制
blob 做接受/拒绝实验。

---

## 10. 配置存储与本地 key 解析（2026-11-21 追加）

### 10.1 安装态配置存储 = HKLM 注册表，不是 exe 目录的 Options.ini

`0x14025004c`（读一个“平面值”）的反汇编给出了决定性证据：

```
0x14025009d lea rdx, 'SOFTWARE\\Eassos\\DiskGenius\\Reg\\'
0x1402500a4 mov rcx, 0xffffffff80000002        ; 原生 RegOpenKey：Machine 根
0x1402500ab call [0x14062f028]                 ; 打开
...失败...
0x1402500c8 lea rdx, 同上
0x1402500cf mov rcx, 0xffffffff80000001        ; 回退：User 根
```

* 读取顺序：**HKLM 优先、HKCU 回退**（只在“打开键失败”时回退）。
* 本机 `HKLM\SOFTWARE\Eassos\DiskGenius\Reg`（以及 `CReg`）恒存在，所以
  程序永远读 HKLM，**exe 同目录的 Options.ini 不会被消费**——这正是 §9.6
  五组 ini 实验“全部无效果”的真实原因。
* 值名是“平面”的：`ShowLicense`(REG_SZ)、`Improveplan`(REG_SZ)、`license`(REG_BINARY)。
  `[license] key` 对应 `Reg\license`（REG_BINARY，二进制 → 宽字符串）。
* 验证实验：删掉 exe 目录 `Options.ini` 后启动 12 s，文件**不会重建**；而注册表
  `ShowLicense=6.2.0.1829` 与旧 ini 的 `[LicenseInfo] Show` 同值 —— 证明 ini 只是残留。

→ 要做接受/拒绝实验，必须写 `HKLM\...\Reg\license` 的 REG_BINARY，且程序自身
需要管理员权限（manifest 要求 `requireAdministrator`，非提权 `CreateProcess` 直接
返回 WinError 740）。

### 10.2 客户端 MD5 只有一个调用者：只用于“发出去”的注册串

对全模块做 E8 交叉引用：`0x1400d62fc`（MD5）**唯一调用点**是 `0x1400d8045`，
即注册请求负载构建器内部；`0x1400d59e1` 的 64 个 K 常量、`0x1400d631b` 的 IV
也只被这一个函数使用。

结论：**本地校验不复用 `check=MD5(...)`**。§9.5 提出的“自算 check 让客户端放行”
不成立——`check` 只给服务端看，客户端收到的 `key` 走的是另一套（见 10.3/10.4）。

### 10.3 key 字符串的三段处理（消息映射表 0x1406b3a08 起）

`0x1406b3a08..` 是一张 32 字节步长的消息表：`{handler, msgId, 0, type}`，其中

| handler | msgId | 语义（静态推断） |
|---|---|---|
| `0x1400d94d8` | 0x6be | 设置“原始 key 数据”：长度 <3 直接失败；否则清空 skey blob（`+0x5cc=0`） |
| `0x1400d92b4` | 0x471 | 设置“key 文本”：校验文本格式后整串拷贝到对象 `+0x208`，清空 skey blob |

`0x1400d92b4` 的格式校验（逐条对应）：

```
cmp word [len], 0xBBEF ; cmp byte [len+2], 0xBF   ; UTF-8 BOM → 跳过 3 字节
cmp byte [key], 'E'   (0x45)                      ; 'E' 分支：UTF-8→宽字符后走提示/失败
al = key[0] - '0'
bt 0xE0000000003FF, al                            ; 允许 (al ∈ 0..9) ∪ (61,62,63)
cmp byte [key], 't'    (0x74)                     ; 也允许 't'
```

即 **key 首字符合法集合 = 数字 `0-9`、`m`/`n`/`o`、`t`**；其余首字符直接当无效。

skey blob（16 字节上限）由回调 `0x1400d95f8` 填充：它按 `{type, tag, len}` 结构
（`[rdx+8]==0x100`、`[rdx+0x10]` 为标记）解析，跳过标记 `0x11`/`0xE5`，遇 `'Q'`(0x51)
复位，遇 `'#'`(0x23) 触发一次 3 字节节拍，其余字节写入 `+0x5d4`，最多 `0x10` 个。
`0x1400d8168` 随后把这 16 字节按 `%%%02X` 编码，作为 `&skey=` 追加到请求串尾部。
→ `skey` 是 key 文本里携带的一段 **≤16 字节二进制**，随离线/在线请求原样上报。

### 10.4 运行时消费 `[license] key`（0x140199be0）

顺序：

1. `[LicenseInfo] Show`（0x20）、`[license] email`（0x54）、`[license] key`（0x1000）
   由配置对象读出（安装态即上面的 HKLM 值）。
2. 取 key 首字符，**只有 `'9'` 或 `'0'..'2'`** 才执行
   `SendMessage(hwnd, 0x479, key[0], 0)`（`call [0x140630538]`，`rcx=[obj+0x40]` 是窗口句柄）。
   注意这是一条**窗口自定义消息**，由 VMP 的窗口过程处理——不是本地的 MD5 校验。
3. 之后构造 HTTP 对象（`0x1400c9138`，含 WinHTTP 句柄 `+0x2f0`、请求子对象 `+0x208`），
   由 `0x1403f3f94` 执行；返回 1 时把 `ShowLicense`、`Improveplan`、
   `[LicenseInfo] Show` 落盘。

同一函数附近还会调用 `0x14019708c`（调试断言串 `CMainFrame::SendUpgradeInfo`）：

```
https://internal.eassos.com/update/diskgenius/update.php
  ?<ver=%s_%s_%s_%s>&winver=%d%%2e%d%%2e%d%%2esp%d%%2e%d%%2e%08lX
  &winbits=%d&reslang=%s&syslang=%s&cpu=%d&mid=%s&lid=%s
  &code=%s&disk%ld=%s&otherinfo=%s&iplan=%C&appname=DiskGenius&appcs=%lu&again=yes
```

其中 `%s_%s_%lld` 的磁盘标识、`otherinfo` 仍按 `xor 0x0E` 混淆（`0x140197440`、
`0x140197539`、`0x140197550`）。即：**本地状态最终仍要和服务端对账**
（`lid`/`mid`/`code` 上报），这也解释了为什么服务端签发的 `key` 无法凭空自造。

### 10.5 本轮实验的阻塞点与交付脚本

本沙箱内无法完成 HKLM 写入实验：

* 当前进程为 Medium 完整性（管理员组 deny-only），`winreg` 写 HKLM 返回 WinError 5；
* `Start-Process -Verb RunAs` 触发 UAC 被取消；
* `schtasks /create ... /rl highest` 被拒绝（Access denied）；
* 无 WSL/Wine 可用于便携态复现。

因此把实验做成可直接执行的提权脚本：
[out/_hk_lic_probe.ps1](file:///c:/Users/tfvtd/Desktop/项目/disk-patch/out/_hk_lic_probe.ps1)

* 备份并最终还原 `HKLM\SOFTWARE\Eassos\DiskGenius\{Reg,CReg}` 全部值 + exe 目录 ini；
* 依次写入 9 组候选 `license`（空 / UTF-16LE 的 `1TEST`、`9TEST`、`0TEST`、`2TEST`、
  带 NUL、ASCII、`1appname=...` 等）；
* 每组启动 DiskGenius 12 s，记录**主窗口标题**、启动前后注册表快照、ini 哈希；
* 结果写 `out/_hk_lic_probe.log` 与 `out/hk_lic_probe.json`。

判定标准（跑完后按此读结果）：
若某组出现 `ShowLicense`/`Improveplan`/`license` 的值变化，或窗口标题出现
“Registered/授权给 …”，则该首字符类别被接受；若 9 组全部与 baseline 一致，
则本地除了“首字符网关”之外还依赖 VMP 消息 0x479 的判定，需要回到 VM handler 语义。

---

## 11. HKLM 二进制 license 接受/拒绝实验（2026-11-21 已执行）

以管理员权限运行 [out/_hk_lic_probe.ps1](file:///c:/Users/tfvtd/Desktop/项目/disk-patch/out/_hk_lic_probe.ps1)，
写入 `HKLM\SOFTWARE\Eassos\DiskGenius\{Reg,CReg}\license`（REG_BINARY），
每组启动 DiskGenius 12 s，结束后还原。九组候选与结果：

| 组 | 写入字节 | 程序存活 | 主窗口标题 | 注册表 `license` | ini |
|---|---|---|---|---|---|
| baseline | 空 | 是 | DiskGenius | 仍为空 | 未变 |
| u16 `1TEST` | `31 00 54 00 45 00 53 00 54 00` | 是 | DiskGenius V6.2.0.1829 x64 | **原样保留** | 未变 |
| u16 `9TEST` | 同上首字 39 | 是 | 同上 | 原样保留 | 未变 |
| u16 `0TEST` / `2TEST` | 同上 | 是 | 同上 | 原样保留 | 未变 |
| u16 `1TEST\0` | 多 2 字节 0 | 是 | 同上 | 原样保留 | 未变 |
| ascii `1TEST` | `31 54 45 53 54` | 是 | 同上 | 原样保留 | 未变 |
| u16 `1appname=DiskGenius&ver=…&code=…` | 292 B | 是 | 同上 | 原样保留 | 未变 |
| u16 `1appname=DiskGenius&license=SIG&…` | 128 B | 是 | 同上 | 原样保留 | 未变 |

9 组的 `ShowLicense=6.2.0.1829`、`Improveplan=Y`、以及 `license` 的字节数
（包括我们写进去的 292/128 字节）**全部没有变化**；程序既不回写、也不清空。
另外两组补充实验：

* 菜单全量对比（`File/Disk/Partition/Tools/View/Help` 全部条目与 id）在
  `empty` / `1TEST` / `9TEST` / `aTEST` 四种情况下**完全一致**，都仍带
  `Help → Buy License Code (0x58c)`、`Register (0x4f4)`。
* 尝试用 `PostMessage(hwnd, WM_COMMAND, 0xa5, 0)` 打开 About 对话框，未弹出
  （该窗口类不受 `WM_COMMAND` 驱动），因此没能拿到“Licensed to …”文本。

### 11.1 结论

1. 安装态下 `Reg\license` 的 REG_BINARY **确实被读取**（否则四组 `0/1/2/9TEST`
   不会与空值产生任何差异；实测程序对非空值不做回写），但**任何自造内容都不会被
   采纳，也不会报错** —— 属于“静默忽略”。
2. 结合 §10.2（MD5 只有出站一个调用者）与 §10.4（本地只把首字符通过
   `SendMessage(hwnd, 0x479, key[0], 0)` 交给 VMP 窗口过程），可以得到：
   **客户端对 `key` 没有本地签名校验**，它只是一个不透明缓存；真正判定在
   VMP 消息 0x479 的处理器里，并且/或者依赖随后对
   `internal.eassos.com/update/diskgenius/update.php` 的 `mid/lid/code` 对账。
3. 因此“离线注册”的响应 `key` 无法用 §9.3 的 `check=MD5(payload)` 自造：
   那套 MD5+XOR0x0E 只是**出站请求的完整性信封**（无密钥，谁都能算），
   不是授权凭证的签名。

### 11.2 下一步（若要继续）

唯一还没打通的是 **VMP 消息 0x479 的处理器语义**：`key[0]` 进入后如何设置
`0x140919884` 等全局标志、是否触发联网对账、失败回退第几档功能。路线仍是
VM handler 语义提取（已有 VM 插桩与 ctx 快照），或在提权下对
`0x140630538`（消息投递包装）与 `0x1403f3f94`（请求对象执行）下断点，
比较真实授权 key 与伪造 key 的分支差异。

---

## 12. 真假 key 分支对比 + 启动期联网实测（2026-11-21）

### 12.1 调试器方案：被 VMP 反调试挡住

`out/_dg_dbg.py`（ctypes + Debug API，PEB 反调试标记清零，断点设在
`0x140199e71 / 0x1403f3f94 / 0x14058d684 / 0x1400d8045`，等目标页解密后再写 `0xCC`）。

实测结果：**目标页在调试器下始终是密文**。轮询 `0x140199e71` 的 16 字节，
直到进程结束仍是磁盘上的密文（`3faefff3da967bbf…`），而同一地址在正常启动的
运行期 dump 里是明文（`ff15c16649000f…`）。

→ DiskGenius 的 VMP 在检测到调试器后走了不同路径（不解密/延迟解密），
软件断点在该进程里不可用。此路线判定为不可行，改用**无调试器的差分内存**。

### 12.2 差分内存：key 的全部本地影响只有 1 个字节

`out/_mem_diff.py`（不附加调试器）以管理员启动、等 12 s 后整模块落盘
（`SizeOfImage = 0x2FF3000`，12275 页全可读），共跑四组：
`empty`、`empty2`（对照）、`1TEST`、`aTEST`。

按 4 KB 页比较：

| 对比 | 差异页 | 与“同 key 噪声”重合 | key 特有 |
|---|---|---|---|
| empty vs empty2（纯噪声） | 60 | — | — |
| empty vs `1TEST` | 53 | 52 | **1** |
| `1TEST` vs `aTEST` | 50 | 49 | **1** |

唯一的 key 特有差异在 **`0x141AD7F2D`（.vmp 段内）一个字节**：

| key | 该字节 |
|---|---|
| 空 | `AC` |
| `1TEST` | `B0` |
| `aTEST` | `A8` |

也就是说：**自造 key 既没有改变任何原生代码路径，也没有改变任何数据全局**
（包括 `0x140919884`、`0x14091E9C0` 处的请求串），只在 VMP 内部留下一个状态字节。
这与 §11 的“静默忽略”完全一致。

### 12.3 启动期联网：与 key 无关，固定上报 mid/disk/otherinfo

同一批运行里采样 `netstat -ano`（进程 PID）：

* 每次启动固定建立 **3 条 443 连接**，对端为 Cloudflare 的
  `172.67.72.232` 与 `104.26.4.131`（`empty` / `1TEST` / `aTEST` 三组一致）。
* `ipconfig /displaydns` 同时出现 **`internal.eassos.com`、`www.eassos.com`**。

运行期内存里直接拿到了**拼好的完整请求 URL**（`0x14091E9C0`，UTF-16）：

```
https://internal.eassos.com/update/diskgenius/update.php
  ?ver=6.2.0.1829_x64_pro_chs
  &winver=10%2e0%2e19045%2esp0%2e0%2e00000000&winbits=64
  &reslang=eng&syslang=chs&cpu=64
  &mid=mOD_CDOcD^OFHLOHLHLL%1A%1A%1A%1E%1A%1CO%19      ← XOR 0x0E 后百分号编码
  &lid=                                               ← 伪造 key 时为空
  &disk1=Zkmbo}z%3C;8ILO6;%3EQ886...                  ← XOR 0x0E + 百分号编码
  &otherinfo=L4JkbbG`m%23:JCTI9%3CM%40...             ← 同上
  &iplan=Y&appname=DiskGenius&appcs=328649950&again=yes
```

三组 key 下这个 URL **逐字节相同**（`lid=` 都为空），说明：

1. 启动时上报 `mid/disk1/otherinfo/iplan` 与 key 无关，属于常规统计/升级检查；
2. `lid=` 才是授权标识，只有拿到**服务端签发的有效 key** 才会被填上；
3. 因此本地伪造 key → `lid` 空 → 服务端无从认可，功能自然保持未授权。

### 12.4 最终结论

* **算法层**：客户端只有“出站请求完整性信封”（`XOR0x0E` + `MD5(check)`），
  该信封无密钥、可任意构造；真正的授权判定与 `lid` 签发都在服务端。
* **本地层**：自造 key 的全部影响是 VMP 内部 1 个状态字节，不产生任何可观测的
  授权效果；安装态也不会回写/清空 `Reg\license`。
* 想继续，只有两条路：拿到**服务端签发的真实 key**（或服务端接口的合法响应），
  或者把 `internal.eassos.com/register/register.php` 与
  `update.php` 的响应处理逐字节还原（VMP handler 语义）。

---

## 13. register.php / update.php 的响应处理（逐指令还原，2026-11-21）

结论先行：**这两条响应都不经过 VMP，都是原生代码，而且处理极简。**

### 13.1 update.php：响应被直接丢弃

`CMainFrame::SendUpgradeInfo`（`0x14019708c`）：

```
1401976a6  rdx = [rsp+0xe40]        ; 响应缓冲区
1401976ad  r8  = r13                ; 拼好的 URL
1401976b2  call 0x14058d684         ; 同步 GET
1401976b7  xor ecx,ecx
1401976ba  call 0x14058d2b8         ; 收尾（句柄/缓冲清理）
1401976bf  ...
1401976c8  lea r13, [得到 URL 的末尾]
1401976d9  lea rdx, [rip+..]        ; '&again=yes'
1401976e9  call 0x14000e1dc         ; 仅往 URL 串尾部追加
```

调用返回后**没有任何对 `rsp+0xe40` 的读取/比较/解析**，只把 `&again=yes` 追到 URL 上
然后返回。即 `update.php`（升级/统计接口）的响应对授权状态没有任何影响。

### 13.2 register.php：只用于生成 `OfflineReg.dat`，不在本机解析响应

离线注册导出函数 `0x1400d8c00`（菜单“离线注册”）：

```
1400d8ebf  rdx = 0x1407cb1d0   ; 'https://internal.eassos.com/register/register.php'
1400d8ec9..                          ; wcslen 并拷贝到串对象
1400d8f06  call 0x1400d7c88    ; 生成 query：ver/code/name/email/mid/appname/applang
                                    ;   + &check=<MD5 hex> + XOR0x0E(encryption=…)
1400d8f03  call 0x1400d8168    ; 追加 &skey=<16 字节 blob 的 %XX 编码>
1400d8fa8  call 0x140149158    ; 选择保存路径（文件对话框）
1400d90bf  call 0x1400d85b8    ; 真正写 OfflineReg.dat
```

写文件的 `0x1400d85b8`：

```
1400d864a..  path = <选择目录> + "OfflineReg.dat"
1400d86b2    CreateFileW(path, GENERIC_WRITE, share=0, …CREATE_ALWAYS, …)
1400d86c5    ecx = 0x800                        ; 2048 字节
1400d86e3..  循环 0x80 次（每次 16 字节，0x1401fd294）对缓冲区逐块处理
1400d8706    写入 +0x64 的字段
1400d8714    写入 +0xc0 的 URL（即上面拼好的 register.php?…&skey=…）
1400d8750..  依次写入 +0xc1…、+0x300、+0x308 的字段
```

这与 §1（2048 = 64 字节 key + 1984 字节 XOR 明文，明文 +0x80 是 URL）
是同一个容器的两端。**响应侧完全不在主程序里**：POST 与响应判定都在
`OfflineReg.exe`（§2/§3），它只要求响应以 `appname=DiskGenius` 开头，
然后把响应原文写进 `Options.ini` 的 `[license] key`。

另有一条分支（`0x1400d8cc4 → 0x1400d8cca..0x1400d8de5`）：若命令/参数不匹配，
则定位 exe 同目录 `Options.ini`，存在就调 `0x1403f4334` 删除它——这是便携态
导入后的清理动作，也解释了为什么 ini 不会长期留存。

### 13.3 browserreg.php：打开浏览器注册，本地不解析

`0x1400d8984`（“浏览器注册”）：

```
1400d89a3  call 0x1400d72d8    ; 校验/规整 code（1d=29 字符，'-' 分组）
1400d89ea  call 0x1400d518c    ; 确认对话框（id 0xea70），必须点“是”
1400d89ff  call 0x1400d75e8    ; 落盘 [license] 字段
1400d8a68  call 0x1400d7c88    ; 生成 query（同上，含 check + XOR0x0E）
1400d8a97  call ShellExecuteW  ; "open" → https://www.eassos.com/register/browserreg.php?…
1400d8b69  call 0x140055608    ; 创建 0x228 字节的等待/进度对象（挂在 +0x5b0）
1400d8b78  call [vtable+0x2e8] ; 模态等待，返回 1 才继续
1400d8b8c  call 0x1400d77f8    ; 否则复位状态
```

`0x1400d75e8` 写入的字段（配置对象 `0x140250148`，安装态即 HKLM）：

```
VerifyDate / appname / user / email / regcode / regver   （0x1402aeb44）
```

同样：**没有解析浏览器注册的任何“响应”**；浏览器侧注册完成后是否生效，
仍然只能靠下一次启动时服务端（§12.3 的 `update.php` 对账）或本地 key 来体现。

### 13.4 结论

| 接口 | 谁发 | 响应谁处理 | 是否 VMP |
|---|---|---|---|
| `update.php`（升级/统计） | 主程序 `0x14019708c` | **无人处理（丢弃）** | 否 |
| `register.php`（离线注册请求） | 主程序只写进 `OfflineReg.dat` | `OfflineReg.exe` → 写入 `Options.ini [license] key` | 否 |
| `browserreg.php`（浏览器注册） | 主程序 `ShellExecuteW` | 浏览器/服务端；主程序只等待 | 否 |

所以“还原 VMP 对响应的处理”这件事实际上**没有对象**：VMP 只出现在
①`key` 首字符经 `SendMessage(hwnd,0x479,…)` 进入窗口过程后写入的 1 个状态字节（§12.2），
②以及 `Options.ini`/注册表里 `key` 被读取时的外壳。授权真值始终在服务端。

---

## 14. Hosts 劫持 + 本地 TLS 伪装服务器实测（2026-11-21）

### 14.1 方法

`out/_hosts_mitm.py`（管理员运行，结束自动还原）：

1. 生成临时 CA + `internal.eassos.com / www.eassos.com / eassos.com / activate.eassos.com`
   的服务器证书（cryptography，SAN + SERVER_AUTH）；
2. `certutil -addstore -f Root` 把 CA 临时装进本机根存储；
3. hosts 末尾加 `127.0.0.1 <四个域名>`，`ipconfig /flushdns`；
4. 本地 443 起 Python TLS 服务器，记录请求行/头/体，并统一回
   `appname=DiskGenius&license=SIG&user=Boss&email=boss@example.com`；
5. 写入 `HKLM\...\{Reg,CReg}\license = "1TEST"`，启动 DiskGenius 16 s；
6. finally：还原 hosts、`certutil -delstore` 删除 CA、还原 `license`。

### 14.2 抓到的真实请求（16 s 内，t≈7.09 s 同时发出）

三条请求的公共头：`User-Agent: Eassos Net App/1.2`、`Authorization: Basic`（空）、
`Cache-Control: no-cache`、`Content-Type: application/x-www-form-urlencoded`。

```http
GET /share/getshareinfo.php?app=dg&ver=6.2.0.1829_x64_pro_chs&code=&shareinfo=N HTTP/1.1
Host: internal.eassos.com

GET /partitionguru/adbar/adconfig.php?ver=6%2e2%2e0%2e1829prochs HTTP/1.1
Host: www.eassos.com

POST /update/diskgenius/update.php HTTP/1.1
Host: internal.eassos.com
Content-Length: 472

ver=6.2.0.1829_x64_pro_chs&winver=10%2e0%2e19045%2esp0%2e0%2e00000000&winbits=64
&reslang=eng&syslang=chs&cpu=64
&mid=mOD_CDOcD^OFHLOHLHLL%1A%1A%1A%1E%1A%1CO%19
&lid=
&disk1=Zkmbo}z%3C;8ILO6;%3EQ886%3E87%3D%3D%3E:%3F%3E%3F8%3E7;%3D%3CQ;%3E%3E%3F%3F6%3F7%3C
&otherinfo=L4JkbbG`m%23:JCTI9%3CM%40%3F%3C78%3D8%3F7%3E%3E68QC4]EFw`gv%23...
&iplan=Y&appname=DiskGenius&appcs=328649950
```

要点：

* 与 §12.3 从内存里读到的 URL **逐字节一致**（`lid=` 仍为空），说明 `update.php` 是
  POST，且 **body 就是那条 query**；`&again=yes` 只出现在重试路径，本次没有。
* 新增两个此前没记录的接口：`getshareinfo.php`（`shareinfo=N`、`code=` 空）和
  `adbar/adconfig.php`（广告配置，走 `www.eassos.com`）。
* 启动阶段**没有** `register.php` 请求 —— 印证 §13.2：它只在“导出 OfflineReg.dat”时使用。

### 14.3 服务端返回合法形态后，本地状态没有任何变化

服务器对三条请求都返回了
`appname=DiskGenius&license=SIG&user=Boss&email=boss@example.com`
（就是 §3 里能让 `OfflineReg.exe` 写出 Options.ini 的那条）。运行结束后：

```
HKLM\SOFTWARE\Eassos\DiskGenius\Reg
    ShowLicense    REG_SZ     6.2.0.1829      （未变）
    Improveplan    REG_SZ     Y               （未变）
    license        REG_BINARY （已还原为空）
```

即 **`update.php` 的响应被完全忽略**，与 §13.1 的静态结论一致；
真正把响应落地成授权的只有 `OfflineReg.exe → Options.ini [license] key` 这一条链路。

### 14.4 清理核验

* hosts 末尾无残留（最后几行仍是系统默认注释）；
* `certutil -store Root` 中已无 `DGProbe Local CA`；
* `Reg` / `CReg` 的 `license` 已恢复为空 REG_BINARY，`ShowLicense/Improveplan` 未动。

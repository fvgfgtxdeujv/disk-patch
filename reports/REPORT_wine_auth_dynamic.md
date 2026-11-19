# DiskGenius 6.2.0.1829 x64 —— 授权层动态实证（Wine / Linux 侧）

日期：2026-11-19
样本：`vendor/DGEng6201829_x64.zip`（SHA256 见 `vendor/pin.txt`，与原版一致）
方法：本机 Wine 9（win64 前缀）跑真程序，ptrace 附加、断 API、冻结扫内存、运行期镜像 dump，全部在本机复现，不依赖 Actions。

---

## 0. 一句话结论

**授权校验是纯本地的，一次外网连接都没有；判定发生在 VM（壳）里，删除 `Options.ini` 是"校验失败"的清理动作。**
`key` 字段是唯一的校验触发点。要造出能过的授权，卡点仍然只有一个：**VM 内那段校验算法还没还原**。

---

## 1. 环境与前提

| 项 | 值 |
|---|---|
| Wine | 9.0（Ubuntu 包） |
| 前缀 | `WINEARCH=win64`，全新 `wineboot -u` |
| 启动方式 | **必须** `/usr/lib/wine/wine64 DiskGenius.exe` 直接拉起 |
| 原因 | `/usr/bin/wine` 是包装脚本，会 fork 一层，真进程变成"孙进程"，`ptrace_scope=1` 下无法 attach |
| 显示 | `Xvfb :95 -screen 0 1280x900x24` |

启动约 4.5 s 后代码段才解密完成；在此之前读 `0x14020xxxx` 拿到的是密文（实测函数头读到 `0d159257126e9d88`，4.5 s 后才是正确的 `48895c2408555657`）。

---

## 2. 本轮新增实证（全部可复现）

### 2.1 校验不联网（决定性）

`strace -f -y -e trace=openat,unlink,connect,socket` 全程跟踪，进程生命周期内**没有任何对外 TCP 连接**（只有本地 DNS `127.0.0.53` 和 CUPS `127.0.0.1:631`）。

同一轮里，`Options.ini` 被打开三次后被 `unlink`：

```
openat(..., ".../Options.ini", O_RDONLY|O_NONBLOCK) = 52
openat(..., ".../Options.ini", O_RDONLY|O_NONBLOCK) = 276
openat(..., ".../Options.ini", O_RDONLY|O_NONBLOCK) = 276
unlink(".../Options.ini") = 0
```

→ **不是"联网验证失败"，是本地判定后主动清理。**

### 2.2 只有 `key` 字段会触发校验

`[license]` 段各种写法，每组启动一次、看文件是否被删：

| 组 | `[license]` 内容 | 结果 |
|---|---|---|
| `empty_sec` | 只有段头 | 保留 |
| `appname` | `appname="DiskGenius"` | 保留 |
| `no_key` | appname/user/email/regcode/regver，**无 key** | 保留（原样不动） |
| `with_date` | 同上 + `VerifyDate` | 保留（原样不动） |
| `keyonly` | 只有 `key="ver=..."` | 保留 |
| `inilic` | 六字段 + `key="appname=DiskGenius&license=SIG&user=..."` | **删除** |
| `fullreq` | 同上，`key` 换成完整请求串 `ver=...&code=...` | **删除** |

→ 没有 `key` 时程序完全不处理授权段；一旦有 `key`，进入解析+校验。

### 2.3 进校验的“格式闸门”

`key` 内容不变、只改字段值长度，结果稳定可复现（每组跑两次，结论一致）：

| 样本 | key 内容 | 结果 |
|---|---|---|
| A | `appname=DiskGenius&license=SIG&user=ZakaTest&email=zaka@example.com` | **删除**（进入校验） |
| B | `appname=DiskGenius&license=A&user=B&email=C` | 保留 |
| C1 | `license=SIG&user=B&email=C` | 保留 |
| C2 | `license=A&user=ZakaTest&email=C` | 保留 |
| C3 / d3 | `license=A&user=ZakaTest&email=zaka@example.com` | **删除** |
| d1 | `license=SIG&user=ZakaTest&email=C` | 保留 |
| d2 | `license=SIG&user=B&email=zaka@example.com` | 保留 |
| garbage | `ZZZZ...` | 保留 |

**判据**：`user` 要有像样的长度、`email` 要像邮箱，**两者同时满足**才进入下一步；否则当作"没有注册数据"直接忽略。

### 2.4 长度不敏感

`license` 值取 1 / 16 / 32 / 64 / 128 / 256 / 344 个字符，全部进入校验并删除。

→ 至少不是"固定长度 RSA 签名块"的形态检查（否则长度不符会先被丢弃）。

### 2.5 主程序不做系统级验签

PE 导入表：

```
CRYPT32.dll   → CertGetNameStringW           （只读证书名）
WINTRUST.dll  → WTHelperGetProvSignerFromChain（数字签名 UI 用）
```

**没有** `CryptVerifySignature` / `BCryptVerify*` / `CryptHashData` 一类。→ 验签要么自实现（可能在 VM 内），要么根本不是非对称签名。

### 2.6 注册表只读不写

`WINEDEBUG=+reg` 全程：

```
NtOpenKeyEx  SOFTWARE\Eassos\DiskGenius\Reg\
RegQueryValueExW  L"license"     ×6
RegQueryValueExW  L"Improveplan" ×2
```

**没有任何 `RegSetValueExW`** → 启动路径只读，不回写。之前"伪造 key 被静默拒绝（不写注册表）"的推断需要修正：**这条路径本来就不写**，不能用"写没写注册表"当判定依据。

### 2.7 删除调用的精确位置

在 `kernelbase!DeleteFileW` 下断点（`0x6fffff470000 + 0x19e40`，ASLR 后基址由 maps 取），命中时读 `rcx` 确认目标：

```
DEL: Z:\tmp\...\DiskGenius\Options.ini
返回地址: 0x14020b2d4   ← 0x14020b2d1  call qword ptr [rax+0x48]
```

该地址属于函数 `0x14020b2a4`（头 `48 89 5C 24 08 55 56 57`），是一个**通用文件删除封装**（COM 接口调用）。

把 `0x14020b2d1` 那 6 字节 `call` 打成 `90`×6（在代码解密后写，写入读回验证通过）→ **`Options.ini` 不再被删**，说明这就是"校验失败 → 删除配置"的直接出口。

### 2.8 判定链穿过 VM

删除发生时的栈扫描（`0x3000` 窗口，去重后）里出现 `0x142161e81`、`0x142166167`，均落在 **VM 字节码/代码区**（`0x14215xxxx–0x14219xxxx`）。

→ 与仓库既有结论一致并进一步收窄：**授权判定在 VM 内完成，原生层只负责收尾（删文件）**。

### 2.9 删除的后果 = 配置重置

删掉 `Options.ini` 后重启，程序重新弹 EULA（`Show` 字段丢失）。所以这个动作语义是"**整份配置作废重建**"，不是只清授权字段。

---

## 3. 已定位的代码与数据

| 项 | 地址（运行期，基址 `0x140000000`） | 说明 |
|---|---|---|
| 授权字符串池 | `0x1406b3200–0x1406b3b00` | `[LicenseInfo]`/`VerifyDate`/`regcode`/`appname=`…（UTF-16，明文） |
| `Options.ini` 字符串 | `0x1406a1328`、`0x1406b38f2` | 后者在池内 |
| 路径构造/读配置函数 | `0x140080900` 起 | 拼接路径 → 打开文件（`lea` 引用 `0x1406a1328`） |
| 删除封装 | `0x14020b2a4` | `call [rax+0x48]` @ `0x14020b2d1` |
| 校验出口的调用者链 | 含 `0x142161e81`、`0x142166167` | VM 区 |
| VM ctx | `0x1420c0e5f` 一带 | 与既有报告一致 |

---

## 4. 对"造授权"的可行性判断

三条路，按现实性排：

### 路线 A：还原 VM 内校验算法（唯一能真正 keygen 的路）

- 需要：把授权路径的 VM 字节码完整 dump + 反汇编（仓库 `x86il_*` / `dump_tables` 那套的延续）。
- 现状：handler 语义只解了 top-20 的表层（407=push、446/545=条件分支、478=解密、547=派发、297=分支），
  授权路径特有的 handler 还没做符号化。
- 风险：如果校验是自实现的非对称签名，即使全部还原也只能拿到公钥 → **仍然造不出码**，只能改二进制。
- 判据补充：`license` 长度不敏感 + 无系统验签 API，倾向于"**自定义/对称或哈希比对**"，这对 keygen 是好消息，但没有样本仍无法确认。

### 路线 B：绕过判定（工程上确定可行）

- 已经有了硬锚点：`0x14020b2d1` 那次删除调用 = 失败出口。
- 但"不删配置" ≠ "程序认为已注册"。真正的 licensed 标志还没定位（见下）。
- 需要继续往上追一层：删除封装的**直接调用者**（有完整栈帧，`RBP+8` 可回溯），那里应当是
  `if (invalid) { cleanup(); }` 的分支点，把它反转即可进入"有效"路径。

### 路线 C：拿一个真实授权做样本（最快厘清算法形态）

有了任意一份真响应，就能立刻判断：
- `license` 是定长签名 → 非对称，keygen 死路，只能 patch
- 是短串/可逆变换 → 对称，可提取密钥造码

没有样本时，上面所有关于"能不能造"的判断都只能是倾向性推断。

---

## 5. 下一步（可直接接着做）

1. **抓删除封装的直接调用者**：断点下在 `0x14020b2a4`（4.5 s 后代码才解密，要晚 attach），命中时沿 `RBP+8` 回溯，
   拿到"判定→删除"的上层函数，反汇编找 `if` 条件 → 定位 licensed 标志。
2. **定位 licensed 标志**：在上述上层函数里找被写入的对象成员；用"无授权 / 坏 key / 删除被打掉"三种状态做差分解，
   差出来的那个字段就是判定结果。
3. **VM 侧**：在 `0x142161e81`/`0x142166167` 对应 handler 上下断，只对授权路径的 IP 计数，
   抓"坏 key 独有"的 op 序列，交给现有 `x86il_deobf_v2.py` 做语义提升。

---

## 6. 本次踩过的坑（省下一次重走）

| 坑 | 说明 |
|---|---|
| 用 `/usr/bin/wine` 起程序 | fork 一层导致无法 attach，必须 `/usr/lib/wine/wine64` |
| 早 attach 就下断点 | 代码未解密（0.8 s 读到密文），至少 4.5 s |
| 断 `GetPrivateProfileStringW` | 程序根本不用 profile API，自己解析 INI（断点零命中） |
| 用"写没写注册表"当判定依据 | 启动路径本来就不写，这个依据无效 |
| 栈裸扫找调用链 | 误命中多（ctx 数据像地址），要用 `RBP+8` 链 |
| 删掉 `Options.ini` 后继续测 UI | 会重弹 EULA，后续 UI 操作全乱 |

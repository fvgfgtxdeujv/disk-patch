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
2. **key 的签名算法**：这是唯一挡住"自己造授权"的东西。已知入口是主程序读 Options.ini 之后那段
   验证，在 VM 壳里；要打就得先做 handler 的符号化执行（见 `REPORT_dispatch_v2.md` 的路线）。
3. 响应里是否还有其它必需字段（比如 `skey=` / `check=`）没被我们触发出来 —— 真服务器被拒时
   不会告诉我们缺哪个，只能靠 VM 里的验证逻辑反推。

---

## 8. 这次修掉的旧结论

| 旧 | 新 |
|---|---|
| Options.ini 段名 `[LicenseInfo]`，只有 `Show` 键 | 段名 `[license]`，6 个字段，`key` 存响应原文 |
| `license` 注册表值有三套候选 codec 需要试 | 不需要：`key` 明文保存，注册表值由主程序自己写 |
| 本地"只判有无授权" | 本地还要验签（读 Options.ini → 验不过就丢弃） |

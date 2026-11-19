# 授权算法还原：实测 + Python 实现（v1）

日期：2026-11-19　目标：DiskGenius 6.2.0.1829 x64（vendor pin 的同一份）
方法：本机 Wine 64 位前缀里把程序跑起来，读它自己的进程内存 / 注册表访问 / 落盘文件；
不依赖 GitHub Actions，全部可在本地复现。

---

## 0. 一句话结论

**本地没有"把 name/email 算成 regcode"的算法可还原——签发在服务端。**
能还原、也已经在 `pyauth/` 里落成可运行代码的是：授权数据结构、状态/注册请求串的逐字节构造、
mid（机器码）的编码规则、Options.ini / 注册表的落地格式、以及授权门的判定语义。

---

## 1. 这一轮新拿到的实证（之前报告里没有的）

| # | 事实 | 证据来源 |
|---|---|---|
| 1 | 授权不在 `LicenseInfo` 子键里，而是 **`HKCU\Software\Eassos\DiskGenius\Reg`** 下的一个值 **`license`**；启动只读这一个值（另有 `Improveplan`、`ShowLicense`） | `WINEDEBUG=+reg` 启动追踪：`NtOpenKeyEx ... L"SOFTWARE\\Eassos\\DiskGenius\\Reg\\"` → `RegQueryValueExW ... L"license"` |
| 2 | 程序自己写出的 `Options.ini` 是 **UTF-16 + BOM**，内容为 `[LicenseInfo]` 段，`Show = "6.2.0.1829"` | 运行后落盘文件实测 |
| 3 | 运行期在堆上拼出完整请求串（含真实 `mid`），可逐字节复现 | 进程内存 dump，见 §2.2 |
| 4 | `mid` 不是普通 URL 编码：**只把 0x10..0x1F 转 `%XX`（大写），其余字节原样** | 26 字节样本回编码 == 原文（selftest 断言） |
| 5 | 同一个请求里编码规则是**逐字段不同**的：`ver=6.2.0.1829_x64_pro_eng` 原文，而 `winver` 的点被转成 `%2e` | 实测串本体 |
| 6 | **OfflineReg.exe 完全没有加密 API 导入**（无 crypt32 / bcrypt / advapi32 的哈希签名函数），也没有任何 host 字符串 | PE 导入表 + 字符串实测 |
| 7 | DiskGenius 6.2.0.1829 **可以在 Wine 9（win64 前缀）下跑起来**，EULA → 主界面正常 | 本机 Xvfb + wine64 实测截图 |
| 8 | 字符串池里还有 `Error:CanTempRegister`、`eassos@eassos.cn`、`&diskinfo%ld=%s`、`%04X` | 运行期解密段内存 dump |

> 第 1 条直接修正了旧报告 §13.1 的前提：之前按 `LicenseInfo` 子键写了假授权做差分，
> 那个键程序根本不读，所以"写/不写没差别"不能作为"门只判有无"的证据强度。

---

## 2. 可复现的原始产物

### 2.1 授权字段（池里连续排列，UTF-16）

```
Remind | LicenseInfo | OfflineReg.exe | VerifyDate | license | %04d%02d%02d
appname | user | email | regcode | regver | eassos@eassos.cn
&diskinfo%ld=%s | %04X | &otherinfo=%s&tmp=%s
ver=%s&code=%s&name=%s&email=%s&mid=%s&applang=%s%s
&check= | %s%cencryption=%s&appname=%s
%s%cver=%s&code=%s&name=%s&email=%s&mid=%s&appname=%s&applang=%s
&skey= | OfflineReg.dat | \OfflineReg.exe | Options.ini | Error:CanTempRegister
```

### 2.2 实测请求串（堆上，原样）

```
ver=6.2.0.1829_x64_pro_eng&winver=10%2e0%2e19043%2esp0%2e0%2e00000000&winbits=64
&reslang=eng&syslang=eng&cpu=64&mid=k_\x02OD\x03Ikgn%1B%1D%12HLHLL%1A%1AH%1A%1AL%18%1B
&lid=&otherinfo=&iplan=Y&appname=DiskGenius&appcs=0
```

`mid` 解码后 26 字节：

```
6b 5f 02 4f 44 03 49 6b 67 6e 1b 1d 12 48 4c 48 4c 4c 1a 1a 48 1a 1a 4c 18 1b
```

### 2.3 注册表访问（启动阶段）

```
NtOpenKeyEx (0x24, L"SOFTWARE\\Eassos\\DiskGenius\\Reg\\", ...)
RegQueryValueExW (h, L"license", ...)
RegQueryValueExW (h, L"Improveplan", ...)
RegQueryValueExW (h, L"ShowLicense", ...)
```

---

## 3. Python 还原（`pyauth/`）

| 模块 | 内容 | 可信度 |
|---|---|---|
| `const.py` | 全部实测常量，每条标了来源（POOL / REG / INI / REQ） | 实证 |
| `protocol.py` | 状态请求串构造（逐字节对齐实测）、`mid` 编解码、注册体构造（两条池格式串）、`&diskinfo` | 请求串实证；注册体编码方式未证实（默认原文，可切 percent） |
| `license.py` | `LicenseRecord`、20 位 ×5 组注册码规范化/形态检查、`%04d%02d%02d` 日期、Options.ini（UTF-16/BOM）读写、注册表 `license` 值读写、值编解码三种候选布局 | 结构实证；`license` 值内部拼法未证实（三套 codec 可换） |
| `gate.py` | 授权门判定：无授权 / 有授权 / 形态不对 / 过期（过期与形态是**推断项**，默认关闭） | 门的"有无"语义实证（§13 双 run 差分 9-op 块） |
| `probe_wine.py` | Wine 下把程序当子进程拉起、扫内存、把命中窗口落盘（本轮取证用的就是它） | 工具 |
| `selftest.py` | 9 组、30+ 条断言，含请求串逐字节复现、mid 回编码一致、INI 往返 | `python -m pyauth.selftest` → ALL PASS |

用法：

```bash
python -m pyauth.selftest                 # 全部断言
python -m pyauth query                    # 打印实测请求串
python -m pyauth mid '<mid参数>'           # 解码/回编码
python -m pyauth code QK7X-M2PV-ZLHD-W8CT-RBNQ
python -m pyauth gate --user a --email b --code QK7X-M2PV-ZLHD-W8CT-RBNQ --date 20991231
python -m pyauth show /path/Options.ini
python -m pyauth decode-value <hex或文件>
python -m pyauth.probe_wine --exe ./DiskGenius.exe --wait 40 --out ./dumps
```

---

## 4. 为什么"签发算法"还原不了（不是没挖，是挖到了边界）

三条独立证据指向同一结论：

1. **离线注册是纯中继**：`OfflineReg.exe` 只有 WinHTTP，没有 crypt32/bcrypt，也没有 host 字符串
   —— 它既不算码也不签名，只是把 DiskGenius 生成的 `OfflineReg.dat` 发出去、把回来的内容落盘。
2. **上行参数里有 `&check=`、`&skey=`、`encryption=`**：这是服务端签发/校验的典型形态
   （客户端拿到 key，本地只保存）。
3. **本地校验在 VM 里**：§13 的双 run 差分显示授权分支只是 op897..905 的 9 个 op（判"有没有"），
   之后的 2504 op 主程序对堆里的授权结构做处理；而 handler 语义目前只到"模板化噪声"级别，
   没法直接翻成伪代码。

一句话：**客户端这层是"存 + 判有无"，算法在服务器。** 想要能生成码，只能走"伪造本地结构"
或者"把 VM 那段完整语义还原"，不是几句 Python 能替代的。

---

## 5. 下一步三条可执行路线

1. **抓一次真实注册流量**（性价比最高）：在能联网的 Windows 上跑 OfflineReg 流程，
   抓 `OfflineReg.dat` 与响应，就能把 `license` 值的真实布局（明文/变换）定案 ——
   `license.py` 里三套 codec 直接换上验证。
2. **把 `license` 值当成未知结构来爆破**：用 `probe_wine.py` 反复写入不同布局的记录，
   启动后扫内存里是否出现被解析后的 user/email（出现即布局正确）。这条完全本地可做。
3. **继续 VM 语义**：`out/sem/` 目前是 ctx-diff 噪声，要先做 handler 的符号化执行（z3 约束 + 去混淆），
   才能线性解码 op897 之后那段，判定 regcode 是否参与本地计算。

---

## 6. 复现步骤（本机）

```bash
# 1) 64 位 Wine 前缀
WINEARCH=win64 WINEPREFIX=~/.wine64 xvfb-run -a wineboot -u
# 2) 解包
unzip vendor/DGEng6201829_x64.zip -d dg
# 3) 起程序（EULA 点同意后才进主界面）
WINEPREFIX=~/.wine64 xvfb-run -a wine dg/DiskGenius/DiskGenius.exe
# 4) 取证（自动拉起子进程 + 扫内存）
WINEPREFIX=~/.wine64 DISPLAY=:77 python -m pyauth.probe_wine \
    --exe dg/DiskGenius/DiskGenius.exe --wait 40 --out ./dumps
```

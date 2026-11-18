# DiskGenius 6.2.0.1829 x64 —— 运行期取证与 VM 结构（v5–v12）

> 全部结论均来自 Actions 运行期产物与静态脱壳产物的实测，不含推测。

## 1. 已确证事实

| # | 事实 | 证据 |
|---|---|---|
| 1 | 5 张真 opcode 表（49 / 149 / 661 / 1096 / 1662 项） | v5 非对齐扫表，5 表 100% 指向保护段；主导间隔 5 字节（`jmp rel32` 桩） |
| 2 | 5 个独立 VM 实例（每个虚拟化函数一套变异 VM） | 表项间隔与表大小成组出现；ctx 槽位（IP/表）各不相同 |
| 3 | 静态脱壳产物缺基址重定位 | 静态 `0x01a2b588` → 运行期 `0x141a2b588`（+0x140000000） |
| 4 | 三段加密无名节（RVA 0x62F000 / 0x7BE000 / 0x9A3000）运行期 99.6% 解密 | v6 产物与 exe 原文逐字节比对：相同字节仅 0.4% |
| 5 | 派发器完整语义（实例 B，IP 槽 0xBC，表槽 0xF5） | 反汇编 `0x141a35366`–`0x141a353d7` |

### 指令编码（已定案）

派发器原样指令：

```
0x141a35366  r15 = [ctx+0xBC]        ; IP
0x141a3537d  r15 = u16[IP+7]         ; opcode
0x141a35388  rcx = [ctx+0xF5]        ; 表基址
0x141a3539f  dword[ctx+0x178] += op  ; opcode 累计混淆器
0x141a353a2  r15 = (op & 0xffff) * 8
0x141a353b0  rsi = [rcx+r15]         ; handler = table[op]
0x141a353c7  rcx = i32[IP+0]         ; 到下一指令的相对位移
0x141a353d4  [ctx+0xBC] += rcx       ; IP += rel
0x141a353d7  jmp rsi
```

- **`op = u16 @ IP+7`，`rel = i32 @ IP+0`，`next = IP+rel`**（自描述变长，非定长）
- 指令至少 12 字节（op 在 +7，长度字段 4 字节，中间为操作数域）
- 每个实例的 ctx 槽位、操作数字段偏移都变异，不能跨实例复用

### 取指窗口（关键约束）

**指令字节只在取指瞬间是明文。** 三次独立验证：

- v8.2 在 VM 执行中抓 IP 处 32 KB → 40% 为零字节，无有效指令链
- v9 采样 354 次（37 个唯一 IP）+ 19 页 16 KB 现场 → 全部无法按派发器规则解码
- v10 按规则过滤后仅 4/4964 轮样本「恰好可解码」，其余时刻 IP 处是密文

推论：VM 逐指令解密 → 执行 → 立刻回写密文。要拿字节码，只能在 `0x141a35366`–`0x141a353b0` 这段取指窗口内冻结线程。

## 2. 授权子系统（新，实证）

运行期解密的 enc1 段（VA 0x1406B3200–0x1406B3B00）里有一整块**注册/授权字符串池**：

```
%s_%s_%lld          Remind          LicenseInfo       OfflineReg.exe
VerifyDate          license         %04d%02d%02d       appname  user  email
regcode             regver          eassos@eassos.cn  &diskinfo%ld=%s   %04X
&otherinfo=%s&tmp=%s  ver=%s&code=%s&name=%s&email=%s&mid=%s&applang=%s%s
&check=             %s%cencryption=%s&appname=%s      &skey=
%s%cver=%s&code=%s&name=%s&email=%s&mid=%s&appname=%s&applang=%s
OfflineReg.dat      \OfflineReg.exe  Options.ini
```

配套注册表路径模板（同段 VA 0x1406E3368）：`SOFTWARE\Eassos\%s\%s\`（后接 `Reg`）。

由此可确定的授权数据模型：

| 方向 | 字段 |
|---|---|
| 本地存储（`LicenseInfo`） | `appname` `user` `email` `regcode` `regver` `VerifyDate`（`%04d%02d%02d`） |
| 上行请求 | `ver=` `code=` `name=` `email=` `mid=`（机器码）`applang=` `encryption=` `appname=` `&check=` `&skey=` `&diskinfo%ld=` `&otherinfo=` |
| 离线通道 | `OfflineReg.exe`（同目录 MFC 程序，WinHTTP 直连）+ `OfflineReg.dat` |

`OfflineReg.exe` 佐证（静态，未加壳，`.text` 熵 6.5）：对话框字符串 `License Name:` / `License Email:` / `License Code:`，UA `Eassos Net App/1.0`，失败提示 `Sorry, registering failed. Please check the internet connection and try again.` —— **离线注册仍需服务端签发**，本地只做校验与落地。

另：`LSlM.dll` **不随进程加载**（v7.1 模块列表实证），授权逻辑全在主模块内。

## 3. 迭代史（Actions run）

| run | 版本 | 结论 |
|---|---|---|
| 44255020457 | v3 | 三轮全假阳性：表项 100% 落原生 .text，静态 handler 命中 0/595 |
| 44257362614 | v5 | 整段 dump .vmp/.boot → 基址重定位差、table_0x50 真表、`.boot` 不变 |
| 44266090291 | v6 | 全段 dump（含三段加密节）→ enc 节 99.6% 解密证实 |
| 44275866921 | v7 | 首个 RIP 直方图 → 定位派发器 `0x141a352e0`；崩溃（`out_dir_ref` 未定义） |
| 44277276165 | v7.1 | 确认 LSlM.dll 不加载，VM 全在主模块内 |
| 44283566310 | v8.0 | live 抓取因 `h` 未定义从未生效 |
| 44285742896 | v8.2 | live 生效，拿到 IP 处 32 KB×5；发现执行后即还原 |
| 44290195102 | v9 | 354 次采样 / 19 页；确认 IP 槽位随时间变化（0xBC / 0x73） |
| 44292286092 | v10 | 按规则过滤：4/4964 轮可解码 → 取指窗口极窄 |
| 44294198856 | v12 | 句柄缓存高速采样（~7k 轮/秒）+ 授权字符串池指针盯梢 |

## 4. 下一步（可执行）

1. **取指窗口冻结**：`rip ∈ [0x141a352d0, 0x141a35350]` 时立刻挂起 → 读 IP 与 12 字节指令 → 落盘（v11 已实现）
2. **授权指针盯梢**：任一寄存器落进 `0x1406B3300–0x1406B3B00` → 判为授权路径，抓 ctx + 栈现场（v12 已实现）
3. **差分实验**：写/不写 `HKCU\Software\Eassos\DiskGenius\LicenseInfo`（假 user/email/regcode/regver/VerifyDate）两次运行，比对 ctx/表/RIP 直方图 → 锁定授权 VM 实例
4. **handler 语义提取**：unicorn 沙箱逐 handler 模拟 + ctx 页 diff → 每 opcode 的（读字段、写寄存器、IP 步长、核心运算）
5. **线性解码**：用 #1 的指令样本 + #4 的语义还原虚拟化函数伪代码，定位 `regcode` 校验分支

## 5. 关键产物

- `artifact6/prot_t0_*.bin`：运行期解密内存（.vmp/.boot/enc1-4 共 10 段）
- `artifact82/`：同源 .vmp 解密副本 + `rip_hits.json`（派发器直方图）
- `artifact9/`：v9 采样 `hot_trace.json` + 19 页 `live_p*.bin`
- `winactions/dump_runtime.py`：运行期取证器（v12）
- `winactions/x86il_disasm.py`：字节码反汇编器（编码规则待接入 v12 样本）

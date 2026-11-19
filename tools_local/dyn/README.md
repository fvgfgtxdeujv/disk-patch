# tools_local/dyn —— 运行期动态取证工具（Wine / 本机，不走 Actions）

这一组脚本是「不依赖 GitHub Actions，在本机 Wine 里把加壳后的 DiskGenius 跑起来、
读运行期解密镜像、下断点、抓调用链、插 VM 桩」用的。

两条证据线分别在：

- `reports/REPORT_wine_auth_dynamic.md` —— 授权校验的行为实证（纯本地、key 字段触发、删除出口地址）
- `reports/REPORT_vmp_probe_20261119.md` —— VM 指令级探针（改派发表 + 记录桩 + 影子表回跳）

---

## 环境准备

```bash
# Wine 9.0 + Xvfb；prefix 用 win64
xvfb-run -s "-screen 0 1280x900x24" bash
```

启动目标**不要**用 `wine` 包装脚本（目标会变成孙进程，attach 不到），直接：

```bash
/usr/lib/wine/wine64 DiskGenius/DiskGenius.exe
```

---

## 脚本一览

### 镜像 / 内存

| 脚本 | 作用 |
|---|---|
| `dump_image.py` | 从运行中的进程把 `0x140000000` 起整块镜像 dump 下来（约 50MB），加壳程序静态全是密文，只有运行期才有明文 |
| `freeze_scan.py` | 冻结进程后按标记扫内存，定位字符串/结构所在区段 |
| `maps.py`（同目录外） | 打印目标进程的 maps，找 RWX 段与零洞 |

### 授权行为（黑盒 + 断点）

| 脚本 | 作用 |
|---|---|
| `trial.sh` / `ptest.py` | 最小复现：放一份 Options.ini 进去，看程序启动后认不认、删不删 |
| `keyprobe*.sh` / `variants.sh` / `lenprobe.sh` | key 输入契约二分：哪些形态会被判定为「注册数据」而进入校验分支 |
| `ktrace.sh` | 系统调用级跟踪，确认校验过程有没有对外网络 |
| `regtrace.sh` | Wine 注册表追踪，看 `Reg\license` 是读进来验还是当脏数据 |
| `strace_trial.sh` | 抓 unlink 的完整调用栈（定位「校验失败处理」出口） |
| `patch_verify.py` | 把删除出口打成空操作，验证「不删配置」这个判据成立 |
| `detail.sh` | 单次实验的细节落盘 |
| `bp_delete.py` / `bp_readkey.py` | 在删除封装 / INI key 读取处下断点，抓调用链 |
| `bp3.py` / `bp_rbp.py` / `hw_bp.py` | 沿 RBP 链回溯上层调用者；硬件执行断点（绕 int3 反调试） |

### VM 探针

| 脚本 | 作用 |
|---|---|
| `vmp_tracer.py` | 核心：在 `.vmp` 零洞里写记录桩 → 整张派发表指向它 → 桩里记 `[rbp+0xBC]` 与该地址 8 字节 → 影子表查回真 handler → `jmp rsi` 回原流程 |

```bash
python3 vmp_tracer.py --wait 4 --table 0x1421080ab --count 661 --seconds 6
```

输出 `vm_trace_local.txt`，每行 `IP bytes`。

---

## 踩过的坑（重跑前先看）

1. `ptrace` 的 `restype` 默认 `c_int`，64 位地址会被截成 `0x41cf832a`（少 `0x100000000`）。
2. int3 填充洞当断点没用：PE 异常分发会把 `EXCEPTION_BREAKPOINT` 吃掉，进程直接退。
3. 三张派发表（661 / 49 / 1096 项）只有 **661** 能安全改；49 和 1096 被非派发路径引用，钩了立刻停摆。
4. 记录桩里 `mov rsi,[r10+r15]` 必须是 `4F 8B 34 3A`；写成 `49 8B 34 47` 会变成 `[r15+rax*2]` 直接跑飞。
5. 记录区 / 计数器 / 影子表必须错开排布，否则影子表会盖掉计数器。
6. 零洞按 256KB 找是一无所获，本机最大只有 ~14.8KB，布局要精打细算。
7. 加壳程序代码在启动早期还没解密，早下的断点读到的是密文，要等初始化完再下。

---

## 已知未完成

探针能进 VM 热路径，但只记到 1 条，且 `[rbp+0xBC]` 是否等于 VM IP 尚未证实
（详见 `reports/REPORT_vmp_probe_20261119.md` §5.3 / §7）。下一步是在桩里同时记
`rbp` / `[rbp+0xBC]` / `[rbp+0xF5]`，与派发器 `0x141a35366` 现场比对。

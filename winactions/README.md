# 在 GitHub Actions 的 Windows runner 上抓 handler 表

不用 Frida、不用调试器 —— 只启动 DiskGenius，然后用 `ReadProcessMemory`
配合内存特征扫描，把 VM 上下文里的 handler 表整张读出来。

---

## 为什么不用 Frida / 调试器

DiskGenius 由 WinLicense/Themida 一类加壳保护，这类保护专门盯：

- 调试器：`IsDebuggerPresent`、PEB 标志、INT3 扫描、硬件断点寄存器
- 注入：`frida-agent.dll`、异常线程、`CreateRemoteThread`
- 虚拟机：CPUID hypervisor 位、VMware/Hyper-V 特征

GitHub 的 Windows runner 本身就是 Hyper-V 虚拟机，反虚拟化检测**很可能直接命中**。
所以这条路是「先试 Frida，八成碰壁」；而 `ReadProcessMemory` 通常不在拦截范围内
（保护主要防代码改写和调试，不是防读）。

---

## 流程

```
workflow_dispatch
  ├─ 装 Python + numpy
  ├─ 跑 local_selftest.py（扫描算法自检，不依赖 Windows）
  ├─ 从官网下 DiskGenius 绿色版 x64，解压找 DiskGenius.exe
  ├─ 启动它，轮询读内存，扫 VM 上下文
  │    └─ 失败则用 comsvcs.dll 抓 minidump 兜底
  └─ 上传 artifact: tables.json / dump.log / dg.dmp
```

## 安装包从哪来（三级回退）

1. **仓库里的 `vendor/*.zip`** —— 提交进仓库，最省事，Actions 直接用
2. **Actions cache** —— 首次跑完自动存，之后命中（`pkg_tag` 是缓存键，换版本要改）
3. **官网下载** —— 最后兜底

把包放进仓库（二选一）：

```bash
# Linux / macOS
bash vendor/fetch_vendor.sh
git add vendor/*.zip vendor/pin.txt && git commit -m "vendor: DiskGenius 6.2.0.1829" && git push
```

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File vendor\fetch_vendor.ps1
git add vendor/*.zip; git commit -m "vendor: DiskGenius 6.2.0.1829"; git push
```

`vendor/pin.txt` 里钉了 SHA256，脚本会校验；哈希不符会拒绝入库。

> 42MB 的单文件在 GitHub 100MB 限制内，普通 git 就能提交。
> 嫌仓库变胖就用 `git lfs track "vendor/*.zip"`。

## 怎么用

1. 建一个仓库（私有也行），把本目录、`vendor/` 和 `.github/workflows/dump-vm-tables.yml` 推上去。
2. 仓库 Settings → Actions → General → 允许 workflow 运行。
3. Actions → **dump-vm-tables** → Run workflow。
   - `dg_url` 留空用默认版本；**如果你手上的 dump 不是这个版本，把对应版本的压缩包地址填进去**
   - `seconds` 默认 60，程序启动慢就调大
4. 跑完下载 artifact `vm-tables`。

## 拿到 tables.json 之后

```bash
python merge_tables.py tables.json --out handlers.py --json handlers.json
```

`merge_tables.py` 会把每张表按「下标 = opcode」合并，自动判断是 8 位还是 16 位 opcode，
并报出多表冲突和别名（多个 opcode 指向同一 handler——这在 VM 里很常见）。

生成的 `handlers.py` 里的 `HANDLERS = {opcode: handler_va}`，直接喂给
`x86il_deobf_v2.py --batch` 就能逐条做语义提升。

---

## 版本必须对得上

静态分析用的 `DiskGenius_unpacked_vmp.bin` 是某个特定版本脱壳后的 `.vmp` 段，
`CODE_BASE = 0x140000000 + 0x1D34000`。

- 运行期抓表不依赖这个地址（扫的是内存特征），**换版本也能抓到表**；
- 但 `merge_tables.py` 里的 `CODE_BASE` 默认值是按这份 dump 定的，
  换版本要改 `--vmp-rva` 或直接看 `dump.log` 里打印的模块区间。

workflow 里会打印 exe 大小和模块区间，对不上就说明版本不同。

---

## 已知风险（照实写）

| 风险 | 表现 | 兜底 |
|---|---|---|
| 反虚拟机 | 进程启动即退，或行为异常 | 抓 minidump 离线分析 |
| 反内存读取 | `OpenProcess` 失败 | 降到 minidump 路径 |
| 需要交互 | 程序停在欢迎界面，VM 没跑 | 调大 `seconds`，或加 `--args` 打开镜像 |
| runner 无桌面 | GUI 起不来 | GitHub 的 Windows runner 有交互会话，一般没问题；真不行改用 `--pid` 附加 |
| 版本不符 | 表项指向的地址不在代码段，扫不到 | 换 `dg_url` |

**没在真机上验证过**：这份 workflow 是按 Windows API 和 Actions 的规矩写的，
本地（Linux）只验证了扫描算法（`local_selftest.py`）和 YAML 语法，**没有实际跑过 Actions**。

---

## 文件

| 文件 | 作用 |
|---|---|
| `dump_ctx.py` | 启动/附加进程，扫上下文，dump 表 |
| `local_selftest.py` | 扫描算法自检（跨平台，合成内存镜像） |
| `merge_tables.py` | tables.json → handlers.py |
| `../.github/workflows/dump-vm-tables.yml` | workflow 定义 |

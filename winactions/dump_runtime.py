# -*- coding: utf-8 -*-
"""
dump_runtime.py —— 运行期抓取 DiskGenius 的 X86IL VM 上下文（槽位无关版）

为什么重写 dump_ctx.py
----------------------
旧版硬编码了槽位（CTX_SLOTS = 0x4/0x8/0xF5/0x110/0x1F4），那对应的是
.vmp RVA=0x1D34000 那个构建。本次实查的官方包（RVA=0x19D4000）槽位是
0x70/0x73/0xBC/0x1E2，**完全不同**。0xF5 在两份里语义还相反（旧=表槽，
新=IP 槽）。结论：槽位每个构建重新分配，硬编码必错。

本版的判据不依赖任何槽号，只用两个自洽性指纹：

  指纹 A（表）：某地址起连续 N 项 qword 全部落在镜像可执行段，且不全相同
  指纹 B（字节流）：某地址起能按 `[u16 op][i32 len]` 线性走通 >= 40 步
                （op ∈ (0, 0x4000), len ∈ [6, 0x400]）

随机内存同时满足 B 的概率约等于 0，所以 B 的假阳率可以忽略。

定位 ctx 的三层
--------------
  L1 rbp  ：所有 handler 都以 rbp 为 ctx 基址（`mov rX, rbp; add rX, imm8`）
            SuspendThread + GetThreadContext 取 rbp，一次命中，最便宜最准
  L2 栈   ：线程栈顶若干 KB 内每个 qword 当候选（rbp 已回滚时兜底）
  L3 全内存：--deep 才开，扫所有堆区（最慢）

多轮采样还顺手给出两个判据：
  表在轮间不变 + IP 在轮间变化 => 确实是活着的 VM，不是碰巧的形状

用法
----
  python dump_runtime.py --exe "C:\\dg\\DiskGenius.exe" --seconds 60 --out tables.json
  python dump_runtime.py --pid 1234 --out tables.json
  python dump_runtime.py --selftest          # 跨平台自测，不碰目标程序
"""
import base64
import json
import os
import re
import struct
import sys
import time

# ---------------------------------------------------------------- 控制台

def _utf8_console():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass


_utf8_console()

# ---------------------------------------------------------------- 判据常量

MIN_WALK_STEPS = 40        # 字节流至少走通这么多条指令才算 IP
WALK_MAX_OP = 0x4000       # opcode 上界（16 位但实际远小于 4096）
WALK_MIN_LEN = 6           # 头长度：u16 opcode + i32 len
WALK_MAX_LEN = 0x400
TABLE_ITEMS = 48           # 表至少这么多项连续落在代码段
TABLE_HIT_FRAC = 0.9       # 允许尾部越界一点
CTX_SCAN_SPAN = 0x600      # ctx 逐字节扫的范围
STACK_SCAN_DEPTH = 0x40000  # L2 扫栈深度


def in_ranges(v, ranges):
    for lo, hi in ranges:
        if lo <= v < hi:
            return True
    return False


# ---------------------------------------------------------------- 核心算法
# 这一整段不依赖 Windows，Linux 上也能跑（--selftest 用它）

def walk_stream(view, ip, max_steps=MIN_WALK_STEPS, max_op=WALK_MAX_OP,
                max_len=WALK_MAX_LEN):
    """
    按 `[u16 opcode][i32 len]` 线性走字节流。len 含这 6 字节头。
    返回 (步数, 走过的字节数, opcode 序列)。
    """
    steps = 0
    off = ip
    ops = []
    limit = ip + 0x200000          # 防御性上限，别被伪造的 len 拖死
    while steps < max_steps and off + WALK_MIN_LEN <= limit:
        b = view.block(off, WALK_MIN_LEN)
        if b is None or len(b) < WALK_MIN_LEN:
            break
        op = b[0] | (b[1] << 8)
        ln = struct.unpack_from('<i', b, 2)[0]
        if not (0 < op < max_op) or not (WALK_MIN_LEN <= ln <= max_len):
            break
        ops.append(op)
        off += ln
        steps += 1
    return steps, off - ip, ops


def table_probe(view, ptr, ranges, n=TABLE_ITEMS, guard=None):
    """
    指纹 A：ptr 起 n 个 qword 是否构成 handler 表。
    返回 (是否像表, 读到的 qword 列表)。

    guard = 保护段范围（.vmp/.boot）。真 VM 表的项几乎全部落在保护段；
    普通 C++ 对象数组的 vtable 指针落在原生 .text —— 用 guard 把后者砍掉
    （Actions 实测：不加这条会抓到 0x140641xxx 的 3 项假表，score 84）。
    """
    buf = view.block(ptr, n * 8)
    if buf is None or len(buf) < 16:
        return False, []
    cnt = len(buf) // 8
    vals = list(struct.unpack_from('<%dQ' % cnt, buf, 0))
    hit = sum(1 for v in vals if in_ranges(v, ranges))
    frac = hit / cnt
    uniq = len(set(vals))
    ok = frac >= TABLE_HIT_FRAC and uniq >= 4 and cnt >= 8
    if ok and guard:
        ghit = sum(1 for v in vals if in_ranges(v, guard))
        if ghit < max(4, hit * 0.5):
            ok = False
    return ok, vals


def scan_ctx(view, ctx, ranges, span=CTX_SCAN_SPAN, guard=None):
    """
    逐字节扫 ctx 窗口，自动发现「表槽」与「IP 槽」。
    返回 (tables, ips)。
    """
    buf = view.block(ctx, span + 8)
    tables, ips = [], []
    if buf is None:
        return tables, ips
    limit = min(span, len(buf) - 8)
    cache = {}                      # 同一个指针只探测一次，但槽位照记
    for s in range(0, limit + 1):
        v = struct.unpack_from('<Q', buf, s)[0]
        if v < 0x10000:
            continue
        if v in cache:
            kind = cache[v]
            if kind == 'table':
                tables.append({'slot': s, 'va': v})
            elif kind == 'ip':
                ips.append({'slot': s, 'va': v})
            continue
        ok, _ = table_probe(view, v, ranges, guard=guard)
        if ok:
            cache[v] = 'table'
            tables.append({'slot': s, 'va': v})
            continue
        steps, tot, ops = walk_stream(view, v)
        if steps >= MIN_WALK_STEPS:
            cache[v] = 'ip'
            ips.append({'slot': s, 'va': v, 'steps': steps, 'nbytes': tot,
                        'maxop': max(ops), 'nuniq': len(set(ops))})
            continue
        cache[v] = None
    return tables, ips


def ctx_score(tables, ips):
    """有 IP 才是真 ctx（权重 30）；表每张 6 分。没有 IP 的 ctx 不可信"""
    return len(ips) * 30 + len(tables) * 6


# ---------------------------------------------------------------- 抽象内存视图

class BytesView(object):
    """测试用：从 dict{va: bytes} 取数据，跨 chunk 自动拼接"""

    def __init__(self, chunks):
        # chunks: [(va, bytes)]
        self.chunks = sorted(chunks, key=lambda x: x[0])

    def block(self, va, n):
        out = bytearray()
        cur = va
        while len(out) < n:
            hit = None
            for base, data in self.chunks:
                if base <= cur < base + len(data):
                    hit = (base, data)
                    break
            if hit is None:
                return bytes(out) if out else None
            base, data = hit
            take = min(n - len(out), base + len(data) - cur)
            out += data[cur - base:cur - base + take]
            cur += take
        return bytes(out)


# ---------------------------------------------------------------- Windows 层
if os.name == 'nt':
    import ctypes
    from ctypes import wintypes as wt

    k32 = ctypes.WinDLL('kernel32', use_last_error=True)

    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    THREAD_GET_CONTEXT = 0x0008
    THREAD_QUERY_INFORMATION = 0x0040
    THREAD_SUSPEND_RESUME = 0x0002
    MEM_COMMIT = 0x1000
    PAGE_GUARD_ = 0x100
    PAGE_READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
    TH32CS_SNAPMODULE = 0x00000008
    TH32CS_SNAPMODULE32 = 0x00000010
    TH32CS_SNAPTHREAD = 0x00000004
    CONTEXT_ALL_AMD64 = 0x0010001F
    CTX_RSP, CTX_RBP, CTX_RIP, CTX_FLAGS = 0x98, 0xA0, 0xF8, 0x30
    CONTEXT_SIZE = 0x4D0

    class MBI(ctypes.Structure):
        _fields_ = [('BaseAddress', ctypes.c_void_p),
                    ('AllocationBase', ctypes.c_void_p),
                    ('AllocationProtect', wt.DWORD),
                    ('PartitionId', wt.WORD),
                    ('RegionSize', ctypes.c_size_t),
                    ('State', wt.DWORD),
                    ('Protect', wt.DWORD),
                    ('Type', wt.DWORD)]

    class MODULEENTRY32(ctypes.Structure):
        _fields_ = [('dwSize', wt.DWORD), ('th32ModuleID', wt.DWORD),
                    ('th32ProcessID', wt.DWORD), ('GlblcntUsage', wt.DWORD),
                    ('ProccntUsage', wt.DWORD), ('modBaseAddr', ctypes.c_void_p),
                    ('modBaseSize', wt.DWORD), ('hModule', wt.HMODULE),
                    ('szModule', wt.CHAR * 256), ('szExePath', wt.CHAR * 260)]

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [('dwSize', wt.DWORD), ('cntUsage', wt.DWORD),
                    ('th32ThreadID', wt.DWORD), ('th32OwnerProcessID', wt.DWORD),
                    ('tpBasePri', ctypes.c_long), ('tpDeltaPri', ctypes.c_long),
                    ('dwFlags', wt.DWORD)]

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [('cbSize', wt.DWORD), ('fMask', ctypes.c_ulong),
                    ('hwnd', wt.HWND), ('lpVerb', wt.LPCWSTR),
                    ('lpFile', wt.LPCWSTR), ('lpParameters', wt.LPCWSTR),
                    ('lpDirectory', wt.LPCWSTR), ('nShow', ctypes.c_int),
                    ('hInstApp', wt.HINSTANCE), ('lpIDList', ctypes.c_void_p),
                    ('lpClass', wt.LPCWSTR), ('hkeyClass', wt.HKEY),
                    ('dwHotKey', wt.DWORD), ('hIcon', wt.HANDLE),
                    ('hProcess', wt.HANDLE)]

    shell32 = ctypes.WinDLL('shell32', use_last_error=True)

    class WinView(object):
        """页缓存的内存视图。每轮快照新建一个，避免读到上一轮的旧页。"""

        def __init__(self, h, page=0x1000):
            self.h = h
            self.page = page
            self.pages = {}
            self._regions = None

        # -- 区域表（懒加载）
        def regions(self):
            if self._regions is None:
                self._regions = enum_regions(self.h)
            return self._regions

        def readable(self, va, n=1):
            for base, size, _prot in self.regions():
                if base <= va and va + n <= base + size:
                    return True
            return False

        def _page(self, pno):
            if pno in self.pages:
                return self.pages[pno]
            va = pno * self.page
            buf = ctypes.create_string_buffer(self.page)
            got = ctypes.c_size_t(0)
            ok = k32.ReadProcessMemory(self.h, ctypes.c_void_p(va), buf,
                                       self.page, ctypes.byref(got))
            data = bytes(buf.raw[:got.value]) if ok and got.value else None
            self.pages[pno] = data
            return data

        def block(self, va, n):
            if n <= 0:
                return b''
            out = bytearray()
            cur = va
            while len(out) < n:
                pno = cur // self.page
                off = cur - pno * self.page
                d = self._page(pno)
                if d is None or off >= len(d):
                    return bytes(out) if out else None
                take = min(n - len(out), len(d) - off)
                out += d[off:off + take]
                cur += take
            return bytes(out)

    def is_admin():
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def open_process(pid):
        h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not h:
            raise OSError('OpenProcess 失败，错误码 %d（需要管理员）'
                          % ctypes.get_last_error())
        return h

    def enum_regions(h, limit=None):
        addr = 0x10000
        mbi = MBI()
        out = []
        seen = 0
        while seen < (1 << 21):
            seen += 1
            if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                                      ctypes.sizeof(mbi)):
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize or 0
            if size <= 0:
                break
            prot = mbi.Protect
            if (mbi.State == MEM_COMMIT and not (prot & PAGE_GUARD_)
                    and (prot & 0xFF) in PAGE_READABLE):
                out.append((base, size, prot))
                if limit and len(out) >= limit:
                    break
            nxt = base + size
            if nxt <= addr:
                break
            addr = nxt
        return out

    def list_modules(pid):
        snap = k32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        if snap in (0, -1):
            return []
        me = MODULEENTRY32()
        me.dwSize = ctypes.sizeof(me)
        out = []
        try:
            ok = k32.Module32First(snap, ctypes.byref(me))
            while ok:
                out.append((me.modBaseAddr or 0, me.modBaseSize or 0,
                            me.szModule.decode('latin1', 'replace')
                            if isinstance(me.szModule, bytes) else me.szModule))
                ok = k32.Module32Next(snap, ctypes.byref(me))
        finally:
            k32.CloseHandle(snap)
        return out

    def pe_layout(buf):
        """解析 PE：镜像基址、SizeOfImage、所有可执行段（作为 code ranges）"""
        if len(buf) < 0x200 or buf[:2] != b'MZ':
            return None
        e = struct.unpack_from('<I', buf, 0x3C)[0]
        if e + 0x108 > len(buf) or buf[e:e + 4] != b'PE\0\0':
            return None
        nsec = struct.unpack_from('<H', buf, e + 6)[0]
        opt_size = struct.unpack_from('<H', buf, e + 20)[0]
        opt = e + 24
        magic = struct.unpack_from('<H', buf, opt)[0]
        image_base = struct.unpack_from('<Q' if magic == 0x20b else '<I',
                                        buf, opt + 0x18)[0]
        size_of_image = struct.unpack_from('<I', buf, opt + 0x38)[0]
        so = opt + opt_size
        secs = []
        for i in range(nsec):
            o = so + i * 40
            if o + 40 > len(buf):
                break
            name = buf[o:o + 8].rstrip(b'\0').decode('latin1', 'replace')
            vsize = struct.unpack_from('<I', buf, o + 8)[0]
            rva = struct.unpack_from('<I', buf, o + 12)[0]
            chars = struct.unpack_from('<I', buf, o + 36)[0]
            secs.append({'name': name, 'rva': rva, 'vsize': vsize,
                         'exec': bool(chars & 0x20000000)})
        return {'image_base': image_base, 'size_of_image': size_of_image,
                'sections': secs}

    def read_pe_layout(h, base):
        buf = ctypes.create_string_buffer(0x2000)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, 0x2000,
                                     ctypes.byref(got)) or got.value < 0x200:
            return None
        return pe_layout(buf.raw[:got.value])

    def thread_contexts(pid):
        """[(tid, rip, rsp, rbp)]，逐个 suspend 拿上下文"""
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snap in (0, -1):
            return []
        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(te)
        out = []
        try:
            ok = k32.Thread32First(snap, ctypes.byref(te))
            while ok:
                if te.th32OwnerProcessID == pid:
                    tid = te.th32ThreadID
                    ht = k32.OpenThread(THREAD_GET_CONTEXT |
                                        THREAD_SUSPEND_RESUME |
                                        THREAD_QUERY_INFORMATION, False, tid)
                    if ht:
                        try:
                            k32.SuspendThread(ht)
                            buf = ctypes.create_string_buffer(CONTEXT_SIZE)
                            struct.pack_into('<I', buf, CTX_FLAGS,
                                             CONTEXT_ALL_AMD64)
                            if k32.GetThreadContext(ht, buf):
                                out.append((tid,
                                            struct.unpack_from('<Q', buf, CTX_RIP)[0],
                                            struct.unpack_from('<Q', buf, CTX_RSP)[0],
                                            struct.unpack_from('<Q', buf, CTX_RBP)[0]))
                        finally:
                            k32.ResumeThread(ht)
                            k32.CloseHandle(ht)
                ok = k32.Thread32Next(snap, ctypes.byref(te))
        finally:
            k32.CloseHandle(snap)
        return out

    def launch(exe, args='', wait=0.0):
        """requireAdministrator 的 exe：先试 Popen，740 走 runas"""
        exe = os.path.abspath(exe)
        cwd = os.path.dirname(exe) or None
        try:
            p = subprocess_popen(exe, args, cwd)
            time.sleep(wait)
            return p
        except OSError as e:
            if getattr(e, 'winerror', None) != 740 and \
                    'elevation' not in str(e).lower():
                raise
            print('[*] 直接启动被拒（需要管理员），改用 runas')
        sei = SHELLEXECUTEINFOW()
        sei.cbSize = ctypes.sizeof(sei)
        sei.fMask = 0x00000040          # SEE_MASK_NOCLOSEPROCESS
        sei.lpVerb = 'runas'
        sei.lpFile = exe
        sei.lpParameters = args or None
        sei.lpDirectory = cwd
        sei.nShow = 1
        if not shell32.ShellExecuteExW(ctypes.byref(sei)):
            raise OSError('ShellExecuteExW(runas) 失败，错误码 %d'
                          % ctypes.get_last_error())
        pid = k32.GetProcessId(sei.hProcess) if sei.hProcess else 0
        if sei.hProcess:
            k32.CloseHandle(sei.hProcess)
        if not pid:
            raise OSError('提权启动后拿不到 pid')
        time.sleep(wait)
        return pid

    def subprocess_popen(exe, args, cwd):
        import subprocess
        return subprocess.Popen([exe] + ([args] if args else []), cwd=cwd)

    def read_mem(h, va, n):
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, n,
                                   ctypes.byref(got))
        return bytes(buf.raw[:got.value]) if ok and got.value else None

    def read_mem_safe(h, va, n, chunk=0x100000):
        """整段读，跨不可读页时退化为逐页（读不到的页填 0）"""
        out = bytearray()
        off = 0
        while off < n:
            c = min(chunk, n - off)
            b = read_mem(h, va + off, c)
            if b is None or len(b) < c:
                # 逐页兜底
                for p in range(off, off + c, 0x1000):
                    pn = min(0x1000, n - p)
                    pb = read_mem(h, va + p, pn)
                    out += pb if pb else b'\x00' * pn
                off += c
            else:
                out += b
                off += len(b)
        return bytes(out)


# ---------------------------------------------------------------- 采样

def code_ranges_of(h, base):
    """主模块所有可执行段 → [(lo, hi)]"""
    lay = read_pe_layout(h, base)
    if not lay:
        return [], None
    ranges = []
    for s in lay['sections']:
        if s['exec'] and s['vsize']:
            ranges.append((base + s['rva'], base + s['rva'] + s['vsize']))
    return ranges, lay


def quick_prefilter(view, va, ranges, span=0x100):
    """
    廉价预筛：ctx 窗口里至少要有 1 个 qword 落在可执行段。
    没有的话根本不用做完整 scan_ctx（后者要读 0x600 + 可能的表/流页）。
    这一层把栈扫描从「13 万次完整探测」降到「13 万次 256B 读」。
    """
    buf = view.block(va, span)
    if not buf:
        return False
    for s in range(0, len(buf) - 8, 8):
        if in_ranges(struct.unpack_from('<Q', buf, s)[0], ranges):
            return True
    return False


def quick_prefilter(view, va, ranges, span=0x100, guard=None):
    """
    廉价预筛：ctx 窗口里至少要有 1 个 qword 落在可执行段。
    传 guard 时要求落在保护段（.vmp/.boot）——原生 .text 的指针直接排除。
    这一层把栈扫描从「13 万次完整探测」降到「13 万次 256B 读」。
    """
    buf = view.block(va, span)
    if not buf:
        return False
    tgt = guard or ranges
    for s in range(0, len(buf) - 8, 8):
        if in_ranges(struct.unpack_from('<Q', buf, s)[0], tgt):
            return True
    return False


def probe_ctx(view, ctx, ranges, guard=None):
    t, i = scan_ctx(view, ctx, ranges, guard=guard)
    return {'ctx': ctx, 'score': ctx_score(t, i), 'tables': t, 'ips': i}


def hot_phase(view, pid, ranges, guard, seconds, out_dir_ref=['.']):
    """
    v11：线程句柄缓存 + 高速 GetThreadContext 采样（目标 ~7k 轮/秒）。
    rbp 落保护段 => VM 正在跑。对 ctx 的 IP 候选槽做「派发器规则」验证：
      op = u16@IP+7, rel = i32@IP, next = IP+rel
    只有解码成立的样本才落盘（指令字节只在取指瞬间是明文）。
    """
    trace = []
    pages = set()
    MAX_PAGES = 96
    WIN = 0x4000
    IP_SLOTS = [0xBC, 0x73, 0x120, 0x70]
    TABLE_SLOTS = [0xF5, 0xC4, 0x36, 0x5B, 0xB9]
    DISP = [(0x141a352d0, 0x141a35350)]       # 已知派发器窗口（实例 B）
    rip_hits = {}
    handles = []

    def refresh():
        for _tid, h in handles:
            try:
                k32.CloseHandle(h)
            except Exception:
                pass
        del handles[:]
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snap in (0, -1):
            return
        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(te)
        try:
            ok = k32.Thread32First(snap, ctypes.byref(te))
            while ok:
                if te.th32OwnerProcessID == pid:
                    h = k32.OpenThread(THREAD_GET_CONTEXT |
                                       THREAD_SUSPEND_RESUME |
                                       THREAD_QUERY_INFORMATION, False,
                                       te.th32ThreadID)
                    if h:
                        handles.append((te.th32ThreadID, h))
                ok = k32.Thread32Next(snap, ctypes.byref(te))
        finally:
            k32.CloseHandle(snap)

    def grab(tid, h, rbp, rip):
        """命中：挂起线程 -> 读 ctx -> 逐槽解码 -> 落盘"""
        k32.SuspendThread(h)
        try:
            ctx_raw = read_mem(view.h, rbp, 0x200) or b''
            if len(ctx_raw) < 0x200:
                return
            for sl in IP_SLOTS:
                ptr = struct.unpack_from('<Q', ctx_raw, sl)[0]
                if not (0x140000000 <= ptr < 0x143000000):
                    continue
                raw = read_mem(view.h, ptr, 16) or b''
                if len(raw) < 12:
                    continue
                rel = struct.unpack_from('<i', raw, 0)[0]
                op = struct.unpack_from('<H', raw, 7)[0]
                if not (0 <= op < 0x2000 and 4 <= rel <= 0x1000):
                    continue
                # 强校验：table[op] 必须是指向模块内的代码指针
                hw = None
                for ts in TABLE_SLOTS:
                    if ts + 8 > len(ctx_raw):
                        continue
                    tb = struct.unpack_from('<Q', ctx_raw, ts)[0]
                    if not (0x140000000 <= tb < 0x143000000):
                        continue
                    ent = read_mem(view.h, tb + op * 8, 8) or b''
                    if len(ent) < 8:
                        continue
                    hd = struct.unpack_from('<Q', ent, 0)[0]
                    if any(lo <= hd < hi for lo, hi in ranges):
                        hw = hd
                        break
                if hw is None:
                    continue
                trace.append([round(time.time() - t0h, 6), tid, rbp, sl,
                              ptr, op, rel, raw[:12].hex(), rip, hw])
                pg = ptr & ~0xFFF
                if pg not in pages and len(pages) < MAX_PAGES:
                    pages.add(pg)
                    buf = read_mem(view.h, pg, WIN) or b''
                    with open(os.path.join(out_dir_ref[0],
                                           'live_p%x.bin' % pg), 'wb') as f:
                        f.write(buf)
                print('    [hit] ctx=%#x slot+%#x ip=%#x op=%d rel=%d '
                      'handler=%#x rip=%#x' % (rbp, sl, ptr, op, rel, hw, rip),
                      flush=True)
        except Exception as e:
            print('    [hit] 失败: %s' % e, flush=True)
        finally:
            k32.ResumeThread(h)

    # v12：授权字符串指针盯梢。enc1 解密后含 LicenseInfo/regcode/skey/VerifyDate/
    # OfflineReg.exe 等，VM 处理授权时寄存器必然指向这块池子 —— 命中即现场取证
    LIC_POOL = (0x1406b3300, 0x1406b3b00)
    lic_hits = []
    lic_files = set()

    def lic_watch(tid, h, cs):
        try:
            k32.SuspendThread(h)
        except Exception:
            return
        try:
            names = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
                     'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip')
            regs = {}
            for idx, nm in enumerate(names):
                regs[nm] = struct.unpack_from('<Q', cs, 0x78 + idx * 8)[0]
            rbp = regs['rbp']
            hit = {k: v for k, v in regs.items()
                   if LIC_POOL[0] <= v < LIC_POOL[1]}
            if not hit:
                return
            tag = len(lic_hits)
            lic_hits.append({'tid': tid, 't': round(time.time() - t0h, 5),
                             'regs': {k: hex(v) for k, v in regs.items()},
                             'hit': {k: hex(v) for k, v in hit.items()}})
            base = out_dir_ref[0]
            if rbp and (rbp not in lic_files):
                lic_files.add(rbp)
                for nm, va, sz in (('ctx', rbp, 0x400),
                                   ('stk', regs['rsp'] - 0x800, 0x2000)):
                    buf = read_mem(view.h, va, sz) or b''
                    with open(os.path.join(base, 'lic_%s_%x_%d.bin'
                                           % (nm, rbp, tag)), 'wb') as f:
                        f.write(buf)
            print('    [LIC] tid=%d rbp=%#x rip=%#x 命中 %s'
                  % (tid, rbp, regs['rip'],
                     {k: hex(v) for k, v in hit.items()}), flush=True)
        except Exception as e:
            print('    [LIC] 失败: %s' % e, flush=True)
        finally:
            k32.ResumeThread(h)

    refresh()
    t0h = time.time()
    t_end = t0h + seconds
    k = 0
    buf = ctypes.create_string_buffer(CONTEXT_SIZE)

    def _flush():
        try:
            with open(os.path.join(out_dir_ref[0], 'hot_trace.json'), 'w') as f:
                json.dump({'n_rounds': k, 'samples': trace,
                           'fmt': '[t,tid,ctx,slot,ip,op,rel,bytes12,rip,handler]'},
                          f)
            print('[*] hot_trace: %d 条可解码采样, %d 页, %d 轮'
                  % (len(trace), len(pages), k), flush=True)
        except Exception as e:
            print('[*] hot_trace 写失败: %s' % e, flush=True)
        if lic_hits:
            try:
                with open(os.path.join(out_dir_ref[0], 'lic_trace.json'), 'w') as f:
                    json.dump(lic_hits, f, indent=1)
                print('[*] 授权池命中 %d 次' % len(lic_hits), flush=True)
            except Exception as e:
                print('[*] lic_trace 写失败: %s' % e, flush=True)
        if rip_hits:
            top = sorted(rip_hits.items(), key=lambda x: -x[1])[:24]
            print('[*] VM 执行期 RIP 直方图（top24）:', flush=True)
            for a, c in top:
                print('    rip=%#x x%d' % (a, c), flush=True)
            try:
                with open(os.path.join(out_dir_ref[0], 'rip_hits.json'), 'w') as f:
                    json.dump({hex(a): c for a, c in sorted(
                        rip_hits.items(), key=lambda x: -x[1])[:200]}, f, indent=1)
            except Exception:
                pass

    focus = {}          # v13：已确认在跑 VM 的线程（只盯它们，采样率 ×100）
    while time.time() < t_end:
        k += 1
        if k % 2000 == 0:
            refresh()
            if focus:
                have = dict(handles)
                focus = {t: have[t] for t in focus if t in have}
        todo = ([(t, h) for t, h in handles if t in focus] if focus
                else handles)
        for tid, h in todo:
            struct.pack_into('<I', buf, CTX_FLAGS, CONTEXT_ALL_AMD64)
            if not k32.GetThreadContext(h, buf):
                continue
            rip = struct.unpack_from('<Q', buf, CTX_RIP)[0]
            rbp = struct.unpack_from('<Q', buf, CTX_RBP)[0]
            lic_watch(tid, h, buf)
            if rbp < 0x10000 or not any(lo <= rbp < hi for lo, hi in guard):
                continue
            rip_hits[rip] = rip_hits.get(rip, 0) + 1
            if tid not in focus:
                focus[tid] = h
            if any(lo <= rip < hi for lo, hi in DISP):
                grab(tid, h, rbp, rip)
                continue
            # 廉价验证：单次读 ctx，看 IP 候选槽能否解码出一条合法指令
            ctx_raw = read_mem(view.h, rbp, 0x200) or b''
            if len(ctx_raw) < 0x200:
                continue
            for sl in IP_SLOTS:
                ptr = struct.unpack_from('<Q', ctx_raw, sl)[0]
                if not (0x140000000 <= ptr < 0x143000000):
                    continue
                raw = read_mem(view.h, ptr, 16) or b''
                if len(raw) < 12:
                    continue
                rel = struct.unpack_from('<i', raw, 0)[0]
                op = struct.unpack_from('<H', raw, 7)[0]
                if 0 <= op < 0x2000 and 4 <= rel <= 0x1000:
                    grab(tid, h, rbp, rip)
                    break

    _flush()
    return [], k


def best_ctx(view, pid, ranges, deep=False, guard=None, hot=False):
    """L1 rbp → L2 栈 → L3 全内存。返回候选列表（已排序）"""
    cands = {}
    tried = set()
    stats = {'tried': 0, 'prefiltered': 0}

    def consider(va, how):
        if va in tried or va < 0x10000:
            return
        tried.add(va)
        stats['tried'] += 1
        if not quick_prefilter(view, va, ranges, guard=guard):
            return
        stats['prefiltered'] += 1
        r = probe_ctx(view, va, ranges, guard)
        if r['score'] > 0:
            r['how'] = how
            cands[va] = r

    ctxs = thread_contexts(pid)

    # L1：rbp（所有 handler 都以 rbp 为 ctx）
    for tid, rip, rsp, rbp in ctxs:
        consider(rbp, 'rbp:t%d' % tid)

    if hot:
        return sorted(cands.values(), key=lambda x: -x['score'])

    # L2：栈（rbp 已回滚时兜底）
    if not cands:
        print('[*] rbp 未命中，扫栈（%d 个线程）' % len(ctxs))
        for tid, rip, rsp, rbp in ctxs:
            if rsp < 0x10000:
                continue
            for chunk_off in range(0, STACK_SCAN_DEPTH, 0x8000):
                buf = view.block(rsp + chunk_off, 0x8000)
                if not buf:
                    break
                for o in range(0, len(buf) - 8, 8):
                    consider(struct.unpack_from('<Q', buf, o)[0],
                             'stack:rsp+%#x' % (chunk_off + o))

    # L3：全内存（--deep）
    if not cands and deep:
        print('[*] 栈也没命中，全内存扫（慢）')
        for base, size, _prot in enum_regions(view.h):
            done = 0
            while done < size:
                n = min(8 << 20, size - done) & ~7
                if n <= 0:
                    break
                buf = view.block(base + done, n)
                if not buf:
                    break
                for o in range(0, len(buf) - 8, 8):
                    consider(struct.unpack_from('<Q', buf, o)[0], 'heap')
                done += n

    if stats['tried']:
        print('   预筛: %d 候选 -> %d 通过 -> %d 命中'
              % (stats['tried'], stats['prefiltered'], len(cands)))
    return sorted(cands.values(), key=lambda x: -x['score'])



def dump_round(view, cand, ranges, want_bytes=256 << 10):
    """把一张/多张表整读，IP 字节流整读"""
    out = {'ctx': hex(cand['ctx']), 'score': cand['score'],
           'how': cand.get('how'), 'tables': {}, 'streams': {}}

    for t in cand['tables']:
        ptr = t['va']
        vals = []
        zeros = 0                     # 稀疏表允许 0 项，连续 4 个无效才断
        for i in range(65536):
            b = view.block(ptr + i * 8, 8)
            if not b or len(b) < 8:
                break
            v = struct.unpack('<Q', b)[0]
            if v == 0 or not in_ranges(v, ranges):
                zeros += 1
                if zeros >= 4:
                    break
                continue
            zeros = 0
            vals.append(v)
        if vals:
            key = '0x%X' % t['slot']
            out['tables'][key] = {'table_va': hex(ptr), 'entries': vals}

    for ip in cand['ips']:
        ptr = ip['va']
        buf = view.block(ptr, want_bytes) or b''
        steps, tot, ops = walk_stream(view, ptr, max_steps=65536)
        key = '0x%X' % ip['slot']
        out['streams'][key] = {'ip': hex(ptr), 'walk_steps': steps,
                               'walk_bytes': tot, 'ophist': _op_hist(ops),
                               'b64': base64.b64encode(buf).decode('ascii')}

    # ctx 原文（供离线复查槽位布局）
    raw = view.block(cand['ctx'], 0x800) or b''
    out['ctx_b64'] = base64.b64encode(raw).decode('ascii')
    return out


def _op_hist(ops, top=12):
    if not ops:
        return {}
    c = {}
    for o in ops:
        c[o] = c.get(o, 0) + 1
    return {hex(k): v for k, v in sorted(c.items(), key=lambda x: -x[1])[:top]}


# ---------------------------------------------------------------- 保护段整段 dump
# v3 的教训：三轮全假阳性（表项 100% 落原生 .text、ctx 窗口 51/2048 字节非零）。
# 与其继续猜 ctx 槽位，不如直接把非原生可执行段整段搬回来——运行期 VM 把
# 密文解密后写回原节，与静态脱壳产物 diff 即可直接拿到解密区（表+字节流）。

def collect_protected(h, dump_list):
    """dump_list: [(lo, hi)]，返回 {lo: bytes}"""
    out = {}
    for lo, hi in dump_list:
        size = hi - lo
        if not (0 < size <= (256 << 20)):
            continue
        out[lo] = read_mem_safe(h, lo, size)
    return out


def save_protected(data_map, tag, out_dir, ref_map=None):
    """写盘；ref_map 给定时跳过内容相同的段（省 artifact 体积）"""
    for lo, data in sorted(data_map.items()):
        if ref_map is not None and ref_map.get(lo) == data:
            continue
        path = os.path.join(out_dir, 'prot_%s_%x.bin' % (tag, lo))
        with open(path, 'wb') as f:
            f.write(data)
        print('    prot dump: %#x (%#x B) -> %s'
              % (lo, len(data), os.path.basename(path)), flush=True)


def save_rbp_sites(view, hits, out_dir, tag, n=0x1000):
    seen = set()
    for va, r in hits:
        if va in seen:
            continue
        seen.add(va)
        raw = view.block(va, n) or b''
        path = os.path.join(out_dir, 'rbp_%s_%x.bin' % (tag, va))
        with open(path, 'wb') as f:
            f.write(raw)
        print('    rbp site dump: %#x (%d B 非零 %d)'
              % (va, len(raw), sum(1 for b in raw if b)), flush=True)


# ---------------------------------------------------------------- 自测（跨平台）

def selftest():
    """用合成内存验证两个指纹：该命中的命中，不该命中的不误报"""
    # 造一个假镜像：code 段 0x1419D4000 .. +0x10000，里面全是 nop 填充
    CODE_LO, CODE_HI = 0x1419D4000, 0x1419D5000
    code = bytes(range(256)) * 0x100        # 0x10000 字节
    ranges = [(CODE_LO, CODE_HI)]

    # 造表：0x40 项，全部指向 code 段内 16 字节对齐地址
    handlers = [CODE_LO + 0x100 + i * 16 for i in range(0x40)]
    table = struct.pack('<%dQ' % len(handlers), *handlers)
    TABLE_VA = 0x5000000

    # 造字节流：64 条指令，opcode 递增，len 递增（都在合法域内）
    stream = b''
    for i in range(64):
        stream += struct.pack('<Hi', 0x100 + i, 6 + (i % 8)) + b'\xAA' * (i % 8)
    STREAM_VA = 0x5001000

    # 造 ctx：0x37 处放表指针，0x73 处放 IP（故意用非 8 字节对齐的槽位，
    #          模拟真实样本里 0x36/0x5B/0xF5 这种奇数槽）
    ctx = bytearray(0x800)
    struct.pack_into('<Q', ctx, 0x37, TABLE_VA)
    struct.pack_into('<Q', ctx, 0x73, STREAM_VA)
    struct.pack_into('<Q', ctx, 0x1E2, CODE_LO + 0x108)     # 干扰：单条指令地址
    CTX_VA = 0x5002000

    # 干扰块：随机字节，不应被误判
    noise = bytes((i * 37 + 11) & 0xFF for i in range(0x2000))
    NOISE_VA = 0x5003000

    view = BytesView([(CODE_LO, code), (TABLE_VA, table), (STREAM_VA, stream),
                      (CTX_VA, bytes(ctx)), (NOISE_VA, noise)])

    fails = []

    steps, tot, ops = walk_stream(view, STREAM_VA, max_steps=100)
    if steps != 64:
        fails.append('walk_stream 应走 64 步，实际 %d' % steps)
    print('  walk_stream: %d 步 / %d 字节 (期望 64 步)' % (steps, tot))

    ok, vals = table_probe(view, TABLE_VA, ranges)
    print('  table_probe(真表): %s，%d 项' % (ok, len(vals)))
    if not ok:
        fails.append('真表未被识别')

    ok2, _ = table_probe(view, NOISE_VA, ranges)
    print('  table_probe(噪声): %s (期望 False)' % ok2)
    if ok2:
        fails.append('噪声被误判成表')

    s2, _, _ = walk_stream(view, NOISE_VA, max_steps=100)
    print('  walk_stream(噪声): %d 步 (期望 <40)' % s2)
    if s2 >= MIN_WALK_STEPS:
        fails.append('噪声字节流被误判')

    tables, ips = scan_ctx(view, CTX_VA, ranges)
    print('  scan_ctx: 表槽 %s' % [hex(t['slot']) for t in tables])
    print('  scan_ctx: IP 槽 %s' % [hex(i['slot']) for i in ips])
    if not any(t['slot'] == 0x37 for t in tables):
        fails.append('未发现 0x37 的表槽')
    if not any(i['slot'] == 0x73 for i in ips):
        fails.append('未发现 0x73 的 IP 槽')

    # 全零 ctx 不该有任何命中
    zero = BytesView([(0x6000000, b'\x00' * 0x800)])
    t0, i0 = scan_ctx(zero, 0x6000000, ranges)
    if t0 or i0:
        fails.append('全零 ctx 产生误报')

    # guard 过滤：Actions 实测的假阳性是「表项全落在原生 .text」
    # —— guard（保护段）传入后必须被拒
    NAT_LO, NAT_HI = 0x144000000, 0x14401000
    native = bytes(range(256)) * 0x100
    nat_table_va = 0x5100000
    nat_handlers = [NAT_LO + 0x100 + i * 16 for i in range(0x40)]
    view3 = BytesView([(NAT_LO, native), (nat_table_va,
                     struct.pack('<%dQ' % len(nat_handlers), *nat_handlers)),
                      (TABLE_VA, table), (CODE_LO, code)])
    ranges2 = [(NAT_LO, NAT_HI), (CODE_LO, CODE_HI)]
    guard2 = [(CODE_LO, CODE_HI)]                 # guard = ranges[1:]
    ok3, _ = table_probe(view3, nat_table_va, ranges2, guard=guard2)
    print('  table_probe(原生段假表+guard): %s (期望 False)' % ok3)
    if ok3:
        fails.append('guard 没有拦住原生段假表')
    ok4, _ = table_probe(view3, TABLE_VA, ranges2, guard=guard2)
    print('  table_probe(保护段真表+guard): %s (期望 True)' % ok4)
    if not ok4:
        fails.append('guard 误杀了保护段真表')

    # v19 分档桩：结构自检（rel32 落点、末尾必须是 jmp rsi、各档长度）
    exp = {'bare': 6, 'counter': 126, 'copy': 151, 'full': 294}
    for mode in STUB_MODES:
        stub = _build_stub6(mode, 2, 0x100000100, 0x140000000, 0x142ff3000,
                            0x100000000, 0x100100000, 0x100001000)
        lo, hi = 0x100001000, 0x100001000 + len(stub)
        if len(stub) != exp[mode]:
            fails.append('stub6[%s] 长度 %d（期望 %d）' % (mode, len(stub), exp[mode]))
        if stub[-2:] != b'\xff\xe6':
            fails.append('stub6[%s] 末尾不是 jmp rsi' % mode)
        n_rel = 0
        for m in re.finditer(rb'\x0f[\x80-\x8f]', stub):
            i = m.start()
            if i + 6 > len(stub):
                continue
            rel = struct.unpack_from('<i', stub, i + 2)[0]
            tgt = 0x100001000 + i + 6 + rel
            n_rel += 1
            if not (lo <= tgt < hi):
                fails.append('stub6[%s] 第 %#x 处 jcc 跳到桩外 %#x' % (mode, i, tgt))
        print('  stub6[%-7s] %3d 字节，%d 处 rel32 全在桩内' % (mode, len(stub), n_rel))

    s7 = _build_stub7(2, 0x100000100, 0x140000000, 0x142ff3000,
                      0x100000000, 0x100100000)
    print('  stub7(跳转式): %d 字节，尾 %s' % (len(s7), s7[-2:].hex()))
    if len(s7) != 290:
        fails.append('stub7 长度异常: %d（期望 290）' % len(s7))
    if s7[-2:] != b'\xff\xe6':
        fails.append('stub7 末尾不是 jmp rsi')
    # find_cave：造一段带洞的假 .vmp
    fake = bytearray(b'\x90' * 0x200)
    fake[0x108:0x110] = b'\xcc' * 8
    off = find_cave(bytes(fake), 0x100)
    print('  find_cave(0x100) -> %s' % (hex(off) if off is not None else None))
    if off != 0x108:
        fails.append('find_cave 未找到 0x108 处的洞（实际 %s）' % off)

    # discover_tables：造 3 张表（间隔 5 的 qword 序列）+ 噪声
    seg = 0x1419D4000
    fake = bytearray(b'\x90' * 0x4000)
    for t, n in ((0x800, 40), (0xA00, 30)):
        for i in range(n):
            struct.pack_into('<Q', fake, t + i * 8, seg + 0x1000 + i * 5)
    found = discover_tables(bytes(fake), seg, seg, seg + 0x4000)
    print('  discover_tables -> %s' % [(hex(va - seg), n) for va, n in found])
    if [n for _, n in found] != [40, 30]:
        fails.append('discover_tables 长度不对: %s' % [n for _, n in found])

    s9 = _build_stub9(0x141e81f2a, 7, 0x10000100, 0x140000000, 0x142ff3000,
                      0x100000000, 0x100600000)
    print('  stub9(表项): %d 字节，尾 %s' % (len(s9), s9[-2:].hex()))
    if s9[-2:] != b'\xff\xe6' or b'\x48\xbe' not in s9[-12:]:
        fails.append('stub9 尾部不是 mov rsi,orig; jmp rsi')
    if len(s9) > STUB9_SZ:
        fails.append('stub9 超过槽长')

    s11 = _build_stub11(0x141e81f2a, 7, 0x10000100, 0x100100000, 0x1419d4000,
                        0x142780000, 0x100000000, 0x102200000)
    print('  stub11(明文自检): %d 字节，尾 %s' % (len(s11), s11[-2:].hex()))
    if len(s11) > STUB11_SZ:
        fails.append('stub11 超过槽长 %d' % len(s11))
    if s11[-2:] != b'\xff\xe6' or b'\x48\xbe' not in s11[-12:]:
        fails.append('stub11 尾部不是 mov rsi,orig; jmp rsi')
    if s11.count(b'\x48\xff\x00') != 2:
        fails.append('stub11 计数器个数异常（期望 2）')
    if b'\x49\xb9' in s11:
        fails.append('stub11 仍用 r9 做比较（会覆盖 [IP+8]）')

    if fails:
        print('\n[FAIL]')
        for f in fails:
            print('  - ' + f)
        return 1
    print('\n[OK] 全部通过')
    return 0


# ---------------------------------------------------------------- main

def sample_process(h, pid, seconds, rounds, interval, deep, guard=None,
                   hot_seconds=0.0, out_dir='.'):
    """对一个已打开的进程采样若干轮，返回 (rounds, base, lay)"""
    mods = list_modules(pid)
    print('[*] 模块列表: %s' % [(n, hex(b)) for b, s2, n in
                                sorted(mods, key=lambda x: x[0])])
    main_mod = None
    for b, s, n in sorted(mods, key=lambda x: x[0]):
        if 'diskgenius' in n.lower():
            main_mod = (b, s, n)
            break
    if not main_mod:
        print('[!] 找不到主模块，模块列表: %s' % mods[:5])
        return [], None, None

    base = main_mod[0]
    ranges, lay = code_ranges_of(h, base)
    if guard is None:
        # 保护段 = 除第一段（原生 .text）外的可执行段；没有就退化为全部
        guard = ranges[1:] if len(ranges) > 1 else ranges

    # ---- 授权/锁盘模块（LSlM.dll 等）也被 X86IL 虚拟化，其 VM 表落在本模块段 ----
    # 名字命中授权模块的，把它的可执行段并入 ranges，guard 加它的非第一段
    extra = [(b, n) for b, s, n in sorted(mods, key=lambda x: x[0])
             if any(k in n.lower() for k in ('lsim', 'license', 'wlreg', 'activ'))]
    for eb, en in extra:
        er, elay = code_ranges_of(h, eb)
        if not er:
            print('[*] 模块 %s base=%#x 无可执行段映射，跳过' % (en, eb))
            continue
        print('[*] 授权模块 %s base=%#x 可执行段: %s'
              % (en, eb, [('%#x-%#x' % r) for r in er]))
        for r in er:
            if r not in ranges:
                ranges.append(r)
        if len(er) > 1:
            for r in er[1:]:
                if r not in guard:
                    guard.append(r)

    print('[*] 主模块 %s base=%#x' % (main_mod[2], base))
    print('[*] 可执行段: %s' % [('%#x-%#x' % r) for r in ranges])
    print('[*] 保护段(表/流必须落在这里): %s'
          % [('%#x-%#x' % r) for r in guard])

    # v6：整段 dump 范围 = 除原生 .text/.rsrc/.boot 外的全部段。
    # 实证（v5 产物 diff）：VM 表（0x141da2b42 等 5 张）运行期被补上镜像基址，
    # 且加密无名节（RVA 0x62f000/0x7be000/0x9a3000）里有指向 VM 表的明文 RVA
    # （exe 文件偏移 0x9956f8/0x9c4d4a）——VM 字节码在这些节里，运行期解密。
    # .boot 已证 t0==t1 且全程密文，跳过省体积。
    dump_list = []
    if lay:
        skip_names = {'.rsrc', '.boot'}
        for i, sec in enumerate(lay['sections']):
            if sec['name'] in skip_names or not sec['vsize']:
                continue
            lo = base + sec['rva']
            if i == 0 and sec['exec']:
                continue          # 原生 .text
            hi = lo + sec['vsize']
            if (lo, hi) not in dump_list:
                dump_list.append((lo, hi))
    boot_rng = None
    if lay:
        for sec in lay['sections']:
            if sec['name'] == '.boot':
                boot_rng = (base + sec['rva'], base + sec['rva'] + sec['vsize'])
    for r in ranges[1:]:
        if r in dump_list or (boot_rng and not (r[1] <= boot_rng[0] or r[0] >= boot_rng[1])):
            continue
        dump_list.append(r)
    print('[*] dump 范围: %s' % [('%#x-%#x' % r) for r in dump_list])

    rounds_out = []

    # ---- hot 阶段：启动头几秒，VM 窗口，只盯线程寄存器 ----
    prot_t0 = None
    out_dir_ref = [out_dir]
    if hot_seconds > 0:
        view = WinView(h)
        t0 = time.time()
        hits, k = hot_phase(view, pid, ranges, guard, hot_seconds,
                            out_dir_ref)
        print('[*] hot 阶段 %d 轮 / %.1fs，命中 %d'
              % (k, time.time() - t0, len(hits)))
        for va, r in hits:
            if r['score'] >= 36 or r['ips']:       # 有 IP 或 2 表以上才 dump
                rd = dump_round(view, r, ranges)
                rd['t'] = round(time.time(), 3)
                rounds_out.append(rd)
        # ---- v5：不管 ctx 抓没抓到，证据先搬回来 ----
        if hits:
            save_rbp_sites(view, hits, out_dir, 't0')
        prot_t0 = collect_protected(h, dump_list)
        save_protected(prot_t0, 't0', out_dir)

    deadline = time.time() + seconds
    for k in range(rounds):
        if time.time() > deadline:
            break
        view = WinView(h)
        t0 = time.time()
        cands = best_ctx(view, pid, ranges, deep=deep, guard=guard)
        if not cands:
            print('[%d] 没扫到 ctx（%.1fs）' % (k, time.time() - t0))
            time.sleep(interval)
            continue
        top = cands[0]
        print('[%d] ctx=%#x score=%d how=%s 表=%d IP=%d (%.1fs)' % (
            k, top['ctx'], top['score'], top.get('how'),
            len(top['tables']), len(top['ips']), time.time() - t0))
        r = dump_round(view, top, ranges)
        r['t'] = round(time.time(), 3)
        rounds_out.append(r)
        if len(cands) > 1:
            print('     其他候选: %s' % [(hex(c['ctx']), c['score'])
                                        for c in cands[1:4]])
        time.sleep(interval)

    # ---- 采样结束再 dump 一次：对比 t0/t1 可看解密是否随时间扩散 ----
    if dump_list:
        prot_t1 = collect_protected(h, dump_list)
        save_protected(prot_t1, 't1', out_dir, ref_map=prot_t0)
    return rounds_out, base, lay



# ---------------------------------------------------------------- inline hook 追踪

HOOK_OFF = 0x1a353b0      # 派发器内 `mov rsi,[rcx]`（实例 B）
HOOK_BACK = 6             # 补回 5 字节后，回到 hook 点 +6


def _build_stub(count_va, buf_va, shell_va, back_va):
    """生成 hook 桩：记录 (ip, op, handler) 到 buf[count]，再补回被覆盖指令"""
    b = bytearray()
    b += bytes.fromhex('9c')                        # pushfq
    b += bytes.fromhex('5051525356')                # push rax rcx rdx rbx rsi
    b += bytes.fromhex('4150')                      # push r8
    b += bytes.fromhex('488b31')                    # mov rsi,[rcx]（原指令）
    b += b'\x48\xa1' + struct.pack('<Q', count_va)   # mov rax,[count]
    b += b'\x48\x3d' + struct.pack('<I', 2600000)    # cmp rax, MAX
    jae_pos = len(b)
    b += bytes.fromhex('0f83') + b'\x00\x00\x00\x00'  # jae end
    b += bytes.fromhex('4889c3')                    # mov rbx,rax
    b += bytes.fromhex('486bdb18')                  # imul rbx,rbx,24
    b += bytes.fromhex('49b8') + struct.pack('<Q', buf_va)   # mov r8,buf
    b += bytes.fromhex('4901d8')                    # add r8,rbx
    b += bytes.fromhex('488b95bc000000')            # mov rdx,[rbp+0xBC]
    b += bytes.fromhex('498910')                    # mov [r8],rdx
    b += bytes.fromhex('498bd7')                    # mov rdx,r15
    b += bytes.fromhex('48c1ea03')                  # shr rdx,3
    b += bytes.fromhex('49895008')                  # mov [r8+8],rdx
    b += bytes.fromhex('49897010')                  # mov [r8+0x10],rsi
    b += bytes.fromhex('48ffc0')                    # inc rax
    b += b'\x48\xa3' + struct.pack('<Q', count_va)   # mov [count],rax
    end_pos = len(b)
    b += bytes.fromhex('41585e5b5a5958')            # pop r8 rsi rbx rdx rcx rax
    b += bytes.fromhex('9d')                        # popfq
    b += bytes.fromhex('4889eb')                    # mov rbx,rbp（补回）
    b += b'\xe9' + struct.pack('<i', back_va - (shell_va + len(b) + 5))
    off = end_pos - (jae_pos + 6)
    b[jae_pos + 2:jae_pos + 6] = struct.pack('<i', off)
    return bytes(b)


def _build_stub2(count_va, buf_va, shell_va):
    """通用桩：挂在各派发器的 `jmp rsi` 上，记录 (ctx, op, handler) 后 jmp rsi"""
    b = bytearray()
    b += bytes.fromhex('9c')                       # pushfq
    b += bytes.fromhex('50515253')                 # push rax rcx rdx rbx
    b += bytes.fromhex('415041514152')             # push r8 r9 r10
    b += b'\x48\xa1' + struct.pack('<Q', count_va)  # mov rax,[count]
    b += b'\x48\x3d' + struct.pack('<I', 2600000)   # cmp rax, MAX
    jae_pos = len(b)
    b += bytes.fromhex('0f83') + b'\x00\x00\x00\x00'
    b += bytes.fromhex('4889c3')                   # mov rbx,rax
    b += bytes.fromhex('486bdb18')                 # imul rbx,rbx,24
    b += bytes.fromhex('49b8') + struct.pack('<Q', buf_va)   # mov r8,buf
    b += bytes.fromhex('4901d8')                   # add r8,rbx
    b += bytes.fromhex('4889ea')                   # mov rdx,rbp
    b += bytes.fromhex('498910')                   # mov [r8],rdx
    b += bytes.fromhex('498bd7')                   # mov rdx,r15
    b += bytes.fromhex('48c1ea03')                 # shr rdx,3
    b += bytes.fromhex('49895008')                 # mov [r8+8],rdx
    b += bytes.fromhex('49897010')                 # mov [r8+0x10],rsi
    b += bytes.fromhex('48ffc0')                   # inc rax
    b += b'\x48\xa3' + struct.pack('<Q', count_va)  # mov [count],rax
    end_pos = len(b)
    b += bytes.fromhex('415a41594158')             # pop r10 r9 r8
    b += bytes.fromhex('5b5a5958')                 # pop rbx rdx rcx rax
    b += bytes.fromhex('9d')                       # popfq
    b += bytes.fromhex('4883c408')                 # add rsp,8（丢弃 call 的返回地址）
    b += bytes.fromhex('ffe6')                     # jmp rsi
    off = end_pos - (jae_pos + 6)
    b[jae_pos + 2:jae_pos + 6] = struct.pack('<i', off)
    return bytes(b)


REC_SZ = 192          # v17 每条轨迹 192 字节（完整寄存器组 + ctx 槽 + IP 明文）
REC_MAX = 200000      # 200000*192 = 38.4 MB，落在 64MB 缓冲内
REG_ORDER = ['r15', 'r14', 'r13', 'r12', 'r11', 'r10', 'r9', 'r8',
             'rdi', 'rsi', 'rbp', 'rbx', 'rdx', 'rcx', 'rax', 'flags']


PROBE_BASE = 0x100     # 每站点 3 个探针：+0 进入 / +8 复制完 / +0x10 ctx 通过
PROBE_STRIDE = 0x18
STUB_MODES = ('bare', 'counter', 'copy', 'full')


def _build_stub6(mode, site_no, probe_base, lo_va, hi_va, count_va, buf_va, shell_va):
    """v19 分档桩：同一轮里 4 个站点各装一档，用来二分出「哪一步把进程打死」。
         bare    只有 add rsp,8; jmp rsi（等价于原指令，不落任何字节）
         counter 加 push 全寄存器 + 进入计数
         copy    再加 rep movsq 复制 128 字节寄存器组
         full    再加 ctx/IP 读取（v18 行为）
       记录格式（仅 copy/full 写）：192 字节/条，同 v17。"""
    b = bytearray()
    holes = []

    def jcc(op, kind):
        pos = len(b)
        b.extend(op + b'\x00\x00\x00\x00')
        holes.append((pos, kind))
        return pos

    def counter(va):
        b.extend(b'\x48\xb8' + struct.pack('<Q', va))
        b.extend(b'\x48\xff\x00')                      # inc qword [rax]

    if mode != 'bare':
        b += b'\x9c'
        b += bytes.fromhex('50515253555657')
        b += bytes.fromhex('4150415141524153415441554156')
        b += bytes.fromhex('4157')
        counter(probe_base)
        b += b'\x48\xa1' + struct.pack('<Q', count_va)   # mov rax,[count]
        b += bytes.fromhex('4889c3')                      # mov rbx,rax
        b += b'\x48\x3d' + struct.pack('<I', REC_MAX)
        jcc(bytes.fromhex('0f83'), 'out')
        b += bytes.fromhex('4869cbc0000000')              # imul rcx,rbx,192
        b += bytes.fromhex('48bf') + struct.pack('<Q', buf_va)
        b += bytes.fromhex('4801cf')                      # add rdi,rcx
        if mode in ('copy', 'full'):
            b += bytes.fromhex('4889e6')                  # mov rsi,rsp
            b += bytes.fromhex('fc')                      # cld
            b += bytes.fromhex('b910000000')              # mov ecx,16
            b += bytes.fromhex('f348a5')                  # rep movsq
            counter(probe_base + 8)
    if mode == 'full':
        b += bytes.fromhex('4889ea')                      # mov rdx,rbp
        b += b'\x49\xb9' + struct.pack('<Q', lo_va)
        b += bytes.fromhex('4c39ca')
        jcc(bytes.fromhex('0f82'), 'fin')
        b += b'\x49\xb9' + struct.pack('<Q', hi_va)
        b += bytes.fromhex('4c39ca')
        jcc(bytes.fromhex('0f83'), 'fin')
        b += bytes.fromhex('488b95bc000000')
        b += bytes.fromhex('488917')
        b += bytes.fromhex('488b95f5000000')
        b += bytes.fromhex('48895708')
        b += bytes.fromhex('488b17')
        b += b'\x49\xb9' + struct.pack('<Q', lo_va)
        b += bytes.fromhex('4c39ca')
        jcc(bytes.fromhex('0f82'), 'fin')
        b += bytes.fromhex('4c8d5210')
        b += b'\x49\xb9' + struct.pack('<Q', hi_va)
        b += bytes.fromhex('4d39ca')
        jcc(bytes.fromhex('0f87'), 'fin')
        counter(probe_base + 0x10)
        b += bytes.fromhex('4c8b0a')
        b += bytes.fromhex('4c894f10')
        b += bytes.fromhex('4c8b4a08')
        b += bytes.fromhex('4c894f18')
        fin_pos = len(b)
        b += bytes.fromhex('48c74720') + struct.pack('<I', site_no)
    elif mode in ('counter', 'copy'):
        fin_pos = len(b)
    if mode != 'bare':
        b += bytes.fromhex('488d4301')                    # lea rax,[rbx+1]
        b += b'\x48\xa3' + struct.pack('<Q', count_va)
        out_pos = len(b)
        b += bytes.fromhex('415f415e415d415c415b415a41594158')
        b += bytes.fromhex('5f5e5d5b5a5958')
        b += bytes.fromhex('9d')
        for pos, kind in holes:
            tgt = out_pos if kind == 'out' else fin_pos
            b[pos + 2:pos + 6] = struct.pack('<i', tgt - (pos + 6))
    b += bytes.fromhex('4883c408')                        # add rsp,8
    b += bytes.fromhex('ffe6')                            # jmp rsi
    return bytes(b)


def _build_stub7(site_no, probe_base, lo_va, hi_va, count_va, buf_va):
    """v21 跳转式桩（不占用栈、不吃 call 返回地址）：
       末尾是裸 `jmp rsi`，因此入口用 2 字节 `eb rel8` 短跳进来，
       绝不覆盖 `jmp rsi` 之后的任何指令。记录 192 字节/条。"""
    b = bytearray()
    holes = []

    def jcc(op, kind):
        pos = len(b)
        b.extend(op + b'\x00\x00\x00\x00')
        holes.append((pos, kind))
        return pos

    def counter(va):
        b.extend(b'\x48\xb8' + struct.pack('<Q', va))
        b.extend(b'\x48\xff\x00')

    b += b'\x9c'
    b += bytes.fromhex('50515253555657')
    b += bytes.fromhex('4150415141524153415441554156')
    b += bytes.fromhex('4157')
    counter(probe_base)
    b += b'\x48\xa1' + struct.pack('<Q', count_va)
    b += bytes.fromhex('4889c3')
    b += b'\x48\x3d' + struct.pack('<I', REC_MAX)
    jcc(bytes.fromhex('0f83'), 'out')
    b += bytes.fromhex('4869cbc0000000')                  # imul rcx,rbx,192
    b += bytes.fromhex('48bf') + struct.pack('<Q', buf_va)
    b += bytes.fromhex('4801cf')
    b += bytes.fromhex('4889e6')
    b += bytes.fromhex('fc')
    b += bytes.fromhex('b910000000')
    b += bytes.fromhex('f348a5')                          # rep movsq
    counter(probe_base + 8)
    b += bytes.fromhex('4889ea')
    b += b'\x49\xb9' + struct.pack('<Q', lo_va)
    b += bytes.fromhex('4c39ca')
    jcc(bytes.fromhex('0f82'), 'fin')
    b += b'\x49\xb9' + struct.pack('<Q', hi_va)
    b += bytes.fromhex('4c39ca')
    jcc(bytes.fromhex('0f83'), 'fin')
    b += bytes.fromhex('488b95bc000000')
    b += bytes.fromhex('488917')
    b += bytes.fromhex('488b95f5000000')
    b += bytes.fromhex('48895708')
    b += bytes.fromhex('488b17')
    b += b'\x49\xb9' + struct.pack('<Q', lo_va)
    b += bytes.fromhex('4c39ca')
    jcc(bytes.fromhex('0f82'), 'fin')
    b += bytes.fromhex('4c8d5210')
    b += b'\x49\xb9' + struct.pack('<Q', hi_va)
    b += bytes.fromhex('4d39ca')
    jcc(bytes.fromhex('0f87'), 'fin')
    counter(probe_base + 0x10)
    b += bytes.fromhex('4c8b0a')
    b += bytes.fromhex('4c894f10')
    b += bytes.fromhex('4c8b4a08')
    b += bytes.fromhex('4c894f18')
    fin_pos = len(b)
    b += bytes.fromhex('48c74720') + struct.pack('<I', site_no)
    b += bytes.fromhex('488d4301')
    b += b'\x48\xa3' + struct.pack('<Q', count_va)
    out_pos = len(b)
    b += bytes.fromhex('415f415e415d415c415b415a41594158')
    b += bytes.fromhex('5f5e5d5b5a5958')
    b += bytes.fromhex('9d')
    b += bytes.fromhex('ffe6')                            # 裸 jmp rsi
    for pos, kind in holes:
        tgt = out_pos if kind == 'out' else fin_pos
        b[pos + 2:pos + 6] = struct.pack('<i', tgt - (pos + 6))
    return bytes(b)


def find_cave(vmp, site_off, span=0x70, need=5, fill=(0xCC, 0x00)):
    """在 site_off 前后 span 字节内找一个 need 字节的填充洞（0xCC/0x00 连续）。
    返回相对偏移（洞起点），要求能放进 `e9 rel32`（5 字节）且不与站点重叠。"""
    best = None
    for delta in range(1, span):
        for sign in (-1, 1):
            off = site_off + sign * delta
            if off < 0 or off + need > len(vmp):
                continue
            if abs(off + need - site_off) < 2 or abs(off - site_off) < 2:
                continue                       # 不能和 `ff e6` 重叠
            chunk = vmp[off:off + need]
            if len(chunk) < need:
                continue
            if all(c == chunk[0] for c in chunk) and chunk[0] in fill:
                d = best if best is not None else None
                if d is None or abs(off - site_off) < abs(d - site_off):
                    best = off
        if best is not None and abs(best - site_off) <= 0x30:
            break
    return best


def _build_stub8(copy_va, probe_base, lo_va, hi_va, count_va, buf_va):
    """v22 表项桩：被派发表直接指向它。进入时 r15 = op*8，
    从自己的表副本里取回原 handler（rsi），记录 192 字节，再 jmp rsi。
    全程不碰目标代码，只改数据表。"""
    b = bytearray()
    holes = []

    def jcc(op, kind):
        pos = len(b)
        b.extend(op + b'\x00\x00\x00\x00')
        holes.append((pos, kind))
        return pos

    def counter(va):
        b.extend(b'\x48\xb8' + struct.pack('<Q', va))
        b.extend(b'\x48\xff\x00')

    b += b'\x9c'
    b += bytes.fromhex('50515253555657')
    b += bytes.fromhex('4150415141524153415441554156')
    b += bytes.fromhex('4157')
    counter(probe_base)
    b += b'\x48\xa1' + struct.pack('<Q', count_va)
    b += bytes.fromhex('4889c3')                          # mov rbx,rax
    b += b'\x48\x3d' + struct.pack('<I', REC_MAX)
    jcc(bytes.fromhex('0f83'), 'out')
    b += bytes.fromhex('4869cbc0000000')                  # imul rcx,rbx,192
    b += bytes.fromhex('48bf') + struct.pack('<Q', buf_va)
    b += bytes.fromhex('4801cf')                          # add rdi,rcx
    b += bytes.fromhex('4889e6')                          # mov rsi,rsp
    b += bytes.fromhex('fc')
    b += bytes.fromhex('b910000000')
    b += bytes.fromhex('f348a5')                          # rep movsq
    counter(probe_base + 8)
    b += bytes.fromhex('4889ea')                          # mov rdx,rbp
    b += b'\x49\xb9' + struct.pack('<Q', lo_va)
    b += bytes.fromhex('4c39ca')
    jcc(bytes.fromhex('0f82'), 'fin')
    b += b'\x49\xb9' + struct.pack('<Q', hi_va)
    b += bytes.fromhex('4c39ca')
    jcc(bytes.fromhex('0f83'), 'fin')
    b += bytes.fromhex('488b95bc000000')                  # mov rdx,[rbp+0xBC]
    b += bytes.fromhex('488917')                          # mov [rdi],rdx
    b += bytes.fromhex('488b95f5000000')                  # mov rdx,[rbp+0xF5]
    b += bytes.fromhex('48895708')                        # mov [rdi+8],rdx
    b += bytes.fromhex('488b17')                          # mov rdx,[rdi]
    b += b'\x49\xb9' + struct.pack('<Q', lo_va)
    b += bytes.fromhex('4c39ca')
    jcc(bytes.fromhex('0f82'), 'fin')
    b += bytes.fromhex('4c8d5210')                        # lea r10,[rdx+16]
    b += b'\x49\xb9' + struct.pack('<Q', hi_va)
    b += bytes.fromhex('4d39ca')
    jcc(bytes.fromhex('0f87'), 'fin')
    counter(probe_base + 0x10)
    b += bytes.fromhex('4c8b0a')
    b += bytes.fromhex('4c894f10')
    b += bytes.fromhex('4c8b4a08')
    b += bytes.fromhex('4c894f18')
    fin_pos = len(b)
    b += bytes.fromhex('48c74720') + b'\x00\x00\x00\x00'   # 站点号占位（表号在下面写）
    b += bytes.fromhex('48ba') + struct.pack('<Q', copy_va)    # mov rdx,copy
    b += bytes.fromhex('4a8b343a')                             # mov rsi,[rdx+r15]
    b += bytes.fromhex('488d4301')                             # lea rax,[rbx+1]
    b += b'\x48\xa3' + struct.pack('<Q', count_va)
    out_pos = len(b)
    b += bytes.fromhex('415f415e415d415c415b415a41594158')
    b += bytes.fromhex('5f5e5d5b5a5958')
    b += bytes.fromhex('9d')
    b += bytes.fromhex('ffe6')
    for pos, kind in holes:
        tgt = out_pos if kind == 'out' else fin_pos
        b[pos + 2:pos + 6] = struct.pack('<i', tgt - (pos + 6))
    return bytes(b)


STUB10_SZ = 0x180
REC10_SZ = 64           # +0 IP, +8 bytes0, +16 bytes8, +24 tag, +32 r15, +40 orig, +48 rbp, +56 q1
REC10_MAX = 400000      # 25.6 MB
SEEN_SLOTS = 0x10000    # IP 去重表：64K 槽 * 8B = 512KB


def _build_stub10(orig_va, tag, probe_base, seen_va, lo_va, hi_va, count_va, buf_va):
    """v23 表项桩：只记 64 字节/条，且同一个 IP 只记一次（64K 槽直接映射去重）。
    记录：+0 IP  +8 [IP]  +16 [IP+8]  +24 tag  +32 r15  +40 orig  +48 rbp  +56 表基址"""
    b = bytearray()
    holes = []

    def jcc(op, kind):
        pos = len(b)
        b.extend(op + b'\x00\x00\x00\x00')
        holes.append((pos, kind))
        return pos

    def counter(va):
        b.extend(b'\x48\xb8' + struct.pack('<Q', va))
        b.extend(b'\x48\xff\x00')

    b += b'\x9c'
    b += bytes.fromhex('50515253555657')
    b += bytes.fromhex('4150415141524153415441554156')
    b += bytes.fromhex('4157')
    counter(probe_base)                                   # 进入
    b += b'\x48\xa1' + struct.pack('<Q', count_va)
    b += bytes.fromhex('4889c3')                          # mov rbx,rax
    b += b'\x48\x3d' + struct.pack('<I', REC10_MAX)
    jcc(bytes.fromhex('0f83'), 'out')
    b += bytes.fromhex('4889ea')                          # mov rdx,rbp
    b += b'\x49\xb9' + struct.pack('<Q', lo_va)
    b += bytes.fromhex('4c39ca')
    jcc(bytes.fromhex('0f82'), 'fin')                     # ctx 不在镜像内
    b += b'\x49\xb9' + struct.pack('<Q', hi_va)
    b += bytes.fromhex('4c39ca')
    jcc(bytes.fromhex('0f83'), 'fin')
    b += bytes.fromhex('488b95bc000000')                  # mov rdx,[rbp+0xBC]  = IP
    b += bytes.fromhex('4c8d5210')                        # lea r10,[rdx+0x10]
    b += b'\x49\xb9' + struct.pack('<Q', hi_va)
    b += bytes.fromhex('4d39ca')
    jcc(bytes.fromhex('0f87'), 'fin')                     # IP+16 越界
    b += b'\x49\xb9' + struct.pack('<Q', lo_va)
    b += bytes.fromhex('4c39ca')
    jcc(bytes.fromhex('0f82'), 'fin')                     # IP 越界
    # IP 去重：r9 = (IP>>2 & 0xFFFF)*8
    b += bytes.fromhex('4c89d1')                          # mov rcx,r10
    b += b'\x49\xb9' + struct.pack('<Q', seen_va)
    b += bytes.fromhex('4c89d0')                          # mov rax,r10
    b += bytes.fromhex('48c1e802')                        # shr rax,2
    b += bytes.fromhex('48' + '25' + struct.pack('<I', 0xFFFF).hex())  # and eax,0xFFFF
    b += bytes.fromhex('48c1e003')                        # shl rax,3
    b += bytes.fromhex('4901c1')                          # add r9,rax
    b += bytes.fromhex('4d3911')                          # cmp [r9],r10
    b += bytes.fromhex('488b15') + struct.pack('<i', 0)   # 占位：mov rdx,[rip+0] -> 不用
    b = b[:-7]
    b += bytes.fromhex('740f')                            # je +0x0f -> 跳到 fin（下面回填）
    je_pos = len(b) - 2
    b += bytes.fromhex('4d8911')                          # mov [r9],r10
    counter(probe_base + 8)
    # 写记录
    b += b'\x48\x8b\x3d' + struct.pack('<i', 0)          # 占位
    b = b[:-7]
    b += bytes.fromhex('4889d8')                          # mov rax,rbx
    b += bytes.fromhex('48c1e006')                        # shl rax,6   (x64)
    b += b'\x48\xbf' + struct.pack('<Q', buf_va)          # mov rdi,buf
    b += bytes.fromhex('4801c7')                          # add rdi,rax
    b += bytes.fromhex('4c8917')                          # mov [rdi],r10   (IP)
    b += bytes.fromhex('4d8b02')                          # mov r8,[r10]
    b += bytes.fromhex('4c894708')                        # mov [rdi+8],r8
    b += bytes.fromhex('4d8b4208')                        # mov r8,[r10+8]
    b += bytes.fromhex('4c894710')                        # mov [rdi+0x10],r8
    b += bytes.fromhex('48c74718') + struct.pack('<I', tag & 0xFFFFFFFF)   # tag
    b += bytes.fromhex('4c897f20')                        # mov [rdi+0x20],r15
    b += bytes.fromhex('48c74728') + struct.pack('<I', orig_va & 0xFFFFFFFF)
    b += b'\x48\xb8' + struct.pack('<Q', orig_va)         # 高位也写上（上面 4 字节是低 32 位）
    b += bytes.fromhex('48894728')                        # mov [rdi+0x28],rax
    b += bytes.fromhex('48896f30')                        # mov [rdi+0x30],rbp
    b += bytes.fromhex('488b8df5000000')                  # mov rcx,[rbp+0xF5]
    b += bytes.fromhex('48894f38')                        # mov [rdi+0x38],rcx
    b += bytes.fromhex('488d4301')                        # lea rax,[rbx+1]
    b += b'\x48\xa3' + struct.pack('<Q', count_va)
    fin_pos = len(b)
    b += bytes.fromhex('415f415e415d415c415b415a41594158')
    b += bytes.fromhex('5f5e5d5b5a5958')
    b += bytes.fromhex('9d')
    b += bytes.fromhex('48be') + struct.pack('<Q', orig_va)
    b += bytes.fromhex('ffe6')
    out_pos = fin_pos     # out 与 fin 同址（记录未写也不影响跳转）
    for pos, kind in holes:
        b[pos + 2:pos + 6] = struct.pack('<i', out_pos - (pos + 6))
    # je 回填：从 je 结尾跳到 fin
    rel = fin_pos - (je_pos + 2)
    b[je_pos + 1] = rel & 0xFF
    assert len(b) <= STUB10_SZ, 'stub10 超长 %d' % len(b)
    return bytes(b)


STUB9_SZ = 0x140


def _build_stub9(orig_va, tag, probe_base, lo_va, hi_va, count_va, buf_va):
    """v22 表项桩（每个表项一个，原 handler 直接烤进桩里）：
        记录 192 字节后，恢复全部寄存器，再 `mov rsi, orig; jmp rsi`。
        —— 不依赖 r15 的索引约定，也不需要表副本，最简单也最不容易错。"""
    b = bytearray()
    holes = []

    def jcc(op, kind):
        pos = len(b)
        b.extend(op + b'\x00\x00\x00\x00')
        holes.append((pos, kind))
        return pos

    def counter(va):
        b.extend(b'\x48\xb8' + struct.pack('<Q', va))
        b.extend(b'\x48\xff\x00')

    b += b'\x9c'
    b += bytes.fromhex('50515253555657')
    b += bytes.fromhex('4150415141524153415441554156')
    b += bytes.fromhex('4157')
    counter(probe_base)
    b += b'\x48\xa1' + struct.pack('<Q', count_va)
    b += bytes.fromhex('4889c3')
    b += b'\x48\x3d' + struct.pack('<I', REC_MAX)
    jcc(bytes.fromhex('0f83'), 'out')
    b += bytes.fromhex('4869cbc0000000')
    b += bytes.fromhex('48bf') + struct.pack('<Q', buf_va)
    b += bytes.fromhex('4801cf')
    b += bytes.fromhex('4889e6')
    b += bytes.fromhex('fc')
    b += bytes.fromhex('b910000000')
    b += bytes.fromhex('f348a5')
    counter(probe_base + 8)
    b += bytes.fromhex('4889ea')
    b += b'\x49\xb9' + struct.pack('<Q', lo_va)
    b += bytes.fromhex('4c39ca')
    jcc(bytes.fromhex('0f82'), 'fin')
    b += b'\x49\xb9' + struct.pack('<Q', hi_va)
    b += bytes.fromhex('4c39ca')
    jcc(bytes.fromhex('0f83'), 'fin')
    b += bytes.fromhex('488b95bc000000')
    b += bytes.fromhex('488917')
    b += bytes.fromhex('488b95f5000000')
    b += bytes.fromhex('48895708')
    b += bytes.fromhex('488b17')
    b += b'\x49\xb9' + struct.pack('<Q', lo_va)
    b += bytes.fromhex('4c39ca')
    jcc(bytes.fromhex('0f82'), 'fin')
    b += bytes.fromhex('4c8d5210')
    b += b'\x49\xb9' + struct.pack('<Q', hi_va)
    b += bytes.fromhex('4d39ca')
    jcc(bytes.fromhex('0f87'), 'fin')
    counter(probe_base + 0x10)
    b += bytes.fromhex('4c8b0a')
    b += bytes.fromhex('4c894f10')
    b += bytes.fromhex('4c8b4a08')
    b += bytes.fromhex('4c894f18')
    fin_pos = len(b)
    b += bytes.fromhex('48c74720') + struct.pack('<I', tag & 0xFFFFFFFF)
    b += bytes.fromhex('488d4301')
    b += b'\x48\xa3' + struct.pack('<Q', count_va)
    out_pos = len(b)
    b += bytes.fromhex('415f415e415d415c415b415a41594158')
    b += bytes.fromhex('5f5e5d5b5a5958')
    b += bytes.fromhex('9d')
    b += bytes.fromhex('48be') + struct.pack('<Q', orig_va)   # mov rsi, orig
    b += bytes.fromhex('ffe6')                                # jmp rsi
    for pos, kind in holes:
        tgt = out_pos if kind == 'out' else fin_pos
        b[pos + 2:pos + 6] = struct.pack('<i', tgt - (pos + 6))
    assert len(b) <= STUB9_SZ, 'stub9 超长 %d' % len(b)
    return bytes(b)


REC11_SZ = 64           # v24.1 记录：[IP,[IP],[IP+8],tag,rbp,orig,0,0]
TRACE11_MAX = 150000    # 顺序轨迹 150k 条（9.6MB）
SLOT_COUNT = 0x80000    # IP 直接映射槽表：512K 槽 × 64B = 32MB
STUB11_SZ = 0x1C0


def _build_stub11(orig_va, tag, probe_base, slots_va, lo_va, hi_va,
                  count_va, buf_va):
    """v24.1 表项桩：只在 IP 处字节「像明文」时落盘（u16@IP<0x800 且
    i32@IP+2 ∈ [-0x80000,0x80000)），双写：顺序轨迹 + IP 直接映射槽表。
    记录 64 字节：+0 IP  +8 [IP]  +0x10 [IP+8]  +0x18 tag  +0x20 rbp
    +0x28 orig  +0x30 0  +0x38 0。槽下标=((IP-lo)>>4)&0x7FFFF，后写覆盖。
    r10 作比较寄存器，r9 专存 [IP+8]，原 handler 烤进桩尾。"""
    B = bytearray()
    holes = []          # (pos, kind)

    def jcc(opc, kind):
        pos = len(B)
        B.extend(opc + b'\x00\x00\x00\x00')
        holes.append((pos, kind))
        return pos

    def counter(va):
        B.extend(b'\x48\xb8' + struct.pack('<Q', va))    # mov rax,imm64
        B.extend(b'\x48\xff\x00')                        # inc qword [rax]

    def imm64(prefix, v):
        return prefix + struct.pack('<Q', v)

    # ---- 保存：pushfq + rax rcx rdx rbx rbp rsi rdi + r8..r15 ----
    B += b'\x9c'
    B += bytes.fromhex('50515253')                       # rax rcx rdx rbx
    B += bytes.fromhex('555657')                         # rbp rsi rdi
    B += bytes.fromhex('41504151415241534154415541564157')  # r8..r15
    counter(probe_base)                                  # 进入计数
    B += imm64(b'\x48\xa1', count_va)                    # mov rax,[count]
    B += b'\x48\x3d' + struct.pack('<I', TRACE11_MAX)    # cmp rax,MAX
    jcc(b'\x0f\x83', 'fin')
    B += bytes.fromhex('4889c3')                         # mov rbx,rax
    # ctx 校验（r10=lo/hi）
    B += bytes.fromhex('4889ea')                         # mov rdx,rbp
    B += imm64(b'\x49\xba', lo_va)                       # mov r10,lo
    B += bytes.fromhex('4c39d2')                         # cmp rdx,r10
    jcc(b'\x0f\x82', 'fin')
    B += imm64(b'\x49\xba', hi_va)                       # mov r10,hi
    B += bytes.fromhex('4c39d2')
    jcc(b'\x0f\x83', 'fin')
    B += bytes.fromhex('488b95bc000000')                 # mov rdx,[rbp+0xBC] = IP
    B += bytes.fromhex('488d4a10')                       # lea rcx,[rdx+0x10]
    B += imm64(b'\x49\xba', hi_va)
    B += bytes.fromhex('4c39d1')                         # cmp rcx,r10
    jcc(b'\x0f\x87', 'fin')
    B += imm64(b'\x49\xba', lo_va)
    B += bytes.fromhex('4c39d2')                         # cmp rdx,r10
    jcc(b'\x0f\x82', 'fin')
    # 读 IP 处 16 字节：r8=[IP]，r9=[IP+8]
    B += bytes.fromhex('4c8b02')                         # mov r8,[rdx]
    B += bytes.fromhex('4c8b4a08')                       # mov r9,[rdx+8]
    # 明文自检 1：u16@IP < 0x800
    B += bytes.fromhex('4c89c1')                         # mov rcx,r8
    B += bytes.fromhex('81e1ffff0000')                   # and ecx,0xFFFF
    B += b'\x48\x81\xf9' + struct.pack('<I', 0x800)      # cmp rcx,0x800
    jcc(b'\x0f\x83', 'fin')
    # 明文自检 2：i32@IP+2 ∈ [-0x80000,0x80000)
    B += bytes.fromhex('4c89c1')                         # mov rcx,r8
    B += bytes.fromhex('48c1e910')                       # shr rcx,16
    B += b'\x48\x81\xc1' + struct.pack('<I', 0x80000)    # add rcx,0x80000
    B += b'\x48\x81\xf9' + struct.pack('<I', 0x100000)   # cmp rcx,0x100000
    jcc(b'\x0f\x83', 'fin')
    counter(probe_base + 8)                              # 明文命中计数
    # 槽写入：idx=((IP-lo)>>4)&0x7FFFF，×64
    B += bytes.fromhex('4889d0')                         # mov rax,rdx
    B += imm64(b'\x49\xba', lo_va)                       # mov r10,lo
    B += bytes.fromhex('4c29d0')                         # sub rax,r10
    B += bytes.fromhex('48c1e804')                       # shr rax,4
    B += b'\x48\x25' + struct.pack('<I', SLOT_COUNT - 1) # and rax,0x7FFFF
    B += bytes.fromhex('48c1e006')                       # shl rax,6
    B += imm64(b'\x48\xbf', slots_va)                    # mov rdi,slots
    B += bytes.fromhex('4801c7')                         # add rdi,rax
    B += bytes.fromhex('488917')                         # mov [rdi],rdx
    B += bytes.fromhex('4c894708')                       # mov [rdi+8],r8
    B += bytes.fromhex('4c894f10')                       # mov [rdi+0x10],r9
    B += b'\x48\xc7\x47\x18' + struct.pack('<I', tag & 0xFFFFFFFF)
    B += bytes.fromhex('48896f20')                       # mov [rdi+0x20],rbp
    B += imm64(b'\x48\xb8', orig_va)                     # mov rax,orig
    B += bytes.fromhex('48894728')                       # mov [rdi+0x28],rax
    B += bytes.fromhex('48c7473000000000')               # mov qword [rdi+0x30],0
    B += bytes.fromhex('48c7473800000000')               # mov qword [rdi+0x38],0
    # 顺序轨迹追加（同样 64 字节）
    B += bytes.fromhex('4889d8')                         # mov rax,rbx
    B += bytes.fromhex('48c1e006')                       # shl rax,6
    B += imm64(b'\x48\xbf', buf_va)
    B += bytes.fromhex('4801c7')                         # add rdi,rax
    B += bytes.fromhex('488917')
    B += bytes.fromhex('4c894708')
    B += bytes.fromhex('4c894f10')
    B += b'\x48\xc7\x47\x18' + struct.pack('<I', tag & 0xFFFFFFFF)
    B += bytes.fromhex('48896f20')
    B += imm64(b'\x48\xb8', orig_va)
    B += bytes.fromhex('48894728')
    B += bytes.fromhex('48c7473000000000')
    B += bytes.fromhex('48c7473800000000')
    B += bytes.fromhex('488d4301')                       # lea rax,[rbx+1]
    B += imm64(b'\x48\xa3', count_va)                    # mov [count],rax
    fin_pos = len(B)
    B += bytes.fromhex('415f415e415d415c415b415a41594158')  # pop r15..r8
    B += bytes.fromhex('5f5e5d5b5a5958')                 # pop rdi rsi rbp rbx rdx rcx rax
    B += b'\x9d'                                         # popfq
    B += imm64(b'\x48\xbe', orig_va)                     # mov rsi,orig
    B += b'\xff\xe6'                                     # jmp rsi
    for pos, kind in holes:
        B[pos + 2:pos + 6] = struct.pack('<i', fin_pos - (pos + 6))
    assert len(B) <= STUB11_SZ, 'stub11 超长 %d' % len(B)
    return bytes(B)


def table_hook_trace(exe, seconds, out_dir='.'):
    """v22：只改派发表（数据），不动任何代码。
    1) 在 .vmp 里按「相邻差 5」签名找出所有 opcode 表；
    2) 每个表项换成专属桩（原 handler 烤进桩里，桩记录后跳回原 handler）；
    3) 收集 (ctx, IP, 表基址, IP 处 16 字节, tag) 轨迹。"""
    import ctypes
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    k32.VirtualAllocEx.restype = ctypes.c_void_p
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p

    PROCESS_VM_WRITE = 0x0020
    PROCESS_VM_OPERATION = 0x0008
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_READWRITE = 0x04
    VMPSIZE = 0xDAC000
    VMP_RVA = 0x19d4000

    proc = launch(exe)
    pid = getattr(proc, 'pid', proc)
    if not isinstance(pid, int):
        print('!! 启动失败: %r' % (proc,))
        return None
    print('[*] pid=%d' % pid, flush=True)
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                        0x0400 | 0x0010 | 0x00100000, False, pid)
    if not h:
        print('!! OpenProcess 失败 err=%d' % ctypes.get_last_error())
        return None

    mods = []
    t0m = time.time()
    while time.time() - t0m < 30:
        mods = list_modules(pid) or []
        if mods:
            break
        time.sleep(0.2)
    if not mods:
        print('!! 拿不到模块列表')
        return None
    base, size, name = max(mods, key=lambda m: m[1])
    print('[*] 主模块 %s base=%#x size=%#x' % (name, base, size), flush=True)

    vmp = None
    for _ in range(120):
        blob = read_mem_safe(h, base + VMP_RVA, VMPSIZE)
        if blob and blob.find(b'\x48\x63\x0b') != -1:      # 派发器已解密
            vmp = blob
            break
        time.sleep(0.25)
    if not vmp:
        print('!! .vmp 未解密')
        return None
    lo, hi = base + VMP_RVA, base + VMP_RVA + len(vmp)
    print('[*] .vmp %d 字节，范围 [%#x, %#x)' % (len(vmp), lo, hi), flush=True)

    # 历史证据里的表地址逐个实证。实测保护器会「先填 RVA、后加重定位」，
    # 所以这里要等到表项变成绝对地址（落在 .vmp 内）再动手，最多等 20 秒。
    KNOWN = [0x1421080ab, 0x141da2b42, 0x141d8df04]
    rva_lo, rva_hi = VMP_RVA, VMP_RVA + len(vmp)
    tables = []
    for attempt in range(40):
        tables = []
        for va0 in KNOWN:
            va = va0 - 0x140000000 + base
            raw = read_mem(h, va, 64)
            if not raw or len(raw) < 64:
                print('    known %#x 读不出' % va, flush=True)
                continue
            q = struct.unpack('<8Q', raw)
            inabs = all(lo <= x < hi for x in q)
            inrva = all(rva_lo <= x < rva_hi for x in q)
            if attempt < 2 or attempt == 39:
                print('    known %#x 前 4 项 %s 绝对=%s RVA=%s'
                      % (va, [hex(x) for x in q[:4]], inabs, inrva), flush=True)
            if inabs:
                tables.append(va)
            elif inrva:
                print('      （RVA 形态，等重定位）', flush=True)
        if tables:
            break
        time.sleep(0.5)

    sized = []
    for va in tables:
        big = read_mem(h, va, 4096 * 8)
        if not big:
            continue
        q2 = struct.unpack('<%dQ' % (len(big) // 8), big[:len(big) // 8 * 8])
        m = 0
        while m < len(q2) and lo <= q2[m] < hi:
            m += 1
        if m >= 24:
            sized.append((va, m))
            print('    -> 采纳 %#x，长度 %d 项（%#x..%#x）' % (va, m, va, va + m * 8),
                  flush=True)
    tables = sized

    total = sum(n for _, n in tables)
    print('[*] 发现 %d 张表，共 %d 项: %s'
          % (len(tables), total, [(hex(va), n) for va, n in tables]), flush=True)
    if not tables or total == 0:
        print('!! 没找到表')
        return None

    alloc = None
    for hint in (0x100000000, 0x110000000, 0x150000000, 0x160000000, None):
        alloc = k32.VirtualAllocEx(ctypes.c_void_p(h), ctypes.c_void_p(hint),
                                   ctypes.c_size_t(0x4000000),
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE)
        if alloc:
            break
    if not alloc:
        print('!! VirtualAllocEx 失败')
        return None
    count_va = alloc
    probe_va = alloc + 0x100
    slots_va = alloc + 0x100000            # 512K 槽 × 64B = 32MB
    stub_va = alloc + 0x2100000
    buf_va = alloc + 0x2200000             # 顺序轨迹 150k × 64B
    print('[*] 缓冲: count=%#x slots=%#x stub=%#x buf=%#x'
          % (count_va, slots_va, stub_va, buf_va), flush=True)

    wrote = ctypes.c_size_t(0)
    originals = {}       # table_va -> (原 entries bytes, n)
    stubs = []           # [(table_i, entry_i, stub_va)]
    k = 0
    for ti, (tva, n) in enumerate(tables):
        raw = read_mem(h, tva, n * 8)
        if not raw or len(raw) != n * 8:
            print('   表 %#x 读不出（%s），跳过' % (tva, len(raw) if raw else None))
            continue
        originals[tva] = (raw, n)
        ents = struct.unpack('<%dQ' % n, raw)
        pb = probe_va + ti * PROBE_STRIDE
        blob_stubs = bytearray()
        ptrs = []
        for ei, orig in enumerate(ents):
            sv = stub_va + k * STUB11_SZ
            st = _build_stub11(orig, (ti << 20) | ei, pb, slots_va, lo, hi,
                               count_va, buf_va)
            blob_stubs += st + b'\xcc' * (STUB11_SZ - len(st))
            ptrs.append(sv)
            stubs.append((ti, ei, sv, orig))
            k += 1
        args = [ctypes.c_void_p(h), ctypes.c_void_p(stub_va + (k - n) * STUB11_SZ),
                bytes(blob_stubs), len(blob_stubs), ctypes.byref(wrote)]
        if not k32.WriteProcessMemory(*args):
            print('   写桩失败表 %#x err=%d' % (tva, ctypes.get_last_error()))
            continue
        op = ctypes.c_uint32(0)
        k32.VirtualProtectEx(ctypes.c_void_p(h), ctypes.c_void_p(tva),
                             ctypes.c_size_t(n * 8), PAGE_READWRITE, ctypes.byref(op))
        newtab = struct.pack('<%dQ' % n, *ptrs)
        if k32.WriteProcessMemory(ctypes.c_void_p(h), ctypes.c_void_p(tva),
                                  newtab, len(newtab), ctypes.byref(wrote)):
            print('   表 %#x（%d 项）已换成桩，首项回读 %#x'
                  % (tva, n, struct.unpack('<Q', read_mem(h, tva, 8) or b'\0' * 8)[0]),
                  flush=True)
        else:
            print('   表 %#x 写入失败 err=%d' % (tva, ctypes.get_last_error()))

    # 静态 dump 循环附近字节码区（两次：钩后 / 观察结束），用于离线比对
    for tagx, tva2 in (('lic_bytecode.bin', base + 0x2150000),):
        blob2 = read_mem_safe(h, tva2, 0x40000)
        if blob2:
            with open(os.path.join(out_dir, tagx), 'wb') as f2:
                f2.write(blob2)
            print('[*] 已 dump %s（%#x..%#x）' % (tagx, tva2, tva2 + 0x40000),
                  flush=True)

    t0 = time.time()
    dead_at = None
    tick = 0
    snap = (0, b'')
    snap_slots = b''
    while time.time() - t0 < seconds:
        time.sleep(0.5)
        tick += 1
        # 每 2 秒快照一次（进程随时可能崩，崩后内存就读不出来了）
        if tick % 4 == 0:
            c0 = min(struct.unpack('<Q', read_mem(h, count_va, 8) or b'\0' * 8)[0],
                     TRACE11_MAX)
            if c0:
                raw0 = read_mem(h, buf_va, c0 * REC11_SZ)
                if raw0:
                    snap = (len(raw0) // REC11_SZ, raw0)
            sb = read_mem_safe(h, slots_va, SLOT_COUNT * REC11_SZ)
            if sb and sb.count(b'\x00') < len(sb) - 8:
                snap_slots = sb
        code = ctypes.c_ulong(0)
        oka = k32.GetExitCodeProcess(ctypes.c_void_p(h), ctypes.byref(code))
        pr = _read_probes(read_mem, h, count_va, len(tables))
        if not oka or code.value != 259:
            dead_at = round(time.time() - t0, 1)
            print('[!] 进程在 %.1fs 退出 code=%#x 探针 %s' % (dead_at, code.value, pr),
                  flush=True)
            break
        if tick <= 2 or tick % 8 == 0:
            print('    [hb %.1fs] 存活 探针 %s' % (time.time() - t0, pr), flush=True)
        cnt = struct.unpack('<Q', read_mem(h, count_va, 8) or b'\0' * 8)[0]
        if cnt >= TRACE11_MAX:
            break

    cnt = min(struct.unpack('<Q', read_mem(h, count_va, 8) or b'\0' * 8)[0], TRACE11_MAX)
    raw = read_mem(h, buf_va, cnt * REC11_SZ) or b''
    if not raw and snap[1]:
        raw, cnt = snap[1], snap[0]
        print('[*] 进程已退出，改用最后快照（%d 条）' % cnt, flush=True)
    n = len(raw) // REC11_SZ
    out = [list(struct.unpack_from('<8Q', raw, i * REC11_SZ)) for i in range(n)]
    ips = {e[0] for e in out if e[0]}
    ctxs = {e[4] for e in out if e[0]}
    tags = {}
    for e in out:
        if e[0]:
            tags[e[3]] = tags.get(e[3], 0) + 1
    # 槽表解码（优先用快照，其次现场读）
    sblob = snap_slots or (read_mem_safe(h, slots_va, SLOT_COUNT * REC11_SZ) or b'')
    insns = []
    for i in range(len(sblob) // REC11_SZ):
        ip, b0, b1, tg, rb, og, p0, p1 = struct.unpack_from('<8Q', sblob, i * REC11_SZ)
        if not ip:
            continue
        bb = struct.pack('<QQ', b0, b1)
        op = struct.unpack_from('<H', bb, 0)[0]
        rel = struct.unpack_from('<i', bb, 2)[0]
        insns.append([ip, op, rel, op == (tg & 0xFFFFF), tg & 0xFFFFF, rb])
    ok_op = sum(1 for e in insns if e[3])
    ok_rel = sum(1 for e in insns if e[3] and -0x80000 <= e[2] < 0x80000)
    print('[*] 顺序轨迹 %d 条（不同 IP %d，不同 ctx %d）；槽表 %d 条明文'
          '（op 自证 %d，rel 合理 %d，来源快照=%s）'
          % (n, len(ips), len(ctxs), len(insns), ok_op, ok_rel,
             bool(snap_slots)), flush=True)
    with open(os.path.join(out_dir, 'vm_trace.json'), 'w') as f:
        json.dump({'n': n, 'mode': 'table-plain', 'rec_size': REC11_SZ,
                   'fmt': '[ip,[ip],[ip+8],tag,rbp,orig,0,0]',
                   'dead_at': dead_at, 'n_ip': len(ips), 'n_ctx': len(ctxs),
                   'tables': [(hex(va), nn) for va, nn in tables],
                   'tag_hist': tags, 'trace': out,
                   'insns': insns, 'insns_ok_op': ok_op, 'insns_ok_rel': ok_rel}, f)

    blob3 = read_mem_safe(h, base + 0x2150000, 0x40000)
    if blob3:
        with open(os.path.join(out_dir, 'lic_bytecode_end.bin'), 'wb') as f2:
            f2.write(blob3)
    for tva, (raw0, nn) in originals.items():
        op = ctypes.c_uint32(0)
        k32.VirtualProtectEx(ctypes.c_void_p(h), ctypes.c_void_p(tva),
                             ctypes.c_size_t(nn * 8), PAGE_READWRITE, ctypes.byref(op))
        k32.WriteProcessMemory(ctypes.c_void_p(h), ctypes.c_void_p(tva),
                               raw0, len(raw0), ctypes.byref(wrote))
    print('[*] 已还原 %d 张表' % len(originals), flush=True)
    return n


def discover_tables(blob, va0, lo, hi, min_len=24, delta=5):
    """在 .vmp 段里找 opcode 表：连续 qword 落在 [lo,hi)、且相邻差 5（jmp rel32 桩间距）。
    返回 [(va, 项数), ...]"""
    import array
    n = len(blob) // 8
    q = array.array('Q')
    q.frombytes(blob[:n * 8])
    out = []
    i = 0
    while i < n - 4:
        v = q[i]
        if (lo <= v < hi and q[i + 1] == v + delta and q[i + 2] == v + 2 * delta
                and q[i + 3] == v + 3 * delta):
            j = i
            while j + 1 < n and q[j + 1] == q[j] + delta and lo <= q[j + 1] < hi:
                j += 1
            L = j - i + 1
            if L >= min_len:
                out.append((va0 + i * 8, L))
                i = j + 1
                continue
        i += 1
    return out


def _read_probes(read_mem, h, count_va, n_sites):
    """读探针：条数 + 每站点 3 个（进入/复制完/ctx通过）"""
    def q(va):
        return struct.unpack('<Q', read_mem(h, va, 8) or b'\0' * 8)[0]
    out = {'条数': q(count_va)}
    for i in range(n_sites):
        base = count_va + PROBE_BASE + i * PROBE_STRIDE
        out['s%d' % i] = (q(base), q(base + 8), q(base + 0x10))
    return out


def vm_hook_trace(exe, seconds, out_dir='.'):
    """v15/v16：扫描 .vmp 里所有派发器（jmp rsi 前有 movsxd rcx,[rbx]），
    在各自 `jmp rsi` 处下 5 字节 hook，记录
    (ctx, r15, handler, [ctx+0xBC], [ctx+0xF5], [IP], [IP+8]) 后 jmp rsi。"""
    import ctypes
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    k32.VirtualAllocEx.restype = ctypes.c_void_p
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p

    PROCESS_VM_WRITE = 0x0020
    PROCESS_VM_OPERATION = 0x0008
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40
    VMPSIZE = 0xDAC000

    proc = launch(exe)
    pid = getattr(proc, 'pid', proc)
    if not isinstance(pid, int):
        print('!! 启动失败: %r' % (proc,))
        return None
    print('[*] pid=%d' % pid, flush=True)
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE |
                        PROCESS_VM_OPERATION | 0x0400 | 0x0010 | 0x00100000,
                        False, pid)
    if not h:
        print('!! OpenProcess 失败 err=%d' % ctypes.get_last_error())
        return None

    mods = []
    t0m = time.time()
    while time.time() - t0m < 30:
        mods = list_modules(pid) or []
        if mods:
            break
        time.sleep(0.2)
    if not mods:
        print('!! 拿不到模块列表')
        return None
    base, size, name = max(mods, key=lambda m: m[1])
    print('[*] 主模块 %s base=%#x' % (name, base), flush=True)

    # 等 .vmp 解密（派发器字节可读）
    vmp = None
    for _ in range(80):
        blob = read_mem_safe(h, base + 0x19d4000, VMPSIZE)
        if blob and blob.find(b'\x48\x63\x0b') != -1:
            vmp = blob
            break
        time.sleep(0.25)
    if not vmp:
        print('!! .vmp 未解密，放弃')
        return None
    print('[*] .vmp 已就绪（%d 字节）' % len(vmp), flush=True)

    sites = []
    k = 0
    while True:
        k = vmp.find(b'\xff\xe6', k)
        if k == -1:
            break
        if b'\x48\x63\x0b' in vmp[max(0, k - 0x60):k]:
            sites.append(base + 0x19d4000 + k)
        k += 1
    print('[*] 派发器候选 %d 处: %s' % (len(sites), [hex(x) for x in sites]),
          flush=True)
    if not sites:
        return None

    alloc = None
    for hint in (0x100000000, 0x110000000, 0x150000000, 0x160000000, None):
        alloc = k32.VirtualAllocEx(ctypes.c_void_p(h), ctypes.c_void_p(hint),
                                   ctypes.c_size_t(0x4000000),
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE)
        if alloc:
            break
    if not alloc:
        print('!! VirtualAllocEx 失败')
        return None
    count_va, buf_va = alloc, alloc + 0x100000
    hi_va = base + max(size, 0x2800000)
    print('[*] 校验区间 [%#x, %#x)' % (base, hi_va), flush=True)
    wrote = ctypes.c_size_t(0)

    shells = {}
    caves_short = {}
    patches = {}          # site -> 原始 5 字节
    caves = {}            # cave_va -> 原始 5 字节
    for si, site in enumerate(sites):
        old = read_mem(h, site, 5)
        if not old or old[:2] != b'\xff\xe6':
            print('    site %#x 不是 jmp rsi（%s），跳过'
                  % (site, old.hex() if old else 'None'))
            continue
        site_off = site - (base + 0x19d4000)
        cave_off = find_cave(vmp, site_off) if 0 <= site_off < len(vmp) else None
        if cave_off is None:
            print('    site %#x 附近无填充洞，跳过（5 字节 hook 会劈开后续指令）' % site)
            continue
        cave_va = base + 0x19d4000 + cave_off
        rel8 = cave_va - (site + 2)
        if not -128 <= rel8 <= 127:
            print('    site %#x 洞太远（%d），跳过' % (site, rel8))
            continue
        shell_va = alloc + 0x1000 + si * 0x400
        stub = _build_stub7(si, count_va + PROBE_BASE + si * PROBE_STRIDE,
                            base, hi_va, count_va, buf_va)
        k32.WriteProcessMemory(ctypes.c_void_p(h), ctypes.c_void_p(shell_va),
                               stub, len(stub), ctypes.byref(wrote))
        op2 = ctypes.c_uint32(0)
        for pg in {(site & ~0xFFF), (cave_va & ~0xFFF)}:
            k32.VirtualProtectEx(ctypes.c_void_p(h), ctypes.c_void_p(pg),
                                 ctypes.c_size_t(0x1000), PAGE_EXECUTE_READWRITE,
                                 ctypes.byref(op2))
        old_cave = read_mem(h, cave_va, 5) or b''
        # 洞里放 e9 rel32 -> 桩（5 字节），站点只写 2 字节 eb rel8
        okc = k32.WriteProcessMemory(ctypes.c_void_p(h), ctypes.c_void_p(cave_va),
                                     b'\xe9' + struct.pack('<i', shell_va - (cave_va + 5)),
                                     5, ctypes.byref(wrote))
        oks = k32.WriteProcessMemory(ctypes.c_void_p(h), ctypes.c_void_p(site),
                                     bytes([0xEB, rel8 & 0xFF]), 2,
                                     ctypes.byref(wrote))
        if okc and oks:
            shells[site] = shell_va
            patches[site] = old
            caves[cave_va] = old_cave
            caves_short[site] = bytes([0xEB, rel8 & 0xFF])
            time.sleep(0.15)
            print('    hook %#x 已下（site %d，2 字节短跳->洞 %#x->桩 %#x，%d 字节）'
                  ' 回读站点=%s 洞=%s 原尾3字节=%s'
                  % (site, si, cave_va, shell_va, len(stub),
                     (read_mem(h, site, 4) or b'').hex(),
                     (read_mem(h, cave_va, 5) or b'').hex(), old[2:5].hex()),
                  flush=True)
            time.sleep(1.5)
            code = ctypes.c_ulong(0)
            okalive = k32.GetExitCodeProcess(ctypes.c_void_p(h), ctypes.byref(code))
            if not okalive or code.value != 259:
                print('[!] 装上 site %d（%#x）后进程退出 code=%#x'
                      % (si, site, code.value), flush=True)
                break
            print('    [staged] site %d 观测存活，探针 %s'
                  % (si, _read_probes(read_mem, h, count_va, len(sites))), flush=True)
        else:
            print('    hook %#x 失败 cave=%s site=%s err=%d'
                  % (site, okc, oks, ctypes.get_last_error()))

    t0 = time.time()
    last = 0
    repatch = 0
    dead_at = None
    tick = 0
    while time.time() - t0 < seconds:
        time.sleep(0.5)
        tick += 1
        code = ctypes.c_ulong(0)
        okalive = k32.GetExitCodeProcess(ctypes.c_void_p(h), ctypes.byref(code))
        pr = _read_probes(read_mem, h, count_va, len(sites))
        if not okalive or code.value != 259:        # 259 = STILL_ACTIVE
            dead_at = round(time.time() - t0, 1)
            print('[!] 进程在 %.1fs 已退出（GetExitCodeProcess ok=%s code=%#x）探针 %s'
                  % (dead_at, okalive, code.value, pr), flush=True)
            break
        if tick <= 2 or tick % 8 == 0:
            print('    [hb %.1fs] 存活 code=%#x 探针 %s 首站可读=%s'
                  % (time.time() - t0, code.value, pr,
                     bool(read_mem(h, sites[0], 5))), flush=True)
        for site in list(patches):
            cur = read_mem(h, site, 2) or b''
            if cur[:1] != b'\xeb':                 # 保护器把短跳改回去了
                want = caves_short[site]
                op2 = ctypes.c_uint32(0)
                k32.VirtualProtectEx(ctypes.c_void_p(h),
                                     ctypes.c_void_p(site & ~0xFFF),
                                     ctypes.c_size_t(0x1000),
                                     PAGE_EXECUTE_READWRITE, ctypes.byref(op2))
                k32.WriteProcessMemory(ctypes.c_void_p(h),
                                       ctypes.c_void_p(site), want, 2,
                                       ctypes.byref(wrote))
                repatch += 1
        cnt = struct.unpack('<Q', read_mem(h, count_va, 8) or b'\0' * 8)[0]
        if cnt != last:
            print('    [trace] %d 条' % cnt, flush=True)
            last = cnt
        if cnt >= 2599000:
            break

    print('[*] 期间重下 hook %d 次%s' % (repatch, '' if dead_at is None else
                                     '（进程 %.1fs 已退出）' % dead_at), flush=True)
    print('[*] 探针 %s' % _read_probes(read_mem, h, count_va, len(sites)), flush=True)
    for site, va in shells.items():
        head = read_mem(h, va, 24) or b''
        print('    桩 %#x 前 24 字节: %s' % (va, head.hex()), flush=True)
    cnt = struct.unpack('<Q', read_mem(h, count_va, 8) or b'\0' * 8)[0]
    cnt = min(cnt, REC_MAX)
    raw = read_mem(h, buf_va, cnt * REC_SZ) or b''
    n = len(raw) // REC_SZ
    out = []
    for i in range(n):
        out.append(list(struct.unpack_from('<22Q', raw, i * REC_SZ)))
    keys = {tuple(e[:18]) for e in out}
    valid = sum(1 for e in out if e[16])
    site_hits = {}
    for e in out:
        site_hits[e[20]] = site_hits.get(e[20], 0) + 1
    with open(os.path.join(out_dir, 'vm_trace.json'), 'w') as f:
        json.dump({'n': n, 'reg_order': REG_ORDER,
                   'fmt': 'regs[16] + [rbp+0xBC] + [rbp+0xF5] + [q0] + [q0+8] + site + pad2',
                   'rec_size': REC_SZ, 'sites': [hex(x) for x in patches],
                   'site_map': {str(k): hex(v) for k, v in shells.items()},
                   'site_hits': {str(k): v for k, v in site_hits.items()},
                   'distinct': len(keys), 'ctx_ok': valid, 'trace': out}, f)
    print('[*] 已写 vm_trace.json（%d 条，去重 %d，ctx 有效 %d，站点命中 %s）'
          % (n, len(keys), valid, site_hits), flush=True)

    for site, old in patches.items():
        k32.WriteProcessMemory(ctypes.c_void_p(h), ctypes.c_void_p(site),
                               old[:2], 2, ctypes.byref(wrote))
    for cave_va, oc in caves.items():
        if len(oc) == 5:
            k32.WriteProcessMemory(ctypes.c_void_p(h), ctypes.c_void_p(cave_va),
                                   oc, 5, ctypes.byref(wrote))
    return n


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', help='启动这个程序')
    ap.add_argument('--args', default='')
    ap.add_argument('--pid', type=int, help='附加已有进程')
    ap.add_argument('--seconds', type=float, default=60.0)
    ap.add_argument('--interval', type=float, default=0.5)
    ap.add_argument('--rounds', type=int, default=6)
    ap.add_argument('--relaunch', type=int, default=1,
                    help='重启 N 次，每次启动后立刻高速采样（VM 常只在启动瞬间活跃）')
    ap.add_argument('--boot-wait', type=float, default=0.3,
                    help='启动后等多久开始抓（VM 窗口在头几秒，默认尽快）')
    ap.add_argument('--hot-seconds', type=float, default=60.0,
                    help='启动后先高速盯 rbp/rsp 的秒数（VM 执行期 rbp=ctx）')
    ap.add_argument('--out', default='tables.json')
    ap.add_argument('--deep', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--trace-vm', nargs='?', const='table', default=None,
                    choices=['table', 'site'],
                    help='抓逐条 VM 指令轨迹：table=换派发表(默认)，site=给派发器下 hook')
    ap.add_argument('--trace-seconds', type=float, default=60.0)
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    if os.name != 'nt':
        print('[!] 只能在 Windows 上跑（用 --selftest 测核心算法）')
        return 2

    print('[*] 管理员: %s' % is_admin())
    print('[*] Python: %s' % sys.version.split()[0])

    if a.trace_vm:
        if not a.exe:
            print('[!] --trace-vm 需要 --exe')
            return 2
        od = os.path.dirname(os.path.abspath(a.out)) or '.'
        fn = table_hook_trace if a.trace_vm == 'table' else vm_hook_trace
        print('[*] 追踪方式: %s' % a.trace_vm)
        n = fn(a.exe, a.trace_seconds, od)
        print('[*] trace-mode 结束: %s 条' % n)
        return 0

    all_rounds = []
    base = lay = None
    tries = max(1, a.relaunch if a.exe else 1)

    for attempt in range(tries):
        if a.pid:
            pid = a.pid
            h = open_process(pid)
        else:
            print('\n===== 第 %d/%d 次启动 =====' % (attempt + 1, tries))
            r = launch(a.exe, a.args, wait=a.boot_wait)
            pid = r if isinstance(r, int) else r.pid
            try:
                h = open_process(pid)
            except OSError as e:
                print('[!] 打不开进程: %s' % e)
                continue

        got, b, l = sample_process(h, pid, a.seconds, a.rounds, a.interval,
                                   a.deep, hot_seconds=a.hot_seconds,
                                   out_dir=os.path.dirname(
                                       os.path.abspath(a.out)) or '.')
        all_rounds += got
        base = base or b
        lay = lay or l
        # 提前停止只认「有 IP 槽」的命中——上一版 score>=20 就停，
        # 结果抓到 0x1407be9f0 的 C++ 对象数组假阳性还提前退了
        if any(x['streams'] for x in got):
            print('[*] 第 %d 次已抓到活的字节流，停止重启' % (attempt + 1))
            break
        if any(x['tables'] for x in got):
            print('[*] 第 %d 次抓到表但无流，继续下一轮启动' % (attempt + 1))
        # 关掉再试
        if not a.pid and h:
            try:
                k32.TerminateProcess(h, 0)
            except Exception:
                pass
        time.sleep(1.0)

    if not all_rounds:
        print('[!] 一轮都没抓到')
        return 1

    # 稳定性判定：表不变 + 流在动
    def table_vset(r):
        return {k: v['table_va'] for k, v in r['tables'].items()}

    tbl_stable = len({json.dumps(table_vset(r), sort_keys=True)
                      for r in all_rounds}) == 1
    ip_moved = len({json.dumps(v.get('ophist'), sort_keys=True)
                    for r in all_rounds for v in r['streams'].values()}) > 1

    best = max(all_rounds, key=lambda r: r['score'])
    out = {
        'source': 'runtime',
        'verdict': {'tables_stable': tbl_stable, 'stream_moving': ip_moved,
                    'rounds': len(all_rounds)},
        'module_base': hex(base) if base else None,
        'image_size': hex(lay['size_of_image']) if lay else None,
        'code_ranges': [[hex(x), hex(y)] for x, y in (code_ranges_of(h, base)[0]
                                                      if base else [])],
        'sections': lay['sections'] if lay else [],
        'rounds': all_rounds,
        'best': best,
    }
    with open(a.out, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print('[*] 写入 %s（%d 轮）' % (a.out, len(all_rounds)))

    d = os.path.dirname(os.path.abspath(a.out))
    for k, v in best['tables'].items():
        vals = v['entries']
        with open(os.path.join(d, 'table_%s.bin' % k), 'wb') as f:
            f.write(struct.pack('<%dQ' % len(vals), *vals))
        print('    table %s: %d 项' % (k, len(vals)))
    for k, v in best['streams'].items():
        raw = base64.b64decode(v['b64'])
        with open(os.path.join(d, 'stream_%s.bin' % k), 'wb') as f:
            f.write(raw)
        print('    stream %s: %d 字节, 走通 %d 步' % (k, len(raw), v['walk_steps']))
    if 'ctx_b64' in best:
        with open(os.path.join(d, 'ctx.bin'), 'wb') as f:
            f.write(base64.b64decode(best['ctx_b64']))
        print('    ctx.bin: 0x800 字节原文')

    print('\n[结论] 表稳定=%s 流在动=%s' % (tbl_stable, ip_moved))
    if tbl_stable and ip_moved:
        print('        => 抓的是活的 VM 上下文，可直接喂 resolve_map.py')
    elif best['tables']:
        print('        => 至少拿到表，先用 resolve_map.py 试认编码')
    return 0


if __name__ == '__main__':
    sys.exit(main())

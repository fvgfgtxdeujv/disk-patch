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
    高速只读线程寄存器：VM 执行期间 rbp 就是 ctx（静态已证）。
    不扫内存、不做栈扫，每轮 OpenThread+GetThreadContext，~2ms 一轮。
    命中（score>0）记下；有 IP 槽的立刻返回。
    """
    hits = []
    probed = set()
    rip_hits = {}                     # v7: VM 执行时 RIP 直方图（rbp 落保护段）
    live_ctxs = set()                 # v8: 已抓过活 ctx 的地址
    t_end = time.time() + seconds
    k = 0
    while time.time() < t_end:
        k += 1
        try:
            ctxs = thread_contexts(pid)
        except Exception:
            ctxs = []
        for tid, rip, rsp, rbp in ctxs:
            # v7：rbp 落在保护段 => VM 正在执行，RIP 就是派发器/handler
            if rbp and any(lo <= rbp < hi for lo, hi in guard) \
                    and rip and any(lo <= rip < hi for lo, hi in ranges):
                rip_hits[rip] = rip_hits.get(rip, 0) + 1
                # v8：VM 执行瞬间抓活 ctx + IP 指向的字节码（执行后会被还原）
                if rbp not in live_ctxs:
                    live_ctxs.add(rbp)
                    # v8.1：先挂起该线程，冻结 VM，再读内存（否则读到的可能是还原后的）
                    ht = k32.OpenThread(THREAD_SUSPEND_RESUME |
                                        THREAD_QUERY_INFORMATION, False, tid)
                    if ht:
                        k32.SuspendThread(ht)
                    try:
                        ctx_raw = read_mem(view.h, rbp, 0x1000) or b''
                        tag_dir = out_dir_ref[0]
                        cn = 'live_ctx_%x.bin' % rbp
                        with open(os.path.join(tag_dir, cn), 'wb') as f:
                            f.write(ctx_raw)
                        # 已知 IP/表槽：0x70/0x73/0xBC/0xF5/0xC4 + 全扫描
                        slots = [0x70, 0x73, 0xBC, 0xC4, 0xF5, 0x36, 0x5B, 0xB9]
                        import struct as _s
                        for sl in slots:
                            if sl + 8 <= len(ctx_raw):
                                ptr = _s.unpack_from('<Q', ctx_raw, sl)[0]
                                if 0x140000000 <= ptr < 0x143000000:
                                    buf = read_mem(view.h, ptr, 0x8000) or b''
                                    fn = 'live_ip_%x_slot%x.bin' % (rbp, sl)
                                    with open(os.path.join(tag_dir, fn), 'wb') as f:
                                        f.write(buf)
                                    print('    [live] ctx=%#x slot+%#x ptr=%#x '
                                          '抓取 %d B' % (rbp, sl, ptr, len(buf)),
                                          flush=True)
                    except Exception as e:
                        print('    [live] 抓取失败: %s' % e, flush=True)
                    finally:
                        if ht:
                            k32.ResumeThread(ht)
                            k32.CloseHandle(ht)
            for va, how in ((rbp, 'rbp:t%d' % tid), (rsp, 'rsp:t%d' % tid)):
                if va < 0x10000 or va in probed:
                    continue
                probed.add(va)
                if not quick_prefilter(view, va, ranges, guard=guard):
                    continue
                r = probe_ctx(view, va, ranges, guard)
                if r['score'] > 0:
                    r['how'] = how
                    hits.append((va, r))
                    print('    [hot] %#x how=%s score=%d 表=%d IP=%d'
                          % (va, how, r['score'], len(r['tables']), len(r['ips'])),
                          flush=True)
                    if r['ips']:
                        return hits, k
        # hot 阶段进程刚起，偶发读失败是正常
    if rip_hits:
        top = sorted(rip_hits.items(), key=lambda x: -x[1])[:24]
        print('[*] VM 执行期 RIP 直方图（top24）:', flush=True)
        for rip, cnt in top:
            print('    rip=%#x x%d' % (rip, cnt), flush=True)
        try:
            with open(os.path.join(out_dir_ref[0], 'rip_hits.json'), 'w') as f:
                json.dump({hex(k2): v for k2, v in sorted(rip_hits.items(),
                            key=lambda x: -x[1])[:200]}, f, indent=1)
        except Exception:
            pass
    return hits, k


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
    ap.add_argument('--hot-seconds', type=float, default=10.0,
                    help='启动后先高速盯 rbp/rsp 的秒数（VM 执行期 rbp=ctx）')
    ap.add_argument('--out', default='tables.json')
    ap.add_argument('--deep', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    if os.name != 'nt':
        print('[!] 只能在 Windows 上跑（用 --selftest 测核心算法）')
        return 2

    print('[*] 管理员: %s' % is_admin())
    print('[*] Python: %s' % sys.version.split()[0])

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

# -*- coding: utf-8 -*-
"""
dump_ctx.py —— 在 Windows 上启动 / 附加 DiskGenius，扫描 VM 上下文里handler 表

流程：
  1) 启动目标（requireAdministrator 的 exe 走 ShellExecuteEx runas 提权）
  2) 轮询 ReadProcessMemory，扫可读内存里的「handler 表 + 指向表的结构」
  3) 扫不到就把整块可读内存存成 memimage（自定义容器），再离线扫一遍
     —— 离线扫和在线扫走同一个 scan_buffer，结果一致，但可复算、可当证据

平台无关的扫描核心在文件上半部分，Linux 上也能单测（local_selftest.py）。
"""
import ctypes
import json
import os
import struct
import subprocess
import sys
import time


# ------------------------------------------------------------
# UTF-8 控制台（Windows runner 默认 cp1252，中文 print 会直接抛
# UnicodeEncodeError 把整步打挂）
# ------------------------------------------------------------
def _utf8_console():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass


_utf8_console()

# 平台无关的扫描核心（Linux 上也能跑）
# ------------------------------------------------------------
# 实测出的表指针槽。注意 0x4 与 0x8 作为 8 字节指针会互相重叠，
# 同一个上下文里不可能同时成立 —— 遇到它们只可能命中一个，属正常。
CTX_SLOTS = (0x4, 0x8, 0xF5, 0x110, 0x1F4)
IP_SLOTS = (0x92, 0x18, 0x120, 0x55, 0x17A)

DEFAULT_MIN_LEN = 16          # handler 表至少这么长才算「表」
DEFAULT_MAX_TABLES = 256      # 预筛阶段最多认这么多张表
DEFAULT_MAXN = 65536          # 单张表最多读 65536 项（16 位 opcode 上限）


def table_looks_valid(read_u64, table_ptr, code_lo, code_hi, n=32, readable=None):
    """
    表基址是不是真的表：
      - 表本身要可读（在堆/数据段，不要求落在代码段）
      - 前 n 项都落在代码段，且不能全是同一个地址
    """
    if readable is not None and not readable(table_ptr):
        return False
    if table_ptr == 0:
        return False
    seen = set()
    for i in range(n):
        v = read_u64(table_ptr + i * 8)
        if v is None or not (code_lo <= v < code_hi):
            return False
        seen.add(v)
    return len(seen) >= max(4, n // 4)     # 至少有几个不同值，防止全是同一地址


def score_ctx(read_u64, read_u16, base, code_lo, code_hi, readable):
    """
    给一个候选地址打分。readable(addr) -> bool。
    返回 (score, detail, tables)
    """
    score = 0
    detail = {}
    tables = {}
    for slot in CTX_SLOTS:
        t = read_u64(base + slot)
        if t is None:
            continue
        if table_looks_valid(read_u64, t, code_lo, code_hi, readable=readable):
            score += 3
            tables[slot] = t
            detail['table_0x%X' % slot] = hex(t)
        elif code_lo <= t < code_hi:
            score += 1
            detail['codept_0x%X' % slot] = hex(t)
    for slot in IP_SLOTS:
        v = read_u64(base + slot)
        if v is not None and readable(v):
            score += 1
            detail['ip_0x%X' % slot] = hex(v)
    if read_u16 is not None:
        ip = read_u64(base + 0x92)
        if ip is not None and readable(ip):
            w = read_u16(ip)
            if w is not None:
                detail['opcode16'] = hex(w)
    return score, detail, tables


try:
    import numpy as _np
except Exception:
    _np = None


def _as_qwords(buf):
    n = len(buf) // 8 * 8
    if n <= 0:
        return None
    if _np is not None:
        return _np.frombuffer(buf, dtype='<u8', count=n // 8)
    import array
    a = array.array('Q')
    a.frombytes(buf[:n])
    return a


def find_table_runs(buf, base_va, code_lo, code_hi, min_len=DEFAULT_MIN_LEN):
    """
    找「连续 min_len 个以上都指向代码段的 qword 段」——这就是 handler 表。
    返回 [(表起始VA, 项数)]，按长度从长到短排（长的更像真表）。
    """
    a = _as_qwords(buf)
    if a is None or len(a) < min_len:
        return []
    if _np is None:
        runs = []
        i = 0
        n = len(a)
        while i < n:
            if code_lo <= a[i] < code_hi:
                j = i
                while j < n and code_lo <= a[j] < code_hi:
                    j += 1
                if j - i >= min_len:
                    runs.append((base_va + i * 8, j - i))
                i = j
            else:
                i += 1
        runs.sort(key=lambda x: -x[1])
        return runs
    m = (a >= code_lo) & (a < code_hi)
    if not m.any():
        return []
    padded = _np.concatenate(([False], m, [False]))
    d = _np.diff(padded.astype(_np.int8))
    starts = _np.flatnonzero(d == 1)
    ends = _np.flatnonzero(d == -1)
    runs = [(base_va + int(st) * 8, int(en - st))
            for st, en in zip(starts, ends) if en - st >= min_len]
    runs.sort(key=lambda x: -x[1])
    return runs


def prefilter_ctx_candidates(buf, base_va, code_lo, code_hi,
                             min_len=DEFAULT_MIN_LEN, max_tables=DEFAULT_MAX_TABLES):
    """
    两级预筛：
      1) 先找表（连续指向代码段的 qword 串），按长度取最长的 max_tables 张
      2) 再找「值等于某张表起始地址」的 qword，它的位置减去 slot 就是 ctx 候选
    返回 {ctx_va: {slot: table_va}}
    """
    runs = find_table_runs(buf, base_va, code_lo, code_hi, min_len)[:max_tables]
    if not runs:
        return {}
    table_starts = {va for va, _ in runs}
    a = _as_qwords(buf)
    out = {}
    if _np is not None:
        idxs = _np.flatnonzero(_np.isin(a, list(table_starts)))
        pos = [(base_va + int(i) * 8, int(a[i])) for i in idxs]
    else:
        pos = [(base_va + i * 8, v) for i, v in enumerate(a) if v in table_starts]
    for pc, tva in pos:
        for slot in CTX_SLOTS:
            ctx = pc - slot
            if ctx < base_va:
                continue
            out.setdefault(ctx, {})[slot] = tva
    return out


def scan_buffer(buf, base_va, code_lo, code_hi, step=8, min_score=4,
                max_check=200000, min_len=DEFAULT_MIN_LEN,
                max_tables=DEFAULT_MAX_TABLES):
    """
    在一段内存镜像里扫候选 ctx。buf 是 bytes，base_va 是它对应的虚拟地址。
    这个函数不依赖 Windows，方便单测。
    """
    n = len(buf)

    def rd64(addr, _b=buf, _lo=base_va, _n=n):
        o = addr - _lo
        if o < 0 or o + 8 > _n:
            return None
        return struct.unpack_from('<Q', _b, o)[0]

    def rd16(addr):
        o = addr - base_va
        if o < 0 or o + 2 > n:
            return None
        return struct.unpack_from('<H', buf, o)[0]

    readable = lambda a: (base_va <= a < base_va + n) or (code_lo <= a < code_hi)

    pref = prefilter_ctx_candidates(buf, base_va, code_lo, code_hi,
                                    min_len, max_tables)
    cands = sorted(pref.keys())
    out = []
    for va in cands:
        if (va - base_va) % 8:
            continue
        if not (base_va <= va < base_va + n - 0x200):
            continue
        s, d, tables = score_ctx(rd64, rd16, va, code_lo, code_hi, readable)
        if s >= min_score and tables:
            out.append({'va': va, 'score': s, 'detail': d,
                        'tables': {('0x%X' % k): ('0x%X' % v)
                                   for k, v in tables.items()}})
    out.sort(key=lambda x: -x['score'])
    return out


# ------------------------------------------------------------
# Windows 侧
# ------------------------------------------------------------
k32 = None
shell32 = None
if os.name == 'nt':
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    shell32 = ctypes.WinDLL('shell32', use_last_error=True)

    class MBI(ctypes.Structure):
        _fields_ = [('BaseAddress', ctypes.c_void_p),
                    ('AllocationBase', ctypes.c_void_p),
                    ('AllocationProtect', ctypes.c_uint32),
                    ('RegionSize', ctypes.c_size_t),
                    ('State', ctypes.c_uint32),
                    ('Protect', ctypes.c_uint32),
                    ('Type', ctypes.c_uint32)]

    class MODULEENTRY32(ctypes.Structure):
        _fields_ = [('dwSize', ctypes.c_uint32),
                    ('th32ModuleID', ctypes.c_uint32),
                    ('th32ProcessID', ctypes.c_uint32),
                    ('GlblcntUsage', ctypes.c_uint32),
                    ('ProccntUsage', ctypes.c_uint32),
                    ('modBaseAddr', ctypes.c_void_p),
                    ('modBaseSize', ctypes.c_uint32),
                    ('hModule', ctypes.c_void_p),
                    ('szModule', ctypes.c_wchar * 256),
                    ('szExePath', ctypes.c_wchar * 260)]

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [('cbSize', ctypes.c_uint32),
                    ('fMask', ctypes.c_uint32),
                    ('hwnd', ctypes.c_void_p),
                    ('lpVerb', ctypes.c_wchar_p),
                    ('lpFile', ctypes.c_wchar_p),
                    ('lpParameters', ctypes.c_wchar_p),
                    ('lpDirectory', ctypes.c_wchar_p),
                    ('nShow', ctypes.c_int),
                    ('hInstApp', ctypes.c_void_p),
                    ('lpIDList', ctypes.c_void_p),
                    ('lpClass', ctypes.c_wchar_p),
                    ('hkeyClass', ctypes.c_void_p),
                    ('dwHotKey', ctypes.c_uint32),
                    ('hIcon', ctypes.c_void_p),
                    ('hProcess', ctypes.c_void_p)]

    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    MEM_COMMIT = 0x1000
    PAGE_GUARD_ = 0x100
    PAGE_NOACCESS_ = 0x01
    PAGE_READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}   # R / RW / WC / ER / ERW / ERWC

    TH32CS_SNAPMODULE = 0x00000008
    TH32CS_SNAPMODULE32 = 0x00000010
    SEE_MASK_NOCLOSEPROCESS = 0x00000040


def is_admin():
    if os.name != 'nt':
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def open_process(pid):
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        raise OSError('OpenProcess 失败，错误码 %d' % ctypes.get_last_error())
    return h


def enum_regions(h, limit=None):
    """枚举可读的已提交区域。注意从 1 开始 —— 地址 0 会让 VirtualQueryEx 直接返回 0。"""
    addr = 0x10000
    mbi = MBI()
    out = []
    seen = 0
    while seen < 1 << 21:
        seen += 1
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                                  ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        if size <= 0:
            break
        prot = mbi.Protect
        if (mbi.State == MEM_COMMIT
                and not (prot & PAGE_GUARD_)
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
    """[(base, size, name)]，用 Toolhelp 快照拿，比从内存里猜 PE 靠谱"""
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap in (0, -1):
        return []
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(me)
    out = []
    try:
        ok = k32.Module32First(snap, ctypes.byref(me))
        while ok:
            out.append((me.modBaseAddr or 0, me.modBaseSize or 0, me.szModule))
            ok = k32.Module32Next(snap, ctypes.byref(me))
    finally:
        k32.CloseHandle(snap)
    return out


def reader(h, buf=None):
    if buf is None:
        buf = ctypes.create_string_buffer(8)

    def rd64(addr):
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, 8,
                                     ctypes.byref(got)) or got.value != 8:
            return None
        return struct.unpack('<Q', buf.raw[:8])[0]

    def rd16(addr):
        b2 = ctypes.create_string_buffer(2)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), b2, 2,
                                     ctypes.byref(got)) or got.value != 2:
            return None
        return struct.unpack('<H', b2.raw[:2])[0]

    return rd64, rd16


def pe_layout(buf):
    """
    从一段 PE 头里解析出：镜像基址、SizeOfImage、以及 .vmp/.themida 等段。
    返回 {'image_base','size_of_image','vmp_rva','vmp_vsize','sections'}，解析不出来返回 None。
    """
    if len(buf) < 0x200 or buf[:2] != b'MZ':
        return None
    e_lfanew = struct.unpack_from('<I', buf, 0x3C)[0]
    if e_lfanew + 0x108 > len(buf) or buf[e_lfanew:e_lfanew + 4] != b'PE\0\0':
        return None
    nsec = struct.unpack_from('<H', buf, e_lfanew + 6)[0]
    opt_size = struct.unpack_from('<H', buf, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from('<H', buf, opt)[0]
    if opt + 0x40 > len(buf):
        return None
    image_base = struct.unpack_from('<Q' if magic == 0x20b else '<I', buf, opt + 0x18)[0]
    size_of_image = struct.unpack_from('<I', buf, opt + 0x38)[0]
    so = opt + opt_size
    sections = []
    for i in range(nsec):
        o = so + i * 40
        if o + 40 > len(buf):
            break
        name = buf[o:o + 8].rstrip(b'\0').decode('latin1', 'replace')
        vsize = struct.unpack_from('<I', buf, o + 8)[0]
        rva = struct.unpack_from('<I', buf, o + 12)[0]
        rawsize = struct.unpack_from('<I', buf, o + 16)[0]
        sections.append((name, rva, vsize, rawsize))
    vmp = None
    for name, rva, vsize, rawsize in sections:
        if name.lower() in ('.vmp', '.themida', 'vmp', '.enigma1', '.enigma2'):
            vmp = (rva, vsize)
            break
    return {'image_base': image_base, 'size_of_image': size_of_image,
            'vmp_rva': vmp[0] if vmp else None,
            'vmp_vsize': vmp[1] if vmp else None,
            'sections': sections}


def read_pe_layout(h, base, size=0x2000):
    """从进程里把模块头读出来解析段表"""
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, size,
                                 ctypes.byref(got)) or got.value < 0x200:
        return None
    return pe_layout(buf.raw[:got.value])


def module_range(h, pid=None, exe_name=None):
    """拿主模块（名字匹配 exe）的区间，返回 (code_lo, code_hi, name)"""
    mods = list_modules(pid) if pid else []
    if mods:
        pick = None
        if exe_name:
            low = exe_name.lower()
            for b, s, n in mods:
                if n.lower() == low:
                    pick = (b, s, n)
                    break
        if pick is None:
            # 取基址最低的那个（主镜像一般被最先映射）
            pick = sorted(mods, key=lambda x: x[0])[0]
        base, size, name = pick
        lay = read_pe_layout(h, base)
        hi = base + ((lay or {}).get('size_of_image') or size)
        return base, hi, name
    return None, None, None


def launch(exe, args='', elevate=True, wait=0.0):
    """
    启动 requireAdministrator 的 exe。
    直接 Popen 会 740 (ERROR_ELEVATION_REQUIRED)，改用 ShellExecuteEx + runas。
    """
    exe = os.path.abspath(exe)
    cwd = os.path.dirname(exe) or None
    try:
        p = subprocess.Popen([exe] + ([args] if args else []), cwd=cwd)
        time.sleep(wait)
        return p.pid
    except OSError as e:
        if getattr(e, 'winerror', None) != 740 and 'elevation' not in str(e).lower():
            raise
        print('[*] 直接启动被拒（需要管理员），改用 runas 提权启动')

    if not elevate:
        raise OSError('目标要求管理员权限，且指定了不提权')

    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.lpVerb = 'runas'
    sei.lpFile = exe
    sei.lpParameters = args or None
    sei.lpDirectory = cwd
    sei.nShow = 1
    if not shell32.ShellExecuteExW(ctypes.byref(sei)):
        err = ctypes.get_last_error()
        raise OSError('ShellExecuteExW(runas) 失败，错误码 %d' % err)
    pid = k32.GetProcessId(sei.hProcess) if sei.hProcess else 0
    if sei.hProcess:
        k32.CloseHandle(sei.hProcess)
    if not pid:
        raise OSError('提权启动后拿不到 pid')
    time.sleep(wait)
    return pid


def live_scan(h, code_lo, code_hi, min_score=4, chunk=32 << 20,
              max_ctx_per_chunk=200, skip_module_image=True,
              progress=None, deadline=None, min_len=DEFAULT_MIN_LEN,
              max_tables=DEFAULT_MAX_TABLES):
    """扫整个进程的可读内存，返回候选列表（按分数降序）"""
    rd64, rd16 = reader(h)
    code_lo = code_lo or 0
    code_hi = code_hi or 0x7FFFFFFFFFFF
    hits = []

    regions = enum_regions(h)
    # 先扫模块自己的镜像（VM 上下文常在 .data/.vmp 里），再扫堆
    def rank(r):
        base, size, prot = r
        in_img = code_lo <= base < code_hi
        return (0 if in_img else 1, -size)

    for base, size, prot in sorted(regions, key=rank):
        if deadline and time.time() > deadline:
            break
        in_img = code_lo <= base < code_hi
        if in_img and skip_module_image:
            continue
        done = 0
        while done < size:
            if deadline and time.time() > deadline:
                break
            n = min(chunk, size - done)
            n -= n % 8
            if n <= 0:
                break
            buf = ctypes.create_string_buffer(n)
            got = ctypes.c_size_t(0)
            if not k32.ReadProcessMemory(h, ctypes.c_void_p(base + done), buf, n,
                                         ctypes.byref(got)) or got.value < 64:
                break
            data = buf.raw[:got.value]
            va = base + done
            pref = prefilter_ctx_candidates(data, va, code_lo, code_hi,
                                           min_len, max_tables)
            for ctx_va in list(pref)[:max_ctx_per_chunk]:
                sc, det, tables = score_ctx(rd64, rd16, ctx_va, code_lo, code_hi,
                                            lambda a: True)
                if sc >= min_score and tables:
                    hits.append({'va': ctx_va, 'score': sc, 'detail': det,
                                 'tables': {('0x%X' % k): ('0x%X' % v)
                                            for k, v in tables.items()}})
            if progress:
                progress(va, len(hits))
            done += got.value
    hits.sort(key=lambda x: -x['score'])
    return hits


def dump_tables(h, ctx_va, slots=CTX_SLOTS, maxn=DEFAULT_MAXN,
                code_lo=0, code_hi=0):
    """把 ctx 里每个槽指向的表整张读出来；出代码段/遇到 0 就停"""
    rd64, _ = reader(h)
    out = {}
    for s in slots:
        t = rd64(ctx_va + s)
        if t is None or t == 0:
            continue
        items = []
        for i in range(maxn):
            v = rd64(t + i * 8)
            if v is None or v == 0:
                break
            if code_lo and code_hi and not (code_lo <= v < code_hi):
                break
            items.append(v)
        if items:
            out['0x%X' % s] = {'table_va': '0x%X' % t, 'entries': items}
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', help='启动这个程序后抓它')
    ap.add_argument('--args', default='', help='传给程序的参数')
    ap.add_argument('--pid', type=int, help='直接附加已有进程')
    ap.add_argument('--seconds', type=float, default=60.0, help='轮询时长')
    ap.add_argument('--interval', type=float, default=2.0)
    ap.add_argument('--out', default='tables.json')
    ap.add_argument('--min-score', type=int, default=4)
    ap.add_argument('--image', default=None, help='扫不到就把内存存成这个 memimage 再离线扫')
    ap.add_argument('--no-image', action='store_true', help='不存内存镜像')
    ap.add_argument('--no-elevate', action='store_true')
    a = ap.parse_args()

    if os.name != 'nt':
        print('[!] 这个脚本要在 Windows 上跑（GitHub Actions 的 windows-latest 就行）')
        print('    本地自检请用 local_selftest.py')
        return 2

    print('[*] 管理员: %s' % is_admin())

    proc = None
    pid = a.pid
    if a.exe:
        pid = launch(a.exe, a.args, elevate=not a.no_elevate, wait=3.0)
        print('[*] 已启动 pid=%d' % pid)
    if not pid:
        print('[!] 需要 --exe 或 --pid')
        return 2

    deadline = time.time() + a.seconds
    h = None
    best = None
    code_lo = code_hi = None
    lay = None
    name = None

    while time.time() < deadline:
        try:
            if h is None:
                h = open_process(pid)
                code_lo, code_hi, name = module_range(h, pid, os.path.basename(a.exe or ''))
                print('[*] 模块 %s  区间 0x%X .. 0x%X' % (name, code_lo or 0, code_hi or 0))
                lay = read_pe_layout(h, code_lo) if code_lo else None
                if lay:
                    print('[*] 镜像基址 0x%X  SizeOfImage 0x%X'
                          % (lay['image_base'], lay['size_of_image']))
                    for nm, rva, vs, rs in lay['sections']:
                        print('      %-10s RVA 0x%-9X VSize 0x%-9X Raw 0x%X'
                              % (nm or '(无)', rva, vs, rs))
                    if lay['vmp_rva'] is not None:
                        print('[*] VM 段 RVA 0x%X VSize 0x%X'
                              % (lay['vmp_rva'], lay['vmp_vsize']))
            hits = live_scan(h, code_lo, code_hi, a.min_score,
                             deadline=deadline, skip_module_image=False)
            if hits:
                best = hits[0]
                print('[*] 命中 %d 个候选，最高分 %d @0x%X'
                      % (len(hits), best['score'], best['va']))
                for k, v in sorted(best['detail'].items()):
                    print('      %-14s %s' % (k, v))
                break
            print('[*] 这一轮没命中，%.1fs 后重试' % a.interval)
        except OSError as e:
            print('[!] %s' % e)
        time.sleep(a.interval)

    # 在线扫不到 → 存内存镜像，离线再扫（同算法，可复算）
    source = 'live'
    tables = None
    if best is not None:
        tables = dump_tables(h, best['va'], code_lo=code_lo or 0, code_hi=code_hi or 0)
    elif a.image and h:
        import memimage
        print('[*] 在线没命中，存内存镜像 %s' % a.image)
        n = memimage.save_process(h, a.image, enum_regions(h))
        print('[*] 镜像 %d 个区域，%.1f MB' % (n, os.path.getsize(a.image) / 1e6))
        hits = memimage.scan_image(a.image, code_lo, code_hi, a.min_score)
        if hits:
            best = hits[0]
            source = 'memimage'
            print('[*] 离线扫命中 %d 个候选，最高分 %d @0x%X'
                  % (len(hits), best['score'], best['va']))
            tables = memimage.dump_tables(a.image, best['va'], code_lo or 0, code_hi or 0)

    if best is None:
        print('[!] 没找到上下文候选')
        return 1

    out = {'pid': pid, 'ctx_va': '0x%X' % best['va'], 'score': best['score'],
           'detail': best['detail'], 'tables': tables,
           'module_base': '0x%X' % (code_lo or 0),
           'module_name': name,
           'image_base': ('0x%X' % lay['image_base']) if lay else None,
           'vmp_rva': ('0x%X' % lay['vmp_rva']) if lay and lay['vmp_rva'] else None,
           'vmp_vsize': ('0x%X' % lay['vmp_vsize']) if lay and lay['vmp_vsize'] else None,
           'source': source}
    with open(a.out, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print('[+] 已写入 %s' % a.out)
    for k, v in tables.items():
        print('    ctx+%s -> table %s，%d 项' % (k, v['table_va'], len(v['entries'])))
    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)

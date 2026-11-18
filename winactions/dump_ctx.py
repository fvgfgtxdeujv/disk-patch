# -*- coding: utf-8 -*-
"""
===============================================================
  dump_ctx.py —— 在 Windows 上抓 VM 上下文，导出 handler 表
===============================================================
不注入、不调试，只用 ReadProcessMemory：起进程 -> 枚举内存 -> 找 VM 上下文
-> 把 ctx+0x4 / 0x8 / 0xF5 指向的 handler 表整张读出来 -> 存 JSON。

为什么这么做：
  * Frida / 调试器会被 WinLicense 一类的保护检测，Actions runner 上八成直接崩；
  * ReadProcessMemory 通常不拦（保护主要防调试器和代码改写）；
  * 不依赖版本、不依赖之前算出来的 3314 个派发点地址 —— 换版本也能用。

判定「这是 VM 上下文」的依据（多级，逐级加强）：
  1. ctx+0      -> 指向一段可读内存（VM 字节流指针或栈指针）
  2. ctx+0x4    -> 指向本模块代码段（handler 表基址）
  3. ctx+0x8    -> 指向本模块代码段
  4. 以 2/3 为基址的前 32 个 qword 全都落在代码段（这才像表）
  5. ctx+0x92   -> 指向可读内存（IP 指针）

用法（Windows）：
  python dump_ctx.py --exe DiskGenius.exe --seconds 30 --out tables.json
  python dump_ctx.py --pid 1234 --out tables.json
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import subprocess
import sys
import time

# ------------------------------------------------------------
# 平台无关的扫描核心（在 Linux 上也能单测）
# ------------------------------------------------------------
# 实测出的表指针槽。注意 0x4 与 0x8 作为 8 字节指针会互相重叠，
# 同一个上下文里不可能同时成立 —— 遇到它们只可能命中一个，属正常。
CTX_SLOTS = (0x4, 0x8, 0xF5, 0x110, 0x1F4)
IP_SLOTS = (0x92, 0x18, 0x120, 0x55, 0x17A)


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
    返回 (score, detail)
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


def find_table_runs(buf, base_va, code_lo, code_hi, min_len=8):
    """
    找「连续 min_len 个以上都指向代码段的 qword 段」——这就是 handler 表。
    返回 [(表起始VA, 项数)]。
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
        return runs
    m = (a >= code_lo) & (a < code_hi)
    # 连续 True 段
    padded = _np.concatenate(([False], m, [False]))
    d = _np.diff(padded.astype(_np.int8))
    starts = _np.flatnonzero(d == 1)
    ends = _np.flatnonzero(d == -1)
    return [(base_va + int(st) * 8, int(en - st))
            for st, en in zip(starts, ends) if en - st >= min_len]


def prefilter_ctx_candidates(buf, base_va, code_lo, code_hi, min_len=8, max_tables=4096):
    """
    两级预筛：
      1) 先找表（连续指向代码段的 qword 串）
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


def scan_buffer(buf, base_va, code_lo, code_hi, step=8, min_score=4, max_check=200000):
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

    pref = prefilter_ctx_candidates(buf, base_va, code_lo, code_hi)
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
                        'tables': {('0x%X' % k): ('0x%X' % v) for k, v in tables.items()}})
    out.sort(key=lambda x: -x['score'])
    return out


# ------------------------------------------------------------
# Windows 侧
# ------------------------------------------------------------
k32 = None
if os.name == 'nt':
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)

    class MBI(ctypes.Structure):
        _fields_ = [('BaseAddress', ctypes.c_void_p),
                    ('AllocationBase', ctypes.c_void_p),
                    ('AllocationProtect', wt.DWORD),
                    ('RegionSize', ctypes.c_size_t),
                    ('State', wt.DWORD),
                    ('Protect', wt.DWORD),
                    ('Type', wt.DWORD)]

    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    MEM_COMMIT = 0x1000
    PAGE_READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}   # R / RW / WC / ER / ERW / ERWC


def open_process(pid):
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        raise OSError('OpenProcess 失败，错误码 %d' % ctypes.get_last_error())
    return h


def enum_regions(h, limit=None):
    """枚举可读的已提交区域"""
    addr = 0
    mbi = MBI()
    out = []
    while k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        if mbi.State == MEM_COMMIT and (mbi.Protect & 0xFF) in PAGE_READABLE:
            out.append((base, size, mbi.Protect))
            if limit and len(out) >= limit:
                break
        nxt = base + size
        if nxt <= addr:
            break
        addr = nxt
    return out


def reader(h):
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
    从一段 PE 头里解析出：镜像基址、SizeOfImage、以及 .vmp/.themida/.boot 等段。
    返回 {'image_base':..,'size_of_image':..,'vmp_rva':..,'vmp_vsize':..,'sections':[(name,rva,vsize,rawsize)]}
    解析不出来返回 None。
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


def read_pe_layout(h, base):
    """从进程里把模块头读出来解析段表"""
    buf = ctypes.create_string_buffer(0x2000)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, 0x2000,
                                 ctypes.byref(got)) or got.value < 0x200:
        return None
    return pe_layout(buf.raw[:got.value])


def module_range(h, name_hint=None):
    """拿主模块（或名字匹配的模块）的代码段区间"""
    # 简化：取进程里第一个 PE 头 + 其 SizeOfImage
    for base, size, prot in enum_regions(h):
        if size < 0x1000:
            continue
        head = ctypes.create_string_buffer(0x400)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(base), head, 0x400,
                                     ctypes.byref(got)) or got.value < 0x40:
            continue
        if head.raw[:2] != b'MZ':
            continue
        e_lfanew = struct.unpack_from('<I', head.raw, 0x3C)[0]
        if e_lfanew + 0x60 > 0x400:
            continue
        if head.raw[e_lfanew:e_lfanew + 4] != b'PE\0\0':
            continue
        size_of_image = struct.unpack_from('<I', head.raw, e_lfanew + 0x18 + 0x38)[0]
        if size_of_image > 0x1000:
            return base, base + size_of_image
    return None, None


def dump_tables(h, ctx_va, slots=CTX_SLOTS, maxn=512):
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
            items.append(v)
            if len(items) >= 8 and len(set(items[-8:])) == 1:
                break            # 连续 8 个一样，基本是填充
        if items:
            out['0x%X' % s] = {'table_va': '0x%X' % t, 'entries': items}
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', help='启动这个程序后抓它')
    ap.add_argument('--args', default='', help='传给程序的参数')
    ap.add_argument('--pid', type=int, help='直接附加已有进程')
    ap.add_argument('--seconds', type=float, default=30.0, help='轮询时长')
    ap.add_argument('--interval', type=float, default=2.0)
    ap.add_argument('--out', default='tables.json')
    ap.add_argument('--min-score', type=int, default=4)
    a = ap.parse_args()

    if os.name != 'nt':
        print('[!] 这个脚本要在 Windows 上跑（GitHub Actions 的 windows-latest 就行）')
        print('    本地自检请用 local_selftest.py')
        return 2

    proc = None
    pid = a.pid
    if a.exe:
        proc = subprocess.Popen([a.exe] + ([a.args] if a.args else []),
                                cwd=os.path.dirname(os.path.abspath(a.exe)) or None)
        pid = proc.pid
        print('[*] 已启动 %s  pid=%d' % (a.exe, pid))
    if not pid:
        print('[!] 需要 --exe 或 --pid')
        return 2

    h = None
    deadline = time.time() + a.seconds
    best = None
    while time.time() < deadline:
        try:
            if h is None:
                h = open_process(pid)
                code_lo, code_hi = module_range(h)
                print('[*] 模块区间 0x%X .. 0x%X' % (code_lo or 0, code_hi or 0))
                lay = read_pe_layout(h, code_lo) if code_lo else None
                if lay:
                    print('[*] 镜像基址 0x%X  SizeOfImage 0x%X'
                          % (lay['image_base'], lay['size_of_image']))
                    for nm, rva, vs, rs in lay['sections']:
                        print('      %-8s RVA 0x%-8X VSize 0x%-8X Raw 0x%X'
                              % (nm or '(无)', rva, vs, rs))
                    if lay['vmp_rva'] is not None:
                        print('[*] VM 段 .vmp RVA 0x%X VSize 0x%X'
                              % (lay['vmp_rva'], lay['vmp_vsize']))
                globals()['_LAYOUT'] = lay
            rd64, rd16 = reader(h)
            hits = []
            for base, size, prot in enum_regions(h):
                if code_lo and code_lo <= base < code_hi:
                    continue                      # 跳过模块本身
                CH = 64 * 1024 * 1024
                done = 0
                while done < size:
                    chunk = min(CH, size - done)
                    buf = ctypes.create_string_buffer(chunk)
                    got = ctypes.c_size_t(0)
                    if not k32.ReadProcessMemory(h, ctypes.c_void_p(base + done),
                                                 buf, chunk, ctypes.byref(got)):
                        break
                    data = buf.raw[:got.value]
                    pref = prefilter_ctx_candidates(data, base + done, code_lo, code_hi)
                    for ctx_va in list(pref)[:200]:
                        sc, det, tables = score_ctx(rd64, rd16, ctx_va,
                                                    code_lo, code_hi, lambda a: True)
                        if sc >= a.min_score and tables:
                            hits.append({'va': ctx_va, 'score': sc, 'detail': det,
                                         'tables': {('0x%X' % k): ('0x%X' % v)
                                                    for k, v in tables.items()}})
                    done += chunk
            hits.sort(key=lambda x: -x['score'])
            if hits:
                best = hits[0]
                print('[*] 命中 %d 个候选，最高分 %d @0x%X'
                      % (len(hits), best['score'], best['va']))
                for k, v in sorted(best['detail'].items()):
                    print('      %-14s %s' % (k, v))
                break
        except OSError as e:
            print('[!] %s' % e)
        time.sleep(a.interval)

    if not best:
        print('[!] 没找到上下文候选')
        return 1

    tables = dump_tables(h, best['va'])
    lay = globals().get('_LAYOUT')
    out = {'pid': pid, 'ctx_va': '0x%X' % best['va'], 'score': best['score'],
           'detail': best['detail'], 'tables': tables,
           'module_base': '0x%X' % (code_lo or 0),
           'image_base': ('0x%X' % lay['image_base']) if lay else None,
           'vmp_rva': ('0x%X' % lay['vmp_rva']) if lay and lay['vmp_rva'] else None,
           'vmp_vsize': ('0x%X' % lay['vmp_vsize']) if lay and lay['vmp_vsize'] else None}
    json.dump(out, open(a.out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('[+] 已写入 %s' % a.out)
    for k, v in tables.items():
        print('    ctx+%s -> table %s，%d 项' % (k, v['table_va'], len(v['entries'])))
    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)

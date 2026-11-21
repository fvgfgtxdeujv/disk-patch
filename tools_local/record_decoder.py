#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""逐记录解码器 v2：用 unicorn 以真实 ctx 状态 + 真实 32B 包密文 + 真实桩环境
（表=桩指针、桩区可执行）执行每条记录的 handler，从真实密钥的自然解密中
得到 packet 语义。

输入：artdir（vm_trace.json, ctx_ring.bin, bc_window_1s.bin 及同轮 VMP 快照）
输出：默认 artdir/decoded.json（读写日志、截断点、next_op 反查）
验证：执行流截断于下一记录的桩入口；原生 API / ret 边界需结合 err、hit_next、stop 分析。
"""
import argparse, bisect, json, struct, os, re, sys
from unicorn import *
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VBASE = 0x1419d4000
DUMP = b''
DEND = VBASE
MD = Cs(CS_ARCH_X86, CS_MODE_64)

WIN_LO = 0x142140000           # bc_window 快照起 VA（主模块 base+0x2140000）

# ---- 运行时桩环境（与 dump_runtime.table_hook_fullctx 完全一致的地址布局）----
ALLOC = 0x100000000
COUNT_VA = ALLOC
PROBE_VA = ALLOC + 0x100
SEEN_VA = ALLOC + 0x100000
STUB_VA = ALLOC + 0x2100000
BUF_VA = ALLOC + 0x2200000
RING_VA = ALLOC + 0x3000000
STUB12_SZ = 0x300
REC12_MAX = 8000
LOW_LO = 0x13E0000         # VM 低区工作区：7 位 hex！bad 地址 0x13FFEF8=20,971,256
LOW_HI = 0x1400000         # ∈ [0x13FE0000, 0x1400000)≈20-21MB；v28 起误写成 8 位


def _load_stub_builder(runtime_script):
    """从 dump_runtime.py 提取 _build_stub12（依赖 struct/STUB12_SZ）。"""
    with open(runtime_script, encoding='utf-8') as f:
        src = f.read()
    i0 = src.index('def _build_stub12')
    i1 = src.index('def _build_stub11')
    ns = {'struct': struct, 'STUB12_SZ': STUB12_SZ, 'REC12_MAX': REC12_MAX,
          'STK_SZ': 0x400}
    exec(compile(src[i0:i1], 'stub12', 'exec'), ns)
    return ns['_build_stub12']


def follow_chain(va):
    while True:
        if not (VBASE <= va < DEND):
            return va
        off = va - VBASE
        i = next(MD.disasm(DUMP[off:off + 16], va), None)
        if i and i.mnemonic == 'jmp' and re.match(r'^0x[0-9a-f]+$', i.op_str):
            va = int(i.op_str, 16)
        else:
            return va


# ---- 原生 API 归属 ----------------------------------------------------------
# op574/op46/op27 的 handler 尾部是 pop ...; ret，ret 目标 = ctx[0x32] + u32@ip，
# 即 VM 主动跳进系统 DLL。系统 DLL 在同一次开机内跨进程基址一致，故可用本进程
# 模块表解析；导出名按 RVA 就近查 PE 导出表。
MODRANGES = []
EXP_CACHE = {}


def _module_ranges():
    try:
        if ROOT not in sys.path:
            sys.path.insert(0, ROOT)
        from winactions.dump_runtime import list_modules
        return [(b, b + s, n) for b, s, n in list_modules(os.getpid())
                if b >= 0x7FF000000000]
    except Exception:
        return []


def _exp_str(e):
    n = e.name if e.name is not None else ('#%d' % e.ordinal)
    return n.decode('latin1') if isinstance(n, bytes) else str(n)


def _export_name(module, rva):
    key = module.lower()
    if key not in EXP_CACHE:
        try:
            import pefile
            p = pefile.PE(os.path.join(os.environ['SystemRoot'], 'System32',
                                       module), fast_load=True)
            p.parse_data_directories(directories=[0])
            es = sorted((e.address, _exp_str(e))
                        for e in p.DIRECTORY_ENTRY_EXPORT.symbols)
            EXP_CACHE[key] = ([a for a, _ in es], es)
        except Exception:
            EXP_CACHE[key] = ([], [])
    addrs, es = EXP_CACHE[key]
    if not addrs:
        return None
    i = bisect.bisect_right(addrs, rva) - 1
    if i < 0:
        return None
    a, n = es[i]
    return n if rva - a < 0x1000 else None


def resolve_native(addr):
    global MODRANGES
    if not MODRANGES:
        MODRANGES = _module_ranges()
    for lo, hi, name in MODRANGES:
        if lo <= addr < hi:
            rva = addr - lo
            return {'module': name, 'rva': rva,
                    'export': _export_name(name, rva)}
    return None


def _read_cstr(uc, ptr, wide=False, limit=96):
    if not ptr or ptr < 0x10000:
        return None
    try:
        raw = uc.mem_read(ptr, limit)
    except UcError:
        return None
    if wide:
        s = raw[:len(raw) & ~1].decode('utf-16-le', 'replace')
        return s.split('\x00')[0]
    return raw.split(b'\x00')[0].decode('latin1')


EXIT_BODIES = {}


def _is_exit_body(body):
    """原生边界类 op：handler 尾部是 pop...; popfq; ret，不派发下一条 VM 指令。

    op574 用它 ret 进 Win32/ntdll；op27 用它离开 VM 回到原生调用方。这类记录
    天然到不了「下一条桩」，不能按 nomatch 计。
    """
    if body not in EXIT_BODIES:
        ok = False
        if VBASE <= body < DEND:
            prev = None
            for i in MD.disasm(DUMP[body - VBASE:body - VBASE + 0x400], body):
                if i.mnemonic == 'ret' and prev == 'popfq':
                    ok = True
                    break
                prev = i.mnemonic
        EXIT_BODIES[body] = ok
    return EXIT_BODIES[body]


def _native_args(uc, addr):
    """x64 前四个参数：rcx/rdx/r8/r9；对已知字符串 API 顺带取实参内容。"""
    info = resolve_native(addr)
    if not info:
        return None
    args = {'rcx': uc.reg_read(UC_X86_REG_RCX),
            'rdx': uc.reg_read(UC_X86_REG_RDX),
            'r8': uc.reg_read(UC_X86_REG_R8),
            'r9': uc.reg_read(UC_X86_REG_R9)}
    info['args'] = args
    exp = (info['export'] or '').lower()
    if exp.startswith('lstrcmpi'):
        wide = exp.endswith('w')
        info['str'] = [_read_cstr(uc, args['rcx'], wide),
                       _read_cstr(uc, args['rdx'], wide)]
    elif exp == 'getprocaddress':
        info['str'] = [_read_cstr(uc, args['rdx'])]
    return info



def main(artdir, dump_path=None, out_path=None, runtime_script=None):
    global DUMP, DEND
    dump_path = dump_path or os.path.join(artdir, 'vmp_unpacked_6201829.bin')
    out_path = out_path or os.path.join(artdir, 'decoded.json')
    runtime_script = runtime_script or os.path.join(ROOT, 'winactions', 'dump_runtime.py')
    with open(dump_path, 'rb') as f:
        DUMP = f.read()
    DEND = VBASE + len(DUMP)
    with open(os.path.join(artdir, 'vm_trace.json'), encoding='utf-8') as f:
        tr = json.load(f)
    t = tr['trace']
    ring = open(os.path.join(artdir, 'ctx_ring.bin'), 'rb').read()
    nrec = tr['n']
    lay = tr.get('ring_layout') or {'slot': 0x1000, 'low': None,
                                    'low_va': LOW_LO}
    SLOT = lay['slot']
    LOW_VA = lay['low_va']
    # 低区内容：NOACCESS 陷阱页（CPU 不可读、桩不复制），用 host 侧 RPM 快照
    low_data = None
    import glob
    snaps = sorted(glob.glob(os.path.join(artdir, 'low_snap_*.bin')))
    if snaps:
        low_data = open(snaps[-1], 'rb').read()
        print('低区快照: %s（%d 字节，非零 %d）'
              % (snaps[-1], len(low_data), sum(1 for b in low_data if b)),
              flush=True)
    # VM 输入数据区 0x100000..0x1400000（含授权结构 0x1d0000 区，运行时分配）
    heap_data = None
    hsnap = sorted(glob.glob(os.path.join(artdir, 'heap_snap_*.bin')))
    if hsnap:
        heap_data = open(hsnap[-1], 'rb').read()
        print('堆区快照: %s（%d 字节，非零 %d）'
              % (hsnap[-1], len(heap_data), sum(1 for b in heap_data if b)),
              flush=True)
    # 原生栈窗口（采集端 stub12 从 handler 入口 rsp 起复制）。
    # 仅作证据保留：真实栈注入会让 op574 跳出沙箱并污染重放状态，见报告 §17。
    stk_path = os.path.join(artdir, 'stack_ring.bin')
    stk = b''
    if os.path.exists(stk_path):
        stk = open(stk_path, 'rb').read()
        print('栈窗口: %s（%d 槽 × %d 字节，仅记录不注入）'
              % (stk_path, len(stk) // 0x400, 0x400), flush=True)
    print('记录 %d，ring %.1f MB (%d 槽，槽 %#x)'
          % (nrec, len(ring) / 1048576, len(ring) // SLOT, SLOT), flush=True)
    win = open(os.path.join(artdir, 'bc_window_1s.bin'), 'rb').read()

    TBL_VA = 0x1421080ab
    tbl_off = TBL_VA - VBASE
    n_ent = 661
    table = list(struct.unpack_from('<%dQ' % n_ent, DUMP, tbl_off))
    stub_builder = _load_stub_builder(runtime_script)
    # 桩 blob（tag 传 0：不影响 VM 语义）
    stub_blob = bytearray()
    for ei in range(n_ent):
        st = stub_builder(table[ei], 0, PROBE_VA, SEEN_VA, 0x1419d4000,
                          0x142780000, COUNT_VA, BUF_VA, RING_VA)
        stub_blob += st + b'\xcc' * (STUB12_SZ - len(st))
    assert len(stub_blob) == n_ent * STUB12_SZ
    # 桩指针反查 op
    stub2op = {STUB_VA + ei * STUB12_SZ: ei for ei in range(n_ent)}
    newtab = struct.pack('<%dQ' % n_ent,
                         *[STUB_VA + ei * STUB12_SZ for ei in range(n_ent)])

    # ---- 静态环境（一次构建，逐记录复用）----
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(VBASE & ~0xFFF, (len(DUMP) + 0xFFF) & ~0xFFF)
    uc.mem_write(VBASE, DUMP)
    uc.mem_write(TBL_VA, newtab)              # 表 = 桩指针（真实运行时形态）
    uc.mem_map(STUB_VA, (n_ent * STUB12_SZ + 0xFFF) & ~0xFFF)
    uc.mem_write(STUB_VA, bytes(stub_blob))
    uc.mem_map(COUNT_VA & ~0xFFF, 0x1000)     # count + probe
    uc.mem_map(SEEN_VA, 0x80000)              # seen 512KB
    uc.mem_map(BUF_VA, 0x100000)              # buf 1MB
    uc.mem_map(RING_VA, ((nrec + 1) * 0x1000 + 0xFFF) & ~0xFFF)  # ring
    uc.mem_map(0x100000, LOW_LO - 0x100000)  # 原生侧低区堆
    uc.mem_map(LOW_LO, 0x14000000 - LOW_LO)  # VM 低区工作区
    if low_data:
        uc.mem_write(LOW_VA, low_data)
    if heap_data:
        uc.mem_write(0x1b0000, heap_data)
    # v42：逐 region 堆快照写回（heapr_<s>_<0xVA>.bin / hotr_<ts>_<0xVA>.bin）
    heap_regions = []
    for pat in ('heapr_*.bin', 'hotr_*.bin'):
        for fn in sorted(glob.glob(os.path.join(artdir, pat))):
            base = os.path.basename(fn)[:-4].rsplit('_', 1)[-1]
            if not base.startswith('0x'):
                continue
            try:
                va = int(base, 16)
            except ValueError:
                continue
            blob = open(fn, 'rb').read()
            heap_regions.append((va, blob))
    if heap_regions:
        for va, blob in heap_regions:
            if va >= 0x100000 and va + len(blob) <= 0x14000000:
                uc.mem_write(va, blob)
        print('堆 region 写回 %d 块（%s）' % (
            len(heap_regions),
            ' '.join('%#x+%d' % (va, len(b)) for va, b in heap_regions[:8])),
            flush=True)
    uc.mem_map(0x50000000, 0x100000)          # 合成栈
    uc.reg_write(UC_X86_REG_RSP, 0x50080000)
    uc.mem_map(0x70000000, 0x2000)            # 最小 TEB（gs:[0x30] = TEB 自指针）
    uc.mem_write(0x70000030, struct.pack('<Q', 0x70000000))
    uc.reg_write(UC_X86_REG_GS_BASE, 0x70000000)

    out = []
    stats = {'ok': 0, 'native': 0, 'exit': 0, 'bad': 0, 'skip': 0}
    ctx0 = None
    bc_base = bc_len = 0
    woff = 0
    reads = writes = None

    def hk_mem(uc, access, address, size, value, ud):
        if access == UC_MEM_READ:
            if ctx0 is not None and rbp <= address < rbp + 0x1000:
                i = address - rbp
                v = int.from_bytes(ctx0[i:i + size], 'little')
                reads.append(('ctx', address - rbp, size, v))
            elif bc_base <= address < bc_base + bc_len:
                off = address - bc_base
                v = int.from_bytes(win[woff + off:woff + off + size], 'little') \
                    if 0 <= woff + off < len(win) else 0
                reads.append(('bc', address - bc_base, size, v))
            elif VBASE <= address < DEND:
                reads.append(('code', address, size, 0))
        else:
            if ctx0 is not None and rbp <= address < rbp + 0x1000:
                writes.append(('ctx', address - rbp, size, value))
            elif bc_base <= address < bc_base + bc_len:
                writes.append(('bc', address - bc_base, size, value))
            else:
                writes.append(('other', address, size, value))

    for ri in range(nrec - 1):
        e = t[ri]
        nxt = t[ri + 1]
        # fmt: [ip, [ip], [ip+8], [ip+16], [ip+24], tag, orig, rbp, tbl, rsp]
        ip, b0, b8, b16, b24, tag, orig, rbp, tblb, _rsp = e
        if not ip or not (VBASE <= orig < DEND):
            stats['skip'] += 1
            continue
        if len(ring) < (ri + 1) * SLOT:
            stats['skip'] += 1
            continue
        ctx0 = ring[ri * SLOT:(ri + 1) * SLOT]
        body = follow_chain(orig)
        # ---- 每记录动态环境 ----
        bc_base = (ip - 0x400) & ~0xFFF
        bc_len = 0x2000
        if not (bc_base & 0xFFF):
            pass
        try:
            uc.mem_map(bc_base, bc_len)
        except UcError:
            pass  # 已映射（重复执行同页，理论上不会）
        woff = bc_base - WIN_LO
        if 0 <= woff and woff + bc_len <= len(win):
            uc.mem_write(bc_base, win[woff:woff + bc_len])
        else:
            woff = -1
        pkt = struct.pack('<QQQQ', b0, b8, b16, b24)
        uc.mem_write(ip, pkt)
        # ctx 快照是 [rbp, rbp+0x1000)（rep movsq 从非页对齐的 rbp 复制）——
        # 必须写回 rbp 起，错位会导致 IP 槽读到 0（v27 教训）
        uc.mem_write(rbp, ctx0)
        uc.reg_write(UC_X86_REG_RBP, rbp)
        # 截断：到达下一记录的桩入口
        next_stub = STUB_VA + nxt[5] * STUB12_SZ
        stop_ip = [None]
        last_insn = [0]
        tail = []
        natives = []
        native_addr = [0]
        seen_stub = [None]

        def hk_code(uc, address, size, ud):
            last_insn[0] = address
            tail.append(address)
            if len(tail) > 12:
                del tail[0]
            if address == next_stub:
                stop_ip[0] = address
                uc.emu_stop()
            elif STUB_VA <= address < STUB_VA + n_ent * STUB12_SZ:
                if seen_stub[0] is None:
                    seen_stub[0] = (address - STUB_VA) // STUB12_SZ
            elif not (VBASE <= address < DEND) and \
                    not (ALLOC <= address < ALLOC + 0x10000):
                if 0x7FF000000000 <= address < 0x800000000000:
                    native_addr[0] = address
                    stop_ip[0] = 'native:%#x' % address
                else:
                    stop_ip[0] = 'out:%#x' % address
                uc.emu_stop()

        bad = []

        def hk_unmapped(uc, access, address, size, value, ud):
            if access == UC_MEM_FETCH_UNMAPPED and \
                    0x7FF000000000 <= address < 0x800000000000:
                # 系统 DLL 未映射：op574 的原生 API 边界，不是解码失败
                native_addr[0] = address
                stop_ip[0] = 'native:%#x' % address
            else:
                bad.append((access, address, size))
            uc.emu_stop()

        h_code = uc.hook_add(UC_HOOK_CODE, hk_code)
        h_mem = uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hk_mem)
        h_unmapped = uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
            UC_HOOK_MEM_FETCH_UNMAPPED, hk_unmapped)
        reads, writes = [], []
        err = None
        try:
            uc.emu_start(body, 0, count=20000)
        except UcError as ex:
            err = '%s@%#x' % (ex, uc.reg_read(UC_X86_REG_RIP))
        rip = uc.reg_read(UC_X86_REG_RIP)
        uc.hook_del(h_code)
        uc.hook_del(h_mem)
        uc.hook_del(h_unmapped)
        hit = stop_ip[0] == next_stub
        nop = stub2op.get(rip)
        if native_addr[0]:
            info = _native_args(uc, native_addr[0])
            natives.append(info or {'addr': native_addr[0]})
        if natives:
            kind = 'native'
        elif hit:
            kind = 'ok'
        elif _is_exit_body(body):
            kind = 'exit'
        else:
            kind = 'bad'
        rec = {'ri': ri, 'ip': ip, 'tag': tag, 'orig': orig, 'body': body,
               'n_reads': len(reads), 'n_writes': len(writes),
               'err': err, 'hit_next': bool(hit), 'rip': rip, 'stop': stop_ip[0],
               'next_op_by_tbl': nop, 'tag_next': nxt[5], 'kind': kind,
               'natives': natives, 'last_insn': last_insn[0],
               'tail': tail, 'stub_op': seen_stub[0], 'bad': bad[:8],
               'reads': reads[:80], 'writes': writes[:80]}
        out.append(rec)
        stats[kind] += 1
        if ri % 200 == 0:
            print('  %d/%d %s' % (ri, nrec, stats), flush=True)
    print('统计:', stats)
    out_parent = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(out_parent, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump({'stats': stats, 'records': out}, f)
    print('已写 %s' % out_path)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('artdir', nargs='?',
                    default=os.path.join(ROOT, 'out', 'fullctx-win'))
    ap.add_argument('--dump', help='同轮解密的 VMP 快照路径')
    ap.add_argument('--out', help='decoded.json 输出路径')
    ap.add_argument('--runtime-script', help='提供 _build_stub12 的 dump_runtime.py 路径')
    args = ap.parse_args()
    main(args.artdir, args.dump, args.out, args.runtime_script)

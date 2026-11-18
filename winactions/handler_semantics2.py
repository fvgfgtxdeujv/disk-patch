#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""handler 语义提取第二步：
- 反解读取值（bc 页/ctx 页内容已知）
- 记录退出方式（RIP / rsp delta / 是否走派发表哨兵）
- 保存全量 capstone 反汇编
输出 out/sem/report_semantics.md + raw2.json
"""
import struct, os, json
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import *
from unicorn.x86_const import *

CODE, CTX, BC, TAB, STK, EXIT = (0x10000000, 0x20000000, 0x30000000,
                                 0x40000000, 0x50000000, 0x60000000)
HANDLER_DIR = '/workspace/dgwork/handlers_v82'
OUT = '/workspace/dgwork/out/sem'
MD = Cs(CS_ARCH_X86, CS_MODE_64)
OPS = [101, 197, 210, 256, 263, 297, 395, 407, 409, 418,
       424, 430, 446, 478, 508, 545, 547, 649, 80, 90]


def fill(seed, n):
    return bytes(((seed + 0x11 * i) & 0xFF) for i in range(n))


def run_one(op, seed):
    code = open(os.path.join(HANDLER_DIR, 'handler_%d.bin' % op), 'rb').read()
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE, 0x1000); uc.mem_write(CODE, code)
    uc.mem_map(CTX, 0x1000); uc.mem_map(BC, 0x1000)
    uc.mem_map(TAB, 0x1000); uc.mem_map(STK, 0x10000); uc.mem_map(EXIT, 0x1000)
    rnd = lambda k: ((seed * 0x9E3779B97F4A7C15 + k * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF)
    ctx0 = bytearray(0x1000)
    for off in range(0, 0x1000, 8):
        struct.pack_into('<Q', ctx0, off, rnd(off))
    struct.pack_into('<Q', ctx0, 0xBC, BC + 0x100)
    struct.pack_into('<Q', ctx0, 0xF5, TAB)
    uc.mem_write(CTX, bytes(ctx0))
    bc = fill(seed, 0x1000)
    uc.mem_write(BC, bc)
    tbl = bytearray(0x1000)
    for i in range(512):
        struct.pack_into('<Q', tbl, i * 8, EXIT)
    uc.mem_write(TAB, bytes(tbl))
    uc.mem_write(EXIT, b'\xf4')
    uc.reg_write(UC_X86_REG_RSP, STK + 0x8000)
    uc.reg_write(UC_X86_REG_RBP, CTX)

    events, stop = [], [None]
    ip = BC + 0x100

    def hk_mem(uc, access, address, size, value, ud):
        page = address & ~0xFFF
        if page == CTX:
            off = address - CTX
            if access == UC_MEM_READ:
                v = int.from_bytes(ctx0[off:off + size], 'little')
                events.append(('R', 'ctx+%#x' % off, size, v))
            else:
                events.append(('W', 'ctx+%#x' % off, size, value))
        elif page == BC:
            off = address - BC
            v = int.from_bytes(bc[off:off + size], 'little')
            events.append(('R', 'IP%+#x' % (off - 0x100), size, v))
        elif page == TAB:
            off = address - TAB
            v = struct.unpack_from('<Q', tbl, off)[0]
            events.append(('R', 'tab[%d]' % (off // 8), size, v))
        elif page == EXIT:
            events.append(('J', '->EXIT(哨兵)', 0, 0))
            stop[0] = 'dispatch_exit'; uc.emu_stop()
        elif page != STK:
            stop[0] = 'other_mem:%#x' % address; uc.emu_stop()

    def hk_code(uc, address, size, ud):
        if address == EXIT:
            stop[0] = stop[0] or 'dispatch_exit'; uc.emu_stop()
        elif not (CODE <= address < CODE + len(code)):
            stop[0] = 'fetch_out:%#x' % address; uc.emu_stop()

    uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hk_mem)
    uc.hook_add(UC_HOOK_CODE, hk_code)
    try:
        uc.emu_start(CODE, CODE + len(code), count=8000)
        if stop[0] is None:
            rip = uc.reg_read(UC_X86_REG_RIP)
            stop[0] = 'until_end(rip=%#x)' % rip
    except UcError as e:
        stop[0] = 'uc_error:%s@%#x' % (e, uc.reg_read(UC_X86_REG_RIP))
    ctx1 = bytes(uc.mem_read(CTX, 0x1000))
    diffs = []
    for off in range(0, 0x1000, 8):
        a = struct.unpack_from('<Q', ctx0, off)[0]
        b = struct.unpack_from('<Q', ctx1, off)[0]
        if a != b:
            diffs.append((off, a, b))
    return {'seed': seed, 'stop': stop[0], 'n_events': len(events),
            'events': events, 'ctx_diff': diffs,
            'rsp_delta': (STK + 0x8000) - uc.reg_read(UC_X86_REG_RSP)}


def disasm(op):
    code = open(os.path.join(HANDLER_DIR, 'handler_%d.bin' % op), 'rb').read()
    lines, last = [], None
    for i in MD.disasm(code, CODE):
        lines.append('%#06x  %-9s %s' % (i.address - CODE, i.mnemonic, i.op_str))
        last = i.address - CODE + i.size
    return lines, last


def main():
    os.makedirs(OUT, exist_ok=True)
    raw, rep = {}, ['# handler 语义提取（unicorn ctx-diff，实测）\n',
                    '约定：ctx 槽位=rbp+off；IP%+#x=相对初始 IP 的字节码偏移；'
                    'tab[i]=派发表；初始 IP=BC+0x100，派发表 512 项全指向哨兵。\n']
    for op in OPS:
        runs = [run_one(op, s) for s in (1, 2, 3)]
        raw[op] = runs
        r0 = runs[0]
        stops = sorted(set(r['stop'] for r in runs))
        nins = sorted(set(r['n_events'] for r in runs))
        dip = []
        for r in runs:
            a = r['ctx_diff']
            dipx = [d for d in a if d[0] == 0xB8 or d[0] == 0xBC]
            dip.append(bool(dipx))
        rep.append('\n## op %d\n' % op)
        rep.append('- 终止: %s | 事件数(seed1..3): %s | IP 槽被改: %s'
                   % (stops, nins, dip))
        rep.append('- ctx diff (seed1):')
        for off, a, b in r0['ctx_diff']:
            rep.append('  - ctx+%#03x: %#018x -> %#018x' % (off, a, b))
        rep.append('- 事件流水 (seed1, 前 60 条):')
        for e in r0['events'][:60]:
            if e[0] == 'R':
                rep.append('  - R %-10s size=%d val=%#x' % (e[1], e[2], e[3]))
            elif e[0] == 'W':
                rep.append('  - W %-10s size=%d val=%#x' % (e[1], e[2], e[3]))
            else:
                rep.append('  - %s' % (e[1],))
        lines, last = disasm(op)
        with open(os.path.join(OUT, 'disasm_%d.txt' % op), 'w') as f:
            f.write('\n'.join(lines) + '\n')
        rep.append('- 反汇编 %d 条，覆盖 %#x 字节 → disasm_%d.txt'
                   % (len(lines), last, op))
    with open(os.path.join(OUT, 'raw2.json'), 'w') as f:
        json.dump({str(k): v for k, v in raw.items()}, f, indent=1)
    with open(os.path.join(OUT, 'report_semantics.md'), 'w') as f:
        f.write('\n'.join(rep) + '\n')
    print('done →', OUT)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""实验 4：全零内存归因。
所有内存清零（除受控字段），则野指针目标 = 常量 + f(受控值)，
可直接读出寻址公式。ctx 放大到 64KB，派发表 0x100000（512K 项哨兵）。
"""
import struct, os, json
from unicorn import *
from unicorn.x86_const import *

CODE, CTX, BC, TAB, STK, EXIT = (0x10000000, 0x20000000, 0x30000000,
                                 0x40000000, 0x50000000, 0x60000000)
HANDLER_DIR = '/workspace/dgwork/handlers_v82'
OUT = '/workspace/dgwork/out/sem'
CTX_SZ = 0x10000
TAB_SZ = 0x100000
BC_SZ = 0x100000
OPND = {101: (8, 2), 197: (8, 2), 210: (2, 2), 256: (6, 2), 263: (8, 2),
        297: (6, 4), 395: (2, 4), 407: (8, 2), 409: (2, 4), 418: (6, 2),
        424: (8, 2), 430: (0, 2), 446: (0x16, 2), 478: (8, 2),
        508: (6, 2), 545: (2, 2), 547: (0, 2), 649: (5, 2),
        80: (9, 2), 90: (9, 2)}


def build(op, opnd_val, extra=None):
    """extra: dict {bc偏移(相对IP): (size, val)} 追加受控字段"""
    code = open(os.path.join(HANDLER_DIR, 'handler_%d.bin' % op), 'rb').read()
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE, 0x1000); uc.mem_write(CODE, code)
    uc.mem_map(CTX, CTX_SZ); uc.mem_map(BC, BC_SZ)
    uc.mem_map(TAB, TAB_SZ); uc.mem_map(STK, 0x10000); uc.mem_map(EXIT, 0x1000)
    ip_off = 0x8000
    ctx0 = bytearray(CTX_SZ)
    struct.pack_into('<Q', ctx0, 0xBC, BC + ip_off)
    struct.pack_into('<Q', ctx0, 0xF5, TAB)
    uc.mem_write(CTX, bytes(ctx0))
    bc = bytearray(BC_SZ)
    struct.pack_into('<H', bc, ip_off, op)
    o, sz = OPND[op]
    if sz == 2:
        struct.pack_into('<H', bc, ip_off + o, opnd_val)
    else:
        struct.pack_into('<i', bc, ip_off + o,
                         opnd_val if opnd_val < 0x80000000 else opnd_val - (1 << 32))
    for off, (s, v) in (extra or {}).items():
        bc[ip_off + off:ip_off + off + s] = v.to_bytes(s, 'little')
    uc.mem_write(BC, bytes(bc))
    uc.mem_write(TAB, b'\x00' * TAB_SZ)   # 表内容全零：表项=0
    uc.mem_write(EXIT, b'\xf4')
    uc.reg_write(UC_X86_REG_RSP, STK + 0x8000)
    uc.reg_write(UC_X86_REG_RBP, CTX)
    events, stop = [], [None]

    def page_of(a):
        if CTX <= a < CTX + CTX_SZ: return ('ctx', a - CTX)
        if BC <= a < BC + BC_SZ: return ('bc', a - BC - ip_off)
        if TAB <= a < TAB + TAB_SZ: return ('tab', a - TAB)
        if STK <= a < STK + 0x10000: return ('stk', a - STK)
        if CODE <= a < CODE + 0x1000: return ('code', a - CODE)
        return (None, a)

    def hk_mem(uc, access, address, size, value, ud):
        p, off = page_of(address)
        if access == UC_MEM_READ:
            events.append(('R', p, off, size))
        else:
            events.append(('W', p, off, size, value))

    def hk_unmapped(uc, access, address, size, value, ud):
        stop[0] = 'unmapped:%s target=%#x' % (
            {UC_MEM_READ: 'R', UC_MEM_WRITE: 'W', UC_MEM_FETCH: 'F'}[access],
            address)
        uc.emu_stop()

    def hk_code(uc, address, size, ud):
        if address == EXIT:
            stop[0] = 'dispatch_exit'; uc.emu_stop()
        elif not (CODE <= address < CODE + len(code)):
            stop[0] = 'fetch_out:%#x' % address; uc.emu_stop()

    uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hk_mem)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                UC_HOOK_MEM_FETCH_UNMAPPED, hk_unmapped)
    uc.hook_add(UC_HOOK_CODE, hk_code)
    try:
        uc.emu_start(CODE, CODE + len(code), count=8000)
        stop[0] = stop[0] or 'until_end'
    except UcError as e:
        stop[0] = (stop[0] or '') + ' uc_err:%s' % e
    ctx1 = bytes(uc.mem_read(CTX, CTX_SZ))
    diffs = []
    for off in range(0, CTX_SZ, 8):
        a = struct.unpack_from('<Q', ctx0, off)[0]
        b = struct.unpack_from('<Q', ctx1, off)[0]
        if a != b:
            diffs.append((off, a, b))
    return {'stop': stop[0], 'events': events, 'ctx_diff': diffs}


def main():
    os.makedirs(OUT, exist_ok=True)
    NOISE = {0xA0, 0xA4, 0x118, 0x119, 0x11B, 0x121, 0x138, 0x13B,
             0x140, 0x178, 0xB8, 0xBC}
    out = {}
    for op in sorted(OPND):
        rows = []
        for v in (0, 1, 2, 4, 8, 0x10, 0x40, 0x80, 0x100):
            r = build(op, v)
            rows.append({'v': v, 'stop': r['stop'], 'events': r['events'],
                         'diffs': r['ctx_diff']})
        out[op] = rows
        print('== op %d (%s)' % (op, OPND[op]))
        for r in rows:
            sem = [e for e in r['events']
                   if e[0] == 'R' and e[1] == 'ctx' and e[2] not in NOISE
                   or e[0] == 'W' and e[1] == 'ctx' and e[2] not in NOISE
                   or e[1] in ('tab', None)]
            print('   v=%-4d stop=%-40s 语义事件: %s'
                  % (r['v'], r['stop'],
                     [(e[0], e[1], hex(e[2]) if isinstance(e[2], int) else e[2],
                       e[3]) for e in sem[:8]]))
            if r['diffs']:
                print('        ctx diff: %s' % [
                    ('+%#x' % d[0], '%#x->%#x' % (d[1], d[2]))
                    for d in r['diffs'][:8] if d[0] not in NOISE])
    with open(os.path.join(OUT, 'zero_sweep.json'), 'w') as f:
        json.dump(out, f, indent=1, default=str)
    print('done')


if __name__ == '__main__':
    main()

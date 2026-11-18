#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""实验 3：操作数扫描。
- BC 页 1MB（指令槽 16B 对齐，初始 IP 在中间）
- 0x70000000 起 256MB 影子内存兜底野指针
- 对每个 handler 的主操作数字段（live 实证偏移）扫多个受控值，
  记录每次运行的解引用目标页分布与 ctx diff。
"""
import struct, os, json
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import *
from unicorn.x86_const import *

CODE, CTX, BC, TAB, STK, EXIT, SHADOW = (0x10000000, 0x20000000,
    0x30000000, 0x40000000, 0x50000000, 0x60000000, 0x70000000)
HANDLER_DIR = '/workspace/dgwork/handlers_v82'
OUT = '/workspace/dgwork/out/sem'
# live 实证的主操作数偏移（v24.10 top-20 表）；u16 除非标注 i32
OPND = {101: (8, 2), 197: (8, 2), 210: (2, 2), 256: (6, 2), 263: (8, 2),
        297: (6, 4), 395: (2, 4), 407: (8, 2), 409: (2, 4), 418: (6, 2),
        424: (8, 2), 430: (0, 2), 446: (0x16, 2), 478: (8, 2),
        508: (6, 2), 545: (2, 2), 547: (0, 2), 649: (5, 2),
        80: (9, 2), 90: (9, 2)}


def build(op, seed, opnd_val):
    code = open(os.path.join(HANDLER_DIR, 'handler_%d.bin' % op), 'rb').read()
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE, 0x1000); uc.mem_write(CODE, code)
    uc.mem_map(CTX, 0x1000); uc.mem_map(BC, 0x100000)
    uc.mem_map(TAB, 0x1000); uc.mem_map(STK, 0x10000)
    uc.mem_map(EXIT, 0x1000); uc.mem_map(SHADOW, 0x10000000)
    rnd = lambda k: ((seed * 0x9E3779B97F4A7C15 + k * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF)
    ctx0 = bytearray(0x1000)
    for off in range(0, 0x1000, 8):
        struct.pack_into('<Q', ctx0, off, rnd(off))
    ip_off = 0x8000
    struct.pack_into('<Q', ctx0, 0xBC, BC + ip_off)
    struct.pack_into('<Q', ctx0, 0xF5, TAB)
    uc.mem_write(CTX, bytes(ctx0))
    bc = bytearray(0x100000)
    for i in range(0x100000):
        bc[i] = (seed + 0x11 * i) & 0xFF
    # 主操作数受控值
    o, sz = OPND[op]
    if sz == 2:
        struct.pack_into('<H', bc, ip_off + o, opnd_val)
        struct.pack_into('<H', bc, ip_off, op)          # op@+0（live 实证）
    else:
        struct.pack_into('<i', bc, ip_off + o, opnd_val if opnd_val < 0x80000000 else opnd_val - (1 << 32))
        struct.pack_into('<H', bc, ip_off, op)
    if op == 297:
        struct.pack_into('<i', bc, ip_off + 6, opnd_val)
    uc.mem_write(BC, bytes(bc))
    tbl = bytearray(0x1000)
    for i in range(512):
        struct.pack_into('<Q', tbl, i * 8, EXIT)
    uc.mem_write(TAB, bytes(tbl))
    uc.mem_write(EXIT, b'\xf4')
    uc.reg_write(UC_X86_REG_RSP, STK + 0x8000)
    uc.reg_write(UC_X86_REG_RBP, CTX)
    events, stop = [], [None]

    def page_of(a):
        if CTX <= a < CTX + 0x1000: return 'ctx'
        if BC <= a < BC + 0x100000: return 'bc'
        if TAB <= a < TAB + 0x1000: return 'tab'
        if SHADOW <= a < SHADOW + 0x10000000: return 'shadow'
        if STK <= a < STK + 0x10000: return 'stk'
        return None

    def hk_mem(uc, access, address, size, value, ud):
        p = page_of(address)
        if access == UC_MEM_READ:
            events.append(('R', p, address, size))
        else:
            events.append(('W', p, address, size, value))
        if p is None:
            stop[0] = 'unmapped:%#x' % address; uc.emu_stop()

    def hk_code(uc, address, size, ud):
        if address == EXIT:
            stop[0] = 'dispatch_exit'; uc.emu_stop()
        elif not (CODE <= address < CODE + len(code)):
            stop[0] = 'fetch_out:%#x' % address; uc.emu_stop()

    def hk_unmapped(uc, access, address, size, value, ud):
        stop[0] = 'unmapped_access:%s@target=%#x (rip=%#x)' % (
            {UC_MEM_READ: 'read', UC_MEM_WRITE: 'write',
             UC_MEM_FETCH: 'fetch'}.get(access, access),
            address, uc.reg_read(UC_X86_REG_RIP))
        uc.emu_stop()

    uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hk_mem)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                UC_HOOK_MEM_FETCH_UNMAPPED, hk_unmapped)
    uc.hook_add(UC_HOOK_CODE, hk_code)
    try:
        uc.emu_start(CODE, CODE + len(code), count=8000)
        if stop[0] is None:
            stop[0] = 'until_end'
    except UcError as e:
        if not stop[0] or 'unmapped' not in stop[0]:
            stop[0] = (stop[0] or '') + 'uc_error:%s@rip=%#x' % (
                e, uc.reg_read(UC_X86_REG_RIP))
    ctx1 = bytes(uc.mem_read(CTX, 0x1000))
    diffs = [(o, struct.unpack_from('<Q', ctx0, o)[0],
              struct.unpack_from('<Q', ctx1, o)[0])
             for o in range(0, 0x1000, 8)
             if struct.unpack_from('<Q', ctx0, o)[0] != struct.unpack_from('<Q', ctx1, o)[0]]
    # 非噪声解引用目标（排除 ctx 噪声槽）
    interesting = []
    for e in events:
        if e[0] == 'R' and e[1] in ('shadow', 'bc', 'tab', None):
            interesting.append(e)
        elif e[0] == 'R' and e[1] == 'ctx' and e[3] == 8 and e[2] - CTX in (0xBC, 0xF5):
            interesting.append(e)
    return {'stop': stop[0], 'events': events, 'ctx_diff': diffs,
            'interesting': interesting, 'opnd_off': o, 'opnd_sz': sz}


def main():
    os.makedirs(OUT, exist_ok=True)
    out = {}
    for op in sorted(OPND):
        rows = []
        for v in (0, 1, 2, 3, 4, 8, 0x10, 0x20, 0x40, 0x100):
            r = build(op, 7, v)
            rows.append({'v': v, **{k: r[k] for k in
                         ('stop', 'interesting', 'ctx_diff')}})
        out[op] = rows
        # 摘要：影子/野指针地址是否随 v 线性变化
        wild = [(r['v'], [e[2] for e in r['interesting'] if e[1] == 'shadow'])
                for r in rows]
        stops = [r['stop'] for r in rows]
        print('== op %d (%s)' % (op, OPND[op]))
        for (v, ws), st in zip(wild, stops):
            print('   v=%-5d stop=%-28s shadow_reads=%s'
                  % (v, st, ['%#x' % a for a in ws[:6]]))
    with open(os.path.join(OUT, 'opnd_sweep.json'), 'w') as f:
        json.dump(out, f, indent=1, default=str)
    print('done')


if __name__ == '__main__':
    main()

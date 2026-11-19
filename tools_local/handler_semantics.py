#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""unicorn ctx-diff：对 handlers_v82/handler_<op>.bin 逐个沙箱执行，
记录 (1) 全部内存读/写 (2) ctx 槽位前后 diff (3) 终止方式，
只输出实测事实，不做任何推测性标注。

ctx 初始化（依据 run 期实证的槽位图）：
  +0xBC = IP 指针  -> 字节码页 0x30000000
  +0xF5 = 派发表基址 -> 表页 0x40000000（661 项，全部指向哨兵 EXIT）
  其余槽位用种子随机填充。
字节码页填可逆花纹，读到的值可反解出读取偏移。
"""
import struct, sys, os, json
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import *
from unicorn.x86_const import *

CODE = 0x10000000      # handler 代码
CTX = 0x20000000       # ctx（rbp）
BC = 0x30000000        # 字节码页
TAB = 0x40000000       # 派发表
STK = 0x50000000       # 栈
EXIT = 0x60000000      # 哨兵：跳到这里 = 本 handler 结束（走派发）
HANDLER_DIR = '/workspace/dgwork/handlers_v82'
OUT = '/workspace/dgwork/out/sem'
MD = Cs(CS_ARCH_X86, CS_MODE_64)

OPS = [101, 197, 210, 256, 263, 297, 395, 407, 409, 418,
       424, 430, 446, 478, 508, 545, 547, 649, 80, 90]


def fill_pattern(page_base, size, seed):
    """可逆花纹：byte_i = (seed + 0x11*i) & 0xFF"""
    return bytes(((seed + 0x11 * i) & 0xFF) for i in range(size))


def run_one(op, seed):
    code = open(os.path.join(HANDLER_DIR, 'handler_%d.bin' % op), 'rb').read()
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE, 0x1000)
    uc.mem_write(CODE, code)
    uc.mem_map(CTX, 0x1000)
    uc.mem_map(BC, 0x1000)
    uc.mem_map(TAB, 0x1000)
    uc.mem_map(STK, 0x10000)
    uc.mem_map(EXIT, 0x1000)

    # ctx 初始（可复现随机）
    rnd = lambda k: ((seed * 0x9E3779B97F4A7C15 + k * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF)
    ctx0 = bytearray(0x1000)
    for off in range(0, 0x1000, 8):
        struct.pack_into('<Q', ctx0, off, rnd(off))
    struct.pack_into('<Q', ctx0, 0xBC, BC + 0x100)   # IP
    struct.pack_into('<Q', ctx0, 0xF5, TAB)          # 表基址
    uc.mem_write(CTX, bytes(ctx0))

    # 字节码页 + 表页
    uc.mem_write(BC, fill_pattern(BC, 0x1000, seed))
    tbl = bytearray(0x1000)
    for i in range(512):
        struct.pack_into('<Q', tbl, i * 8, EXIT)
    uc.mem_write(TAB, bytes(tbl))
    uc.mem_write(EXIT, b'\xf4')  # hlt：撞到即终止

    rsp = STK + 0x8000
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RBP, CTX)

    reads, writes, ninsn = [], [], [0]
    stop = [None]

    def hk_mem(uc, access, address, size, value, ud):
        page = address & ~0xFFF
        if page == CTX:
            (reads if access == UC_MEM_READ else writes).append(
                ('ctx', address - CTX, size, value))
        elif page == BC:
            reads.append(('bc', address - (ctx_ip[0] or BC), size, value))
        elif page == TAB:
            reads.append(('tab', address - TAB, size, value))
        elif page == STK:
            pass
        elif page == CODE:
            pass
        else:
            stop.append('other_mem')

    def hk_code(uc, address, size, ud):
        ninsn[0] += 1
        if address < CODE or address >= CODE + len(code):
            stop.append('exit_code')
            uc.emu_stop()
        elif address == EXIT:
            stop.append('dispatch_exit')
            uc.emu_stop()
        elif ninsn[0] > 4000:
            stop.append('cap')

    ctx_ip = [None]
    uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hk_mem)
    uc.hook_add(UC_HOOK_CODE, hk_code)

    try:
        uc.emu_start(CODE, CODE + len(code), count=5000)
        if not stop:
            stop.append('ran_to_end_of_bin')
    except UcError as e:
        stop.append('uc_error:%s @%#x' % (e, uc.reg_read(UC_X86_REG_RIP)))

    ctx1 = uc.mem_read(CTX, 0x1000)
    diffs = []
    for off in range(0, 0x1000, 8):
        a = struct.unpack_from('<Q', ctx0, off)[0]
        b = struct.unpack_from('<Q', bytes(ctx1), off)[0]
        if a != b:
            diffs.append((off, a, b))
    ip0 = BC + 0x100
    ip1 = struct.unpack_from('<Q', bytes(ctx1), 0xBC)[0]
    rsp1 = uc.reg_read(UC_X86_REG_RSP)
    return {'seed': seed, 'stop': stop[0], 'ninsn': ninsn[0],
            'ctx_diff': diffs, 'ip0': ip0, 'ip1': ip1,
            'd_ip': ip1 - ip0 if 0 < ip1 < BC + 0x1000 else None,
            'rsp_delta': rsp - rsp1,
            'reads': reads, 'writes': writes}


def main():
    os.makedirs(OUT, exist_ok=True)
    result = {}
    for op in OPS:
        runs = []
        for seed in (1, 2, 3, 4, 5):
            try:
                runs.append(run_one(op, seed))
            except Exception as e:
                runs.append({'seed': seed, 'error': repr(e)})
        result[op] = runs
        # 汇总打印：稳定的 ctx diff 与读取模式
        stops = set(r.get('stop') for r in runs)
        dip = set(r.get('d_ip') for r in runs)
        # ctx diff 跨 seed 是否一致（按 offset+size 分组）
        pat = {}
        for r in runs:
            for off, a, b in r.get('ctx_diff', []):
                pat.setdefault(off, []).append((a, b))
        stable = [off for off, v in pat.items() if len(v) == len(runs)]
        # 字节码读取偏移
        bcr = set()
        for r in runs:
            for kind, off, size, val in r.get('reads', []):
                if kind == 'bc':
                    bcr.add((off, size))
        print('op %3d  stop=%-22s ninsn=%-4s d_ip=%-10s bc_reads=%s stable_ctx=%d slots'
              % (op, str(sorted(stops)), runs[0].get('ninsn'),
                 str(sorted(dip)), sorted(bcr), len(stable)))
        for off in sorted(stable):
            print('        ctx+%#03x : %s' % (off,
                  ['%#x->%#x' % (a, b) for a, b in pat[off][:3]]))
    with open(os.path.join(OUT, 'raw_runs.json'), 'w') as f:
        json.dump({str(k): v for k, v in result.items()}, f, indent=1)
    print('\nraw 已写 %s/raw_runs.json' % OUT)


if __name__ == '__main__':
    main()

# -*- coding: utf-8 -*-
"""在静态载荷上按地址反汇编一个窗口，用来人眼看待定位置的真实指令。"""
import sys, json
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

CODE_BASE = 0x141D34000
P = open('/workspace/dgwork/payload.bin', 'rb').read()
MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = False


def dump(va, before=64, after=160):
    start = va - CODE_BASE - before
    start = max(0, start)
    end = min(len(P), va - CODE_BASE + after)
    print('=' * 78)
    print('around %#x  (file off %#x)' % (va, va - CODE_BASE))
    print('=' * 78)
    for i in MD.disasm(P[start:end], CODE_BASE + start):
        mark = ' <<<' if i.address == va else ''
        print('%#012x  %-24s %s %s%s' % (i.address, i.bytes.hex(), i.mnemonic, i.op_str, mark))


if __name__ == '__main__':
    addrs = [int(a, 0) for a in sys.argv[1:]]
    for a in addrs:
        dump(a)

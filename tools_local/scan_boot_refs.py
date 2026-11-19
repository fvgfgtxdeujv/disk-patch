# -*- coding: utf-8 -*-
"""在 .boot 明文段里找「引用数据段 0x62F000..0x9A0000」的指令：
   - RIP-relative（lea/mov 等）
   - movabs imm64
"""
import re, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

IB = 0x140000000
BOOT_RVA, BOOT_SIZE = 0x2780000, 0x872000
IMG = open('/workspace/dgwork/unpack6201829/DiskGenius_image.bin', 'rb').read()
CODE = IMG[BOOT_RVA:BOOT_RVA + BOOT_SIZE]
BASE = IB + BOOT_RVA
LO, HI = IB + 0x600000, IB + 0x9A0000

MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.skipdata = True
RIPRE = re.compile(r'rip \+ (0x[0-9a-f]+)')
ABSI = re.compile(r'^0x([0-9a-f]{7,})$')

hits = []
n = 0
for addr, size, mn, op in MD.disasm_lite(CODE, BASE):
    n += 1
    if mn == '.byte':
        continue
    m = RIPRE.search(op)
    if m:
        tgt = addr + size + int(m.group(1), 16)
        if LO <= tgt < HI:
            hits.append((addr, mn, op, tgt, 'rip'))
        continue
    # movabs reg, imm64：capstone 打印成 mov rax, 0x1406...
    if mn == 'mov':
        parts = op.split(', ')
        if len(parts) == 2 and parts[1].startswith('0x'):
            try:
                v = int(parts[1], 16)
            except ValueError:
                continue
            if LO <= v < HI:
                hits.append((addr, mn, op, v, 'imm64'))

print('扫描 %d 条指令' % n)
print('引用数据段 0x600000-0x9A0000 的指令：%d' % len(hits))
c = collections.Counter((h[3], h[4]) for h in hits)
for (t, k), v in c.most_common(30):
    print('  %#x  [%s] x%d' % (t, k, v))
print()
for a, m, o, t, k in hits[:30]:
    print('  %#012x  %-6s %-40s -> %#x' % (a, m, o, t))

# -*- coding: utf-8 -*-
"""扫 .vmp 载荷里所有 RIP-relative 指令（lea / mov），统计引用目标，
   重点看有没有引用到 .boot 数据段（RVA 0x600000-0x900000，即 VA 0x1406xxxxx-0x1409xxxxx）。
"""
import collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

CODE_BASE = 0x141D34000
N = 14_540_800
P = open('/workspace/dgwork/payload.bin', 'rb').read()
MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = False

# RIP-relative 的 ModRM 形态：mod=00, rm=101 → modrm & 0xC7 == 0x05
# lea r64: 48/49/4c/4d 8d <modrm>
# mov r64: 48/49/4c/4d 8b <modrm>
CAND = set()
for i in range(N - 8):
    b = P[i]
    if b in (0x48, 0x49, 0x4c, 0x4d) and P[i + 1] in (0x8d, 0x8b):
        if P[i + 2] & 0xC7 == 0x05:
            CAND.add(i)

print('候选 RIP-rel 位置 %d' % len(CAND))

hits = collections.Counter()
detail = []
insn_n = 0
for off in sorted(CAND):
    seg = P[off:off + 12]
    for ins in MD.disasm(seg, CODE_BASE + off):
        if ins.address != CODE_BASE + off:
            break
        insn_n += 1
        op = ins.op_str
        if 'rip' not in op:
            break
        # 目标 = 下一条地址 + disp
        try:
            disp = int(op.split('rip + ')[1].rstrip(']'), 16)
        except Exception:
            break
        # capstone 打印的是绝对目标（部分版本），这里按 [+ 0x..] 解析相对量
        tgt = ins.address + ins.size + disp
        hits[tgt] += 1
        if 0x140600000 <= tgt < 0x140A00000:
            detail.append((ins.address, ins.mnemonic, ins.op_str, tgt))
        break

print('成功解码 %d 条 RIP-rel' % insn_n)
print('不同目标 %d' % len(hits))
print('\n落在 .boot 数据区（0x140600000-0x140A00000）的引用：%d' % len(detail))
for a, m, o, t in detail[:60]:
    print('  %#x  %s %s   -> %#x' % (a, m, o, t))

print('\n全载荷 Top20 目标：')
for t, c in hits.most_common(20):
    print('  %#x  x%d' % (t, c))

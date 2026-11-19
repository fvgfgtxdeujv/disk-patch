# -*- coding: utf-8 -*-
"""在已脱壳的 .vmp 里找「立即数指向 .boot 数据段」的指令。
   两种形态：
     1) movabs r64, imm64       48 B8+r .. .. ..   （10 字节）
     2) mov r/m32, imm32        C7 /0 .. ..        （RVA 形态）
     3) lea 已确认 8 处，忽略
"""
import struct, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

IB = 0x140000000
VMP_VA = IB + 0x19D4000
P = open('/workspace/dgwork/unpack6201829/DiskGenius_unpacked_vmp.bin', 'rb').read()
N = len(P)
MD = Cs(CS_ARCH_X86, CS_MODE_64)

# 目标区：第二段（RVA 0x62F000..0x69D200）与第三段（0x7BE000 起），放宽到 0x600000..0x9A0000
LO, HI = IB + 0x600000, IB + 0x9A0000

hits = []
# movabs
for off in range(N - 10):
    if P[off] in (0x48, 0x49, 0x4C, 0x4D) and (P[off + 1] & 0xF8) == 0xB8:
        imm = struct.unpack_from('<Q', P, off + 2)[0]
        if LO <= imm < HI:
            hits.append((VMP_VA + off, 'movabs', P[off:off + 10].hex(), imm))

print('movabs 指向 0x600000-0x9A0000 段：%d 处' % len(hits))
cnt = collections.Counter(h[3] for h in hits)
for va, c in cnt.most_common(30):
    print('  target %#x  x%d' % (va, c))
print()
for va, k, b, t in hits[:25]:
    print('  %#012x  %s %s -> %#x' % (va, k, b, t))

# 再用 capstone 复核这些位置确实是 movabs（防止误判）
print('\n=== capstone 复核前 10 条 ===')
for va, k, b, t in hits[:10]:
    off = va - VMP_VA
    for ins in MD.disasm(P[off:off + 15], va):
        print('  %#012x  %-20s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
        break

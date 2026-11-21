import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def u16s(va, m=80):
    o = va - BASE
    if o < 0 or o + 1 >= N: return None
    s = []
    for k in range(0, m * 2, 2):
        if o + k + 1 >= N: break
        c = B[o+k] | (B[o+k+1] << 8)
        if c == 0: break
        if c < 0x20 or c > 0x7e: return None
        s.append(chr(c))
    return ''.join(s) if s else None

f = open(r'out\_offlinefn.txt', 'w', encoding='utf-8')
for ins in md.disasm(B[0x1400d8168-BASE:0x1400d85b7-BASE], 0x1400d8168):
    note = ''
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            t = ins.address + ins.size + op.mem.disp
            note += '  ; %x %r' % (t, u16s(t))
    f.write('%x %-8s %-44s%s\n' % (ins.address, ins.mnemonic, ins.op_str, note))
f.close()
print('lines', sum(1 for _ in open(r'out\_offlinefn.txt', encoding='utf-8')))

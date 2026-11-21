import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def u16s(va, maxlen=80):
    off = va - BASE
    if off < 0 or off + 1 >= N:
        return None
    out = []
    for k in range(0, maxlen * 2, 2):
        if off + k + 1 >= N:
            break
        c = B[off + k] | (B[off + k + 1] << 8)
        if c == 0:
            break
        if c < 0x20 or c > 0x7e:
            return None
        out.append(chr(c))
    return ''.join(out) if out else None

def dis(va, n):
    print('==== %x ====' % va)
    for ins in md.disasm(B[va - BASE: va - BASE + n], va):
        note = ''
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                s = u16s(t)
                note += '   ; %x %r' % (t, s)
        print('%x  %-8s %-42s%s' % (ins.address, ins.mnemonic, ins.op_str, note))

for a, n in ((0x140199d40, 0x2c0),):
    dis(a, n)

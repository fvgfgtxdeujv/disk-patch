import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def callers(target):
    out = []
    for i in range(N - 5):
        if B[i] != 0xE8:
            continue
        rel = struct.unpack_from('<i', B, i + 1)[0]
        if BASE + i + 5 + rel == target:
            out.append(BASE + i)
    return out

def u16s(va, maxlen=70):
    off = va - BASE
    if off < 0 or off + 1 >= N:
        return None
    o = []
    for k in range(0, maxlen * 2, 2):
        if off + k + 1 >= N:
            break
        c = B[off + k] | (B[off + k + 1] << 8)
        if c == 0:
            break
        if c < 0x20 or c > 0x7e:
            return None
        o.append(chr(c))
    return ''.join(o) if o else None

out = open(r'out\_callers2.txt', 'w', encoding='utf-8')
def dis(va, end):
    out.write('==== %x - %x ====\n' % (va, end))
    for ins in md.disasm(B[va - BASE: end - BASE], va):
        note = ''
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                note += '   ; %x %r' % (t, u16s(t))
        out.write('%x  %-8s %-44s%s\n' % (ins.address, ins.mnemonic, ins.op_str, note))

dis(0x14020b114, 0x14020b2a4)
for h in callers(0x14020b114):
    out.write('CALLER2 %x\n' % h)
    dis(h - 0x120 if h - 0x120 > BASE else BASE, h + 0x30)
for h in callers(0x14020b2a4):
    out.write('CALLER1 %x\n' % h)
out.close()
print('done', [hex(x) for x in callers(0x14020b114)])

import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

TARGET = 0x14020b2a4
hits = []
for i in range(N - 5):
    if B[i] != 0xE8:
        continue
    rel = struct.unpack_from('<i', B, i + 1)[0]
    if BASE + i + 5 + rel == TARGET:
        hits.append(BASE + i)
print('direct callers of delete wrapper:', [hex(h) for h in hits])

# function boundaries
e_lfanew = struct.unpack_from('<I', B, 0x3C)[0]
opt = e_lfanew + 4 + 20
dd = opt + 112
exc_rva, exc_size = struct.unpack_from('<II', B, dd + 3 * 8)
nfun = exc_size // 12
def func_of(va):
    rva = va - BASE
    lo, hi = 0, nfun - 1
    while lo <= hi:
        m = (lo + hi) // 2
        b, e, u = struct.unpack_from('<III', B, exc_rva + m * 12)
        if rva < b:
            hi = m - 1
        elif rva >= e:
            lo = m + 1
        else:
            return BASE + b, BASE + e
    return None

out = open(r'out\_callers.txt', 'w', encoding='utf-8')
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

for h in hits:
    fr = func_of(h)
    out.write('CALLER %x in %s\n' % (h, ' '.join(hex(x) for x in fr) if fr else None))
    if fr:
        for ins in md.disasm(B[fr[0] - BASE: h - fr[0] + 0x20], fr[0]):
            note = ''
            for op in ins.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    t = ins.address + ins.size + op.mem.disp
                    note += '   ; %x %r' % (t, u16s(t))
            out.write('%x  %-8s %-44s%s\n' % (ins.address, ins.mnemonic, ins.op_str, note))
out.close()
print('written')

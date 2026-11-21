import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
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

def u16s(va, maxlen=70):
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

out = open(r'out\_dis3.txt', 'w', encoding='utf-8')
def dis(va, end, label):
    out.write('==== %s %x - %x ====\n' % (label, va, end))
    for ins in md.disasm(B[va - BASE: end - BASE], va):
        note = ''
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                note += '   ; %x %r' % (t, u16s(t))
        out.write('%x  %-8s %-44s%s\n' % (ins.address, ins.mnemonic, ins.op_str, note))

for va in (0x1400d69af, 0x1400d706e, 0x1400d7699, 0x1400d79df, 0x1400d7bd8, 0x1400d7e32,
           0x1400d806b, 0x1400d8508, 0x1400d88bd, 0x140113ca7, 0x140159e27, 0x1403293fb,
           0x14019a354, 0x140198fa4, 0x1420c7945):
    fr = func_of(va)
    out.write('%x -> %s\n' % (va, ' '.join(hex(x) for x in fr) if fr else None))
out.write('\n')
# call target and helpers
dis(0x1420c7945, 0x1420c79c5, 'vmp_slot_fn')
for va in (0x14019a354, 0x140198fa4):
    fr = func_of(va)
    if fr:
        dis(fr[0], fr[1], 'helper')
fr = func_of(0x140199f67)
if fr:
    dis(0x140199f67, fr[1], 'ini_reader_tail')
out.close()
print('done')

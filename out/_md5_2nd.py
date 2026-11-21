import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
e = struct.unpack_from('<I', B, 0x3C)[0]
dd = e + 4 + 20 + 112
exc, excsz = struct.unpack_from('<II', B, dd + 3 * 8)
nfun = excsz // 12
def func_of(va):
    lo, hi = 0, nfun - 1
    while lo <= hi:
        m = (lo + hi) // 2
        b, en, u = struct.unpack_from('<III', B, exc + m * 12)
        if va - BASE < b: hi = m - 1
        elif va - BASE >= en: lo = m + 1
        else: return BASE + b, BASE + en
    return None
def u16s(va, m=70):
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

f = open(r'out\_md5_2nd.txt', 'w', encoding='utf-8')
for va in (0x1403cb5d5, 0x1403cb955, 0x1403cc78e):
    fr = func_of(va)
    f.write('caller %x in %s\n' % (va, fr))
    if fr:
        for ins in md.disasm(B[fr[0]-BASE: fr[1]-BASE], fr[0]):
            note = ''
            for op in ins.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    t = ins.address + ins.size + op.mem.disp
                    note += '  ; %x %r' % (t, u16s(t))
            f.write('%x %-8s %-44s%s\n' % (ins.address, ins.mnemonic, ins.op_str, note))
        f.write('\n')
fr = func_of(0x1403cc534)
f.write('md5_2nd fn %s\n' % (fr,))
if fr:
    for ins in md.disasm(B[fr[0]-BASE: fr[1]-BASE], fr[0]):
        note = ''
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                note += '  ; %x %r' % (t, u16s(t))
        f.write('%x %-8s %-44s%s\n' % (ins.address, ins.mnemonic, ins.op_str, note))
f.close()
print('done')

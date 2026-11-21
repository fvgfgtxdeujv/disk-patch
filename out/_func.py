import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# PE data directory 3 (exception)
e_lfanew = struct.unpack_from('<I', B, 0x3C)[0]
opt = e_lfanew + 4 + 20
magic = struct.unpack_from('<H', B, opt)[0]
dd = opt + (112 if magic == 0x20b else 96)
exc_rva, exc_size = struct.unpack_from('<II', B, dd + 3 * 8)
nfun = exc_size // 12
print('pdata', hex(exc_rva), nfun, 'functions')

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

def dis(va, end, label, maxins=400):
    print('==== %s %x - %x ====' % (label, va, end))
    k = 0
    for ins in md.disasm(B[va - BASE: end - BASE], va):
        note = ''
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                s = u16s(t)
                note += '   ; %x %r' % (t, s)
        print('%x  %-8s %-44s%s' % (ins.address, ins.mnemonic, ins.op_str, note))
        k += 1
        if k >= maxins:
            print('... truncated')
            break

for va, lab in ((0x140199d83, 'ini_reader'), (0x1400d7e32, 'req_builder'), (0x1400d8508, 'skey')):
    fr = func_of(va)
    print(lab, hex(va), '->', tuple(hex(x) for x in fr) if fr else None)
    if fr:
        dis(fr[0], fr[1], lab, 500)

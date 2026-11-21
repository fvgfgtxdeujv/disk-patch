import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64)
e = struct.unpack_from('<I', B, 0x3C)[0]
exc, excsz = struct.unpack_from('<II', B, e + 4 + 20 + 112 + 3 * 8)
nfun = excsz // 12
FUNCS = sorted(struct.unpack_from('<III', B, exc + m * 12) for m in range(nfun))
def func_of(va):
    rva = va - BASE; lo, hi = 0, nfun - 1
    while lo <= hi:
        m = (lo + hi) // 2; b, en, u = FUNCS[m]
        if rva < b: hi = m - 1
        elif rva >= en: lo = m + 1
        else: return (BASE + b, BASE + en)
    return None

def hits(disp):
    pat = struct.pack('<I', disp)
    r = []
    st = 0
    while True:
        i = B.find(pat, st)
        if i < 0: break
        st = i + 1
        # try decoding starting 1..4 bytes before so that disp is inside insn
        for back in range(1, 7):
            s = i - back
            if s < 0: continue
            for ins in md.disasm(B[s:s+16], BASE + s, 1):
                txt = ins.mnemonic + ' ' + ins.op_str
                if ('0x%x' % disp) in txt or ('+ 0x%x]' % disp) in txt:
                    if any(('0x%x' % disp) in o for o in [ins.op_str]):
                        r.append((BASE + s, txt))
                        break
            else:
                continue
            break
    return r

for disp in (0x5cc, 0x5d4, 0x5e8, 0x5f0, 0x5f8):
    print('==== disp %x' % disp)
    seen = set()
    for va, txt in hits(disp):
        if va in seen: continue
        seen.add(va)
        print('  %x %-44s func=%s' % (va, txt, func_of(va)))

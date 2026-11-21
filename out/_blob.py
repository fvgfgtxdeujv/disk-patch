import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_OP_IMM

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

e = struct.unpack_from('<I', B, 0x3C)[0]
opt = e + 4 + 20
dd = opt + 112
exc, excsz = struct.unpack_from('<II', B, dd + 3 * 8)
nfun = excsz // 12
FUNCS = [struct.unpack_from('<III', B, exc + m * 12) for m in range(nfun)]

def func_of(va):
    rva = va - BASE
    lo, hi = 0, nfun - 1
    while lo <= hi:
        m = (lo + hi) // 2
        b, en, u = FUNCS[m]
        if rva < b: hi = m - 1
        elif rva >= en: lo = m + 1
        else: return BASE + b, BASE + en
    return None

def callers(t):
    r = []
    for i in range(N - 5):
        if B[i] == 0xE8:
            rel = struct.unpack_from('<i', B, i + 1)[0]
            if BASE + i + 5 + rel == t:
                r.append(BASE + i)
    return r

def refs_mem(t):
    """RIP-relative references to address t (any instruction)."""
    r = []
    for ins in md.disasm(B, BASE):
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                a = ins.address + ins.size + op.mem.disp
                if a == t:
                    r.append(ins.address)
        # stop scanning too far? no, full scan
    return r

def u16s(va, m=90):
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

def u8s(va, m=90):
    o = va - BASE
    if o < 0 or o >= N: return None
    s = []
    for k in range(m):
        if o + k >= N: break
        c = B[o+k]
        if c == 0: break
        if c < 0x20 or c > 0x7e: return None
        s.append(chr(c))
    return ''.join(s) if s else None

f = open(r'out\_blob.txt', 'w', encoding='utf-8')
def dis(va, end, lab):
    f.write('==== %s %x-%x\n' % (lab, va, end))
    for ins in md.disasm(B[va-BASE:end-BASE], va):
        note = ''
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                note += '   ; %x %r %r' % (t, u16s(t), u8s(t))
        f.write('%x %-8s %-46s%s\n' % (ins.address, ins.mnemonic, ins.op_str, note))

targets = [0x1400d95f8, 0x1400d8168, 0x1403291bc, 0x140199be0]
for t in targets:
    fr = func_of(t)
    f.write('\n######## TARGET %x func=%s callers=%s\n' % (t, fr, [hex(x) for x in callers(t)]))
    if fr:
        dis(fr[0], fr[1], 'fn@%x' % t)
f.close()
print('done')
for t in targets:
    print(hex(t), func_of(t), [hex(x) for x in callers(t)])

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

def u16s(va, m=120):
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

f = open(r'out\_lic3.txt', 'w', encoding='utf-8')
def dis(va, end, lab):
    f.write('==== %s %x-%x\n' % (lab, va, end))
    for ins in md.disasm(B[va-BASE:end-BASE], va):
        note = ''
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                note += '   ; %x %r' % (t, u16s(t))
            elif op.type == X86_OP_IMM and t2ok(op.imm):
                note += '   ; imm %x %r' % (op.imm, u16s(op.imm))
        f.write('%x %-8s %-46s%s\n' % (ins.address, ins.mnemonic, ins.op_str, note))

def t2ok(v):
    return BASE <= v < BASE + N

for lab, va, pre, post in [
    ('lic_ref_113ca7', 0x140113ca7, 0xC0, 0x80),
    ('lic_ref_58cb7a', 0x14058cb7a, 0xA0, 0x60),
    ('lic_ref_58cd86', 0x14058cd86, 0xA0, 0x60),
    ('caller_326438', 0x140326438, 0x80, 0x40),
    ('caller_326dbc', 0x140326dbc, 0x80, 0x40),
]:
    f.write('\n######## %s func=%s\n' % (lab, func_of(va)))
    dis(va - pre, va + post, lab)

for t in (0x140323884, 0x1401a0b84, 0x14025004c, 0x140250148, 0x1402aeacc, 0x1402aecd0):
    f.write('\n#### CALLEES OF %x func=%s\n' % (t, func_of(t)))
    cs = callers(t)
    f.write('   callers(%d): %s\n' % (len(cs), [hex(x) for x in cs[:60]]))
f.close()
print('ok')
for t in (0x140323884, 0x1401a0b84, 0x14025004c, 0x140250148):
    print(hex(t), func_of(t), len(callers(t)))

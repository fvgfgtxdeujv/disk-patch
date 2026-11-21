import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_OP_IMM

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
e = struct.unpack_from('<I', B, 0x3C)[0]
exc, excsz = struct.unpack_from('<II', B, e + 4 + 20 + 112 + 3 * 8)
nfun = excsz // 12
FUNCS = sorted(struct.unpack_from('<III', B, exc + m * 12) for m in range(nfun))

def func_of(va):
    rva = va - BASE
    lo, hi = 0, nfun - 1
    while lo <= hi:
        m = (lo + hi) // 2
        b, en, u = FUNCS[m]
        if rva < b: hi = m - 1
        elif rva >= en: lo = m + 1
        else: return (BASE + b, BASE + en)
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

f = open(r'out\_keyfn.txt', 'w', encoding='utf-8')
def dis(va, end, lab):
    f.write('==== %s %x-%x\n' % (lab, va, end))
    for ins in md.disasm(B[va-BASE:end-BASE], va):
        note = ''
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                note += '   ; %x %r' % (t, u16s(t))
            elif op.type == X86_OP_IMM and BASE <= op.imm < BASE + N:
                s = u16s(op.imm)
                if s: note += '   ; %x %r' % (op.imm, s)
        f.write('%x %-8s %-46s%s\n' % (ins.address, ins.mnemonic, ins.op_str, note))

for t in (0x14019708c, 0x14019b2ec, 0x14019a354, 0x140198fa4, 0x14019a594):
    fr = func_of(t)
    f.write('\n######## %x func=%s callers=%s\n' % (t, fr, [hex(x) for x in callers(t)]))
    if fr:
        dis(fr[0], fr[1], 'fn')
dis(0x14019a067, 0x14019a25a, 'keyconsumer_tail')
dis(0x1400d6450, 0x1400d64f0, 'fn_0d6450')
f.close()
print('ok')
for t in (0x14019708c, 0x14019b2ec, 0x14019a354, 0x140198fa4, 0x14019a594):
    print(hex(t), func_of(t), [hex(x) for x in callers(t)])

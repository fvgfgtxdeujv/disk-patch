import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

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
def func_of(va):
    rva = va - BASE
    lo, hi = 0, nfun - 1
    while lo <= hi:
        m = (lo + hi) // 2
        b, en, u = struct.unpack_from('<III', B, exc + m * 12)
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
f = open(r'out\_delchain.txt', 'w', encoding='utf-8')
def dis(va, end, lab):
    f.write('==== %s %x-%x\n' % (lab, va, end))
    for ins in md.disasm(B[va-BASE:end-BASE], va):
        note = ''
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                note += '   ; %x %r' % (t, u16s(t))
        f.write('%x %-8s %-44s%s\n' % (ins.address, ins.mnemonic, ins.op_str, note))
for va in (0x14020b0ee, 0x1401f71ca):
    fr = func_of(va)
    f.write('VA %x func %s\n' % (va, fr))
    if fr:
        dis(fr[0], fr[1], 'callerfn')
        for h in callers(fr[0]):
            f.write('  caller-of-fn %x (func %s)\n' % (h, func_of(h)))
f.close()
print('done')
for va in (0x14020b0ee, 0x1401f71ca, 0x14020b114):
    print(hex(va), func_of(va), [hex(x) for x in callers(va)])

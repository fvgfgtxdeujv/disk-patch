import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_OP_IMM

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
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
def u16s(va, m=140):
    o = va - BASE
    if o < 0 or o + 1 >= N: return None
    s = []
    for k in range(0, m*2, 2):
        if o+k+1 >= N: break
        c = B[o+k] | (B[o+k+1] << 8)
        if c == 0: break
        if c < 0x20 or c > 0x7e: return None
        s.append(chr(c))
    return ''.join(s) if s else None
f = open(r'out\_sigfn.txt', 'w', encoding='utf-8')
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
dis(0x1400d92a0, 0x1400d96d3, 'sig_region')
dis(0x1400d7d80, 0x1400d8020, 'payload_builder_mid')
dis(0x1400d6fc0, 0x1400d7160, 'verifydate_fn')
f.close()
print('ok')
for va in (0x1400d92a0, 0x1400d94b0, 0x1400d9570, 0x1400d6fc0):
    print(hex(va), func_of(va))

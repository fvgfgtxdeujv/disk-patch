import struct
import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_OP_IMM

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
arr = np.frombuffer(B, dtype=np.uint8)
N = len(arr)
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

idx = np.arange(N - 8, dtype=np.int64)
pos = idx[(arr[idx] & 0xC7) == 0x05]
d = (arr[pos+1].astype(np.uint32) | (arr[pos+2].astype(np.uint32) << 8)
     | (arr[pos+3].astype(np.uint32) << 16) | (arr[pos+4].astype(np.uint32) << 24)).astype(np.uint32)
tgt0 = (BASE + pos.astype(np.int64) + 5) + d.astype(np.int64)

def refs(target):
    out = []
    for i in pos[(tgt0 == target)]:
        i = int(i)
        for back in range(1, 7):
            s = i - back
            if s < 0: continue
            ins = next(md.disasm(B[s:s+16], BASE + s, 1), None)
            if not ins: continue
            rip = [op for op in ins.operands if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP]
            if rip and BASE + s + ins.size + rip[0].mem.disp == target:
                out.append((BASE + s, ins.mnemonic + ' ' + ins.op_str)); break
    return out

def u16s(va, m=120):
    o = va - BASE
    s = []
    for k in range(0, m*2, 2):
        c = B[o+k] | (B[o+k+1] << 8)
        if c == 0 or c > 0x7e or c < 0x20: break
        s.append(chr(c))
    return ''.join(s) if s else None

def dis(va, end, f):
    for ins in md.disasm(B[va-BASE:end-BASE], va):
        note = ''
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                note += '   ; %x %r' % (t, u16s(t))
            elif op.type == X86_OP_IMM and BASE <= op.imm < BASE + N:
                s2 = u16s(op.imm)
                if s2: note += '   ; %x %r' % (op.imm, s2)
        f.write('%x %-8s %-46s%s\n' % (ins.address, ins.mnemonic, ins.op_str, note))

T = [0x1406d7b82, 0x1406d7b92, 0x1406d7fbc, 0x1406d7fac, 0x1406d800a, 0x1406d8022, 0x1406d8052, 0x1406d0308]
f = open(r'out\_respfn.txt', 'w', encoding='utf-8')
for t in T:
    rs = refs(t)
    f.write('\n#### %x %r refs=%d\n' % (t, u16s(t), len(rs)))
    for va, txt in rs:
        fr = func_of(va)
        f.write('   %x %-30s func=%s\n' % (va, txt, fr))
        if fr and fr[1] - fr[0] < 0x900:
            dis(va - 0x80, va + 0x100, f)
f.close()
print('ok')
for t in T:
    print(hex(t), u16s(t), len(refs(t)), [hex(x) for x, _ in refs(t)][:8])

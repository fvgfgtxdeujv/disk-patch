import struct
import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

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
            if not rip: continue
            if BASE + s + ins.size + rip[0].mem.disp == target:
                out.append((BASE + s, ins.mnemonic + ' ' + ins.op_str))
                break
    return out

def callers(t):
    r = []
    for i in range(N - 5):
        if B[i] == 0xE8:
            rel = struct.unpack_from('<i', B, i + 1)[0]
            if BASE + i + 5 + rel == t: r.append(BASE + i)
    return r

for t in (0x1400d95f8, 0x1400d96d4, 0x1400d92b4, 0x1400d94d8, 0x1401dd788):
    print('==== %x func=%s' % (t, func_of(t)))
    print('  direct callers:', [hex(x) for x in callers(t)])
    print('  addr refs:')
    for va, txt in refs(t):
        print('    %x %-40s func=%s' % (va, txt, func_of(va)))

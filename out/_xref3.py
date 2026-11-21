import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
arr = np.frombuffer(B, dtype=np.uint8)
N = len(arr)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

idx = np.arange(N - 8, dtype=np.int64)
pos = idx[(arr[idx] & 0xC7) == 0x05]
d = (arr[pos + 1].astype(np.uint32) | (arr[pos + 2].astype(np.uint32) << 8)
     | (arr[pos + 3].astype(np.uint32) << 16) | (arr[pos + 4].astype(np.uint32) << 24)).astype(np.uint32)
tgt0 = (BASE + pos.astype(np.int64) + 5) + d.astype(np.int64)

def u16s(va, maxlen=64):
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

rows = []
for lo, hi in ((0x1406b3000, 0x1406b3c00), (0x1406a1000, 0x1406a1400)):
    for i in pos[(tgt0 >= lo) & (tgt0 < hi)]:
        i = int(i)
        for back in range(1, 7):
            s = i - back
            va = BASE + s
            ins = next(md.disasm(B[s:s + 16], va, 1), None)
            if not ins:
                continue
            rip = [op for op in ins.operands if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP]
            if not rip:
                continue
            t = va + ins.size + rip[0].mem.disp
            if lo <= t < hi:
                rows.append((va, ins.mnemonic + ' ' + ins.op_str, t, u16s(t)))
                break

seen = set()
for va, txt, t, s in sorted(rows):
    key = (va, t)
    if key in seen:
        continue
    seen.add(key)
    print('%x  %-42s -> %x %r' % (va, txt, t, s))

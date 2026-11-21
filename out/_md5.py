import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

pat = struct.pack('<I', 0x67452301)
hits = []
i = 0
while True:
    i = B.find(pat, i)
    if i < 0:
        break
    hits.append(BASE + i)
    i += 1
print('MD5 init-state occurrences:', [hex(h) for h in hits])

def callers(t):
    r = []
    for k in range(N - 5):
        if B[k] == 0xE8:
            rel = struct.unpack_from('<i', B, k + 1)[0]
            if BASE + k + 5 + rel == t:
                r.append(BASE + k)
    return r
print('callers of md5 fn 0x1400d62fc:', [hex(x) for x in callers(0x1400d62fc)])
print('callers of hex fn 0x1401dd748:', [hex(x) for x in callers(0x1401dd748)])
print('callers of prep 0x1401dd6d4:', [hex(x) for x in callers(0x1401dd6d4)])

def u16s(va, m=60):
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

print('== md5 fn head')
for ins in md.disasm(B[0x1400d62fc-BASE: 0x1400d62fc-BASE+0x100], 0x1400d62fc):
    note = ''
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            t = ins.address + ins.size + op.mem.disp
            note += '  ; %x %r' % (t, u16s(t))
    print('%x %-8s %-40s%s' % (ins.address, ins.mnemonic, ins.op_str, note))

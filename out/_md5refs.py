import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64)

e = struct.unpack_from('<I', B, 0x3C)[0]
opt = e + 4 + 20
dd = opt + 112
exc, excsz = struct.unpack_from('<II', B, dd + 3 * 8)
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

print('MD5 0x1400d62fc callers:')
for c in callers(0x1400d62fc):
    print('  ', hex(c), func_of(c))
print()
print('0x1400d95f8-like refs? scan xor ax,0x0e patterns:')
pats = [(b'\x66\x35\x0e\x00', 'xor ax,0x0e'),
        (b'\x35\x0e\x00\x00\x00', 'xor eax,0x0e'),
        (b'\x66\x81', 'xor word [mem],imm16')]
hits = []
for pat, name in pats:
    st = 0
    while True:
        i = B.find(pat, st)
        if i < 0: break
        st = i + 1
        hits.append((BASE + i, name))
for va, name in sorted(hits):
    print('  %x %-20s func=%s' % (va, name, func_of(va)))
print()
print('MD5 IV constant writes scan (01 23 45 67 LE bytes):')
iv = struct.pack('<I', 0x67452301)
st = 0
while True:
    i = B.find(iv, st)
    if i < 0: break
    st = i + 1
    print('  %x func=%s' % (BASE + i, func_of(BASE + i)))

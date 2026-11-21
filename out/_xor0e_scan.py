import struct
BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
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

pats = [b'\x66\x83\xf0\x0e', b'\x66\x83\xf1\x0e', b'\x66\x83\xf2\x0e', b'\x66\x83\xf3\x0e',
        b'\x66\x83\xf7\x0e', b'\x66\x35\x0e\x00', b'\x35\x0e\x00\x00\x00',
        b'\x66\x81\xf0\x0e\x00', b'\x66\x81\xf1\x0e\x00', b'\x66\x81\xf2\x0e\x00']
seen = {}
for pat in pats:
    st = 0
    while True:
        i = B.find(pat, st)
        if i < 0: break
        st = i + 1
        va = BASE + i
        seen.setdefault(va, pat.hex())
for va, p in sorted(seen.items()):
    print('%x  %-14s func=%s' % (va, p, func_of(va)))

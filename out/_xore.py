import struct
BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
e = struct.unpack_from('<I', B, 0x3C)[0]
dd = e + 4 + 20 + 112
exc, excsz = struct.unpack_from('<II', B, dd + 3 * 8)
nfun = excsz // 12
def func_of(va):
    lo, hi = 0, nfun - 1
    while lo <= hi:
        m = (lo + hi) // 2
        b, en, u = struct.unpack_from('<III', B, exc + m * 12)
        if va - BASE < b: hi = m - 1
        elif va - BASE >= en: lo = m + 1
        else: return BASE + b, BASE + en
    return None
for pat, name in ((b'\x66\x83\xf0\x0e', 'xor ax,0xe'), (b'\x66\x35\x0e\x00', 'xor ax,0x000e'),
                  (b'\x83\xf0\x0e', 'xor eax,0xe'), (b'\x34\x0e', 'xor al,0xe')):
    hits = []
    i = 0
    while True:
        i = B.find(pat, i)
        if i < 0: break
        fr = func_of(BASE + i)
        if fr:
            hits.append((BASE + i, fr))
        i += 1
    print('==', name, len(hits))
    for a, fr in hits:
        print('  %x in %x-%x' % (a, fr[0], fr[1]))

import struct
BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
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
names = [b'appname=', b'license=', b'&license', b'regcode', b'regver', b'encryption=',
         b'check=', b'skey=', b'user=', b'email=', b'iplan', b'again=', b'VerifyDate',
         b'register.php', b'update.php', b'lid=', b'&mid=', b'ShowLicense']
for s in names:
    hits = []
    for enc, tag in ((s, 'A'), (s.decode().encode('utf-16-le'), 'U')):
        p = 0
        while True:
            i = B.find(enc, p)
            if i < 0: break
            p = i + 1
            if len(hits) < 6:
                hits.append((BASE + i, tag, func_of(BASE + i)))
    print(s.decode(), '->', [(hex(a), t, (hex(f[0]) if f else None)) for a, t, f in hits])
print()
# find sections list for .vmp range
opt = e + 4 + 20
nsec = struct.unpack_from('<H', B, e + 4 + 2)[0]
so = opt + struct.unpack_from('<H', B, e + 4 + 16)[0]
for i in range(nsec):
    o = so + i * 40
    nm = B[o:o+8].rstrip(b'\0').decode('latin1')
    vs, va, rs, ro = struct.unpack_from('<IIII', B, o + 8)
    if nm:
        print('%-8s va=%x size=%x' % (nm, BASE + va, vs))

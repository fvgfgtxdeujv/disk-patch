import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
e = struct.unpack_from('<I', B, 0x3C)[0]
dd = e + 4 + 20 + 112
exc, excsz = struct.unpack_from('<II', B, dd + 3 * 8)
nfun = excsz // 12
FUNCS = []
for i in range(nfun):
    b, en, u = struct.unpack_from('<III', B, exc + i * 12)
    FUNCS.append((BASE + b, BASE + en))
FUNCS.sort()
def func_of(va):
    lo, hi = 0, len(FUNCS) - 1
    while lo <= hi:
        m = (lo + hi) // 2
        b, en = FUNCS[m]
        if va < b: hi = m - 1
        elif va >= en: lo = m + 1
        else: return (b, en)
    return None

# call targets map: for each E8 in code
calls = {}
for i in range(N - 5):
    if B[i] != 0xE8:
        continue
    t = BASE + i + 5 + struct.unpack_from('<i', B, i + 1)[0]
    if BASE <= t < BASE + N:
        calls.setdefault(t, []).append(BASE + i)
print('call targets', len(calls))

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

def strrefs(fr):
    out = []
    for ins in md.disasm(B[fr[0]-BASE: fr[1]-BASE], fr[0]):
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                s = u16s(t)
                if s and (0x1406b3000 <= t < 0x1406b3c00 or 0x1406a1000 <= t < 0x1406a1400 or 'Options' in s):
                    out.append((ins.address, t, s))
    return out

# upward BFS
seen = set()
frontier = []
for f in (0x1401f71dc, 0x14020b020, 0x14020b114):
    fr = func_of(f)
    if fr: frontier.append(fr)
depth = 0
while frontier and depth < 5:
    nxt = []
    for fr in sorted(set(frontier)):
        if fr in seen: continue
        seen.add(fr)
        srs = strrefs(fr)
        print('D%d fn %x-%x strings=%s' % (depth, fr[0], fr[1], [(hex(a), s) for a, t, s in srs][:6]))
        for h in range(fr[0], fr[1]):
            pass
        # callers of function start
        for h in calls.get(fr[0], []):
            cf = func_of(h)
            if cf and cf not in seen:
                nxt.append(cf)
        # also any call inside function to known function starts -> those are callees, skip
    frontier = nxt
    depth += 1
print('total functions', len(seen))

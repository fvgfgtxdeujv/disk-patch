# -*- coding: utf-8 -*-
import numpy as np
VA = 0x1419D4000
P = np.fromfile('/workspace/dgwork/unpack6201829/DiskGenius_unpacked_vmp.bin', dtype=np.uint8)
N = len(P)
B = P.astype(np.uint32)
M = N - 6                                  # off 上限（需 off+5 < N）
op = (B[0:M] | (B[1:M+1] << 8)).astype(np.int64)
raw = (B[2:M+2] | (B[3:M+3] << 8) | (B[4:M+4] << 16) | (B[5:M+5] << 24)).astype(np.int64)
ln = np.where(raw >= 2**31, raw - 2**32, raw)

cand = (op > 0) & (op < 0x2000) & (ln >= 6) & (ln <= 0x400)
print('格式候选 %d / %d (%.2f%%)' % (cand.sum(), M, 100.0*cand.sum()/M))
idxs = np.nonzero(cand)[0]

def chain(start, max_steps=6000):
    off = start; n = 0; tot = 0
    while n < max_steps and off + 6 <= N:
        o = int(op[off]); L = int(ln[off])
        if not (0 < o < 0x2000 and 6 <= L <= 0x400):
            break
        off += L; tot += L; n += 1
    return n, tot, off

best = []
for s in idxs[::6]:
    n, tot, end = chain(int(s))
    if n >= 60:
        best.append((n, tot, int(s), end))
best.sort(reverse=True)
print('可走 >=60 步的起点：%d' % len(best))
for n, tot, s, e in best[:25]:
    print('  起点 %#x  步数 %5d  总长 %6d  终点 %#x' % (VA+s, n, tot, VA+e))

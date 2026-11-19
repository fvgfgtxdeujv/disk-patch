# -*- coding: utf-8 -*-
"""验证：E9 跳板的高频目标 = handler 入口？
   判据：从该目标线性解码，能否在有限步内精确落到某个 IP 站点（块尾）。
"""
import struct, json, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

VA = 0x1419D4000
P = open('/workspace/dgwork/unpack6201829/DiskGenius_unpacked_vmp.bin', 'rb').read()
N = len(P)
MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.skipdata = True

sites = {int(s['at'], 16) for s in json.load(open('/workspace/dgwork/ipslots_new.json'))['sites']}
print('IP 站点 %d' % len(sites))

# 1. E9 目标频率
freq = collections.Counter()
for off in range(N - 5):
    if P[off] == 0xE9:
        rel = struct.unpack_from('<i', P, off + 1)[0]
        dst = VA + off + 5 + rel
        if VA <= dst < VA + N:
            freq[dst] += 1

print('不同 E9 目标 %d' % len(freq))
print('被引用 >=3 次的目标 %d，>=10 次 %d' % (sum(1 for v in freq.values() if v >= 3),
                                       sum(1 for v in freq.values() if v >= 10)))
print('Top15:', ['%#x:%d' % (k, v) for k, v in freq.most_common(15)])

# 2. 从高频目标线性解码，看能否落到站点
def walk(start, max_insn=4000, max_bytes=16384):
    off = start - VA
    end = min(N, off + max_bytes)
    cnt = 0
    last = None
    for i in MD.disasm(P[off:end], start):
        cnt += 1
        if i.address in sites:
            return i.address, cnt
        last = i.address
        if cnt >= max_insn:
            break
    return None, cnt

top = [t for t, c in freq.most_common(300)]
hit = 0
details = []
for t in top:
    s, n = walk(t)
    if s:
        hit += 1
        details.append((t, s, n, freq[t]))

print('\nTop300 高频目标中，能走到 IP 站点的：%d' % hit)
for t, s, n, c in details[:15]:
    print('  入口 %#x (x%d) -> 站点 %#x  跨 %d 条指令' % (t, c, s, n))

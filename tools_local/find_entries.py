# -*- coding: utf-8 -*-
"""严格判据：从 E9 目标 T 出发，解码到「第一条 jmp」为止；
   若该 jmp 的地址正好是 IP 站点，则 T 是一个可信的 handler 入口。
"""
import struct, json, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

VA = 0x1419D4000
P = open('/workspace/dgwork/unpack6201829/DiskGenius_unpacked_vmp.bin', 'rb').read()
N = len(P)
MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.skipdata = True

sites = {int(s['at'], 16) for s in json.load(open('/workspace/dgwork/ipslots_new.json'))['sites']}

freq = collections.Counter()
for off in range(N - 5):
    if P[off] == 0xE9:
        rel = struct.unpack_from('<i', P, off + 1)[0]
        d = VA + off + 5 + rel
        if VA <= d < VA + N:
            freq[d] += 1


def to_first_jmp(start, max_insn=600):
    off = start - VA
    if off < 0 or off >= N:
        return None, 0
    n = 0
    for i in MD.disasm_lite(P[off:off + 8192], start):
        addr, size, mn, op = i
        n += 1
        if mn == 'jmp':
            return addr, n
        if mn in ('ret', 'hlt', 'ud2') or n >= max_insn:
            return None, n
    return None, n


good = []          # (entry, site, n_insn, refcount)
for t in sorted(freq, key=lambda x: -freq[x]):
    s, n = to_first_jmp(t)
    if s and s in sites:
        good.append((t, s, n, freq[t]))

print('E9 目标 %d；能「解码到第一条 jmp 且落在 IP 站点」的入口：%d' % (len(freq), len(good)))
covered = {g[1] for g in good}
print('覆盖 IP 站点 %d / %d = %.1f%%' % (len(covered), len(sites), 100.0 * len(covered) / len(sites)))

lens = collections.Counter()
for g in good:
    L = g[2]
    lens['1-20' if L <= 20 else '21-60' if L <= 60 else '61-200' if L <= 200 else '>200'] += 1
print('入口块长分布：', dict(lens))
print('入口被 E9 引用次数分布：', collections.Counter(min(g[3], 8) for g in good))

print('\n入口 -> 站点 样例（前 12）：')
for g in good[:12]:
    print('  %#x (x%d) -> %#x  %d 条' % (g[0], g[3], g[1], g[2]))

json.dump([{'entry': hex(g[0]), 'site': hex(g[1]), 'n': g[2], 'refs': g[3]} for g in good],
          open('/workspace/dgwork/handler_entries.json', 'w'), indent=0)
print('\n已写 handler_entries.json')

# -*- coding: utf-8 -*-
"""扫描 .vmp 段内全部 E9 rel32，统计目标分布 / 跳板墙范围 / 目标集合规模。"""
import collections

CODE_BASE = 0x141D34000
P = open('/workspace/dgwork/payload.bin', 'rb').read()
N = len(P)

targets = []          # (src_va, dst_va)
for off in range(N - 5):
    if P[off] == 0xE9:
        rel = int.from_bytes(P[off + 1:off + 5], 'little', signed=True)
        src = CODE_BASE + off
        dst = src + 5 + rel
        targets.append((src, dst))

inside = [(s, d) for s, d in targets if CODE_BASE <= d < CODE_BASE + N]
print('E9 总数 %d，目标落在 .vmp 内 %d (%.1f%%)' % (len(targets), len(inside), 100.0 * len(inside) / max(1, len(targets))))

dstset = set(d for _, d in inside)
print('去重目标 %d' % len(dstset))

# 目标按 64KB / 1MB 分桶，看是否集中在某段
buckets = collections.Counter((d >> 20) for d in dstset)
print('\n目标按 1MB 分桶（只列 >50 的）：')
for k in sorted(buckets):
    if buckets[k] > 50:
        print('  0x%08x - 0x%08x : %5d' % (CODE_BASE + (k << 20) - CODE_BASE + CODE_BASE, 0, buckets[k]) if False else
              '  [%#x, %#x) : %5d' % ((k << 20), ((k + 1) << 20), buckets[k]))

# 跳板墙：src 与 dst 都连续递增的区段
runs = []
cur = []
prev = None
for s, d in sorted(inside):
    if prev is not None and s - prev[0] <= 8 and 0 < d - prev[1] < 0x100000:
        cur.append((s, d))
    else:
        if len(cur) >= 20:
            runs.append(cur)
        cur = [(s, d)]
    prev = (s, d)
if len(cur) >= 20:
    runs.append(cur)

print('\n连续 E9 墙（长度>=20）：%d 段' % len(runs))
for r in sorted(runs, key=len, reverse=True)[:10]:
    gaps = collections.Counter(b[0] - a[0] for a, b in zip(r, r[1:]))
    print('  %#x .. %#x  项数 %5d  项距 %s' % (r[0][0], r[-1][0], len(r), dict(list(gaps.items())[:3])))

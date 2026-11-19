#!/usr/bin/env python3
"""分析 v12 产物：授权字符串池命中现场。

用法: python3 analyze_lic.py <artifact_dir>
"""
import json
import glob
import os
import struct
import sys
from collections import Counter, defaultdict

POOL = (0x1406b3300, 0x1406b3b00)


def qwords(data):
    out = []
    for i in range(0, len(data) - 7, 8):
        out.append((i, struct.unpack_from('<Q', data, i)[0]))
    return out


def ptrs(data, lo=0x140000000, hi=0x143000000):
    res = []
    for off, q in qwords(data):
        if lo <= q < hi:
            res.append((off, q))
    for i in range(1, 8):
        for off, q in qwords(data[i:]):
            if lo <= q < hi:
                res.append((i + off, q))
    return res


def main(d):
    lic = os.path.join(d, 'lic_trace.json')
    if os.path.exists(lic):
        hits = json.load(open(lic))
        print('== lic_trace.json: %d 次命中 ==' % len(hits))
        byctx = Counter((h['regs'].get('rbp'), h['tid']) for h in hits)
        for (rbp, tid), c in byctx.most_common(10):
            print('  ctx=%s tid=%s x%d' % (rbp, tid, c))
        for h in hits[:8]:
            print('  t=%s tid=%s rip=%s 命中 %s' % (h['t'], h['tid'],
                                                    h['regs']['rip'], h['hit']))
    else:
        print('!! 没有 lic_trace.json')

    for f in sorted(glob.glob(os.path.join(d, 'lic_*.bin'))):
        data = open(f, 'rb').read()
        ps = ptrs(data)
        inpool = [(o, v) for o, v in ps if POOL[0] <= v < POOL[1]]
        print('\n== %s (%d B) 指针 %d, 池内 %d ==' %
              (os.path.basename(f), len(data), len(ps), len(inpool)))
        for o, v in inpool[:12]:
            print('   +%#06x -> %#x' % (o, v))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

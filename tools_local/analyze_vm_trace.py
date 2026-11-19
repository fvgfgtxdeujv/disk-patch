#!/usr/bin/env python3
"""分析 v14 的 vm_trace.json：逐条 VM 指令轨迹。

得到的关键量：
  - op / handler 一致性（同一 op 是否总是同一 handler）
  - 指令长度 = 下一条的 ip - 当前 ip（自描述 rel 的实测值）
  - 控制流：长度异常（跳转）的位置
  - 可解码指令表：ip, op, len, handler

用法: python3 analyze_vm_trace.py <vm_trace.json>
"""
import json
import sys
from collections import Counter, defaultdict


def main(path):
    d = json.load(open(path))
    tr = d['trace']
    n = d['n']
    print('轨迹条数: %d（导出 %d）' % (n, len(tr)))
    if not tr:
        return
    ips = [t[0] for t in tr]
    ops = [t[1] for t in tr]
    hds = [t[2] for t in tr]
    print('唯一 ip: %d，唯一 op: %d，唯一 handler: %d'
          % (len(set(ips)), len(set(ops)), len(set(hds))))
    print('op 直方图 top20:', Counter(ops).most_common(20))

    # op -> handler 一致性
    byop = defaultdict(set)
    for op, hd in zip(ops, hds):
        byop[op].add(hd)
    bad = {op: hs for op, hs in byop.items() if len(hs) > 1}
    print('op→handler 多值（应为 1）:', len(bad), list(bad.items())[:5])

    # 指令长度 = 下一条 ip - 当前 ip
    lens = []
    for i in range(len(tr) - 1):
        if tr[i + 1][0] > tr[i][0]:
            lens.append((tr[i][0], tr[i][1], tr[i + 1][0] - tr[i][0], tr[i][2]))
    if lens:
        c = Counter(l[2] for l in lens)
        print('指令长度分布 top15:', c.most_common(15))
        print('最小 %d 最大 %d' % (min(c), max(c)))

    # 按 op 统计长度稳定性
    oplen = defaultdict(Counter)
    for ip, op, ln, hd in lens:
        oplen[op][ln] += 1
    stable = sum(1 for op, c in oplen.items() if len(c) == 1)
    print('长度唯一的 op: %d / %d' % (stable, len(oplen)))

    print('\n前 40 条（ip, op, len, handler）:')
    for i in range(min(40, len(lens))):
        ip, op, ln, hd = lens[i]
        print('  %#x  op=%-5d len=%-4d handler=%#x' % (ip, op, ln, hd))

    out = path.replace('.json', '_insn.json')
    json.dump({'insn': [[ip, op, ln, hd] for ip, op, ln, hd in lens]},
              open(out, 'w'))
    print('\n已写 %s（%d 条带长度的指令）' % (out, len(lens)))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'vm_trace.json')

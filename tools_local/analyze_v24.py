#!/usr/bin/env python3
"""分析 v24 vm_trace.json（table-plain 模式）：
- 槽表解码出的明文指令清单（按 IP 去重，op 自证 + rel 合理性）
- 顺序轨迹 → CFG 边（op/rel/next）
- op → handler 表号/项号 映射
用法: python3 analyze_v24.py <vm_trace.json> [输出目录]
"""
import json, struct, sys, collections, os

def main():
    path = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.abspath(path))
    d = json.load(open(path))
    mode = d.get('mode')
    trace = d.get('trace', [])
    insns = d.get('insns', [])
    tables = d.get('tables', [])
    print('mode=%s 轨迹=%d 槽表明文=%d op自证=%d rel合理=%d dead_at=%s'
          % (mode, d.get('n', 0), len(insns), d.get('insns_ok_op'),
             d.get('insns_ok_rel'), d.get('dead_at')))
    print('表:', tables)

    # ---- 1. 按 IP 去重的指令清单（op 自证优先）----
    byip = {}
    for ip, op, rel, m, tg in insns:
        cur = byip.get(ip)
        if cur is None or (m and not cur[3]):
            byip[ip] = [ip, op, rel, m, tg]
    print('\n== 指令清单（按 IP 去重）: %d 条 ==' % len(byip))
    ok_op = sum(1 for v in byip.values() if v[3])
    inr = sum(1 for ip, op, rel, m, tg in byip.values()
              if m and any(ip + rel >= tv and ip + rel < tv + nn * 8
                           for tv, nn in
                           [(int(t, 16), n) for t, n in tables]))
    print('op 自证: %d/%d' % (ok_op, len(byip)))
    rows = sorted(byip.values(), key=lambda v: (v[4] >> 20, v[4] & 0xFFFFF))
    lines = ['ip,op,rel,next,op_ok,table,entry']
    for ip, op, rel, m, tg in rows:
        lines.append('%#x,%d,%d,%#x,%s,%d,%d'
                     % (ip, op, rel, ip + rel, m, tg >> 20, tg & 0xFFFFF))
        if m and len([1 for v in rows[:rows.index([ip, op, rel, m, tg]) + 1]]) < 400:
            pass
    with open(os.path.join(outdir, 'v24_insns.csv'), 'w') as f:
        f.write('\n'.join(lines) + '\n')
    print('已写 v24_insns.csv')

    # ---- 2. op 频次 ----
    ops = collections.Counter(v[1] for v in byip.values())
    print('\nop 分布（%d 种）前 20:' % len(ops), ops.most_common(20))

    # ---- 3. 顺序轨迹 → CFG 边 ----
    edges = collections.Counter()
    seq_ips = set()
    for e in trace:
        ip = e[0]
        if not ip:
            continue
        seq_ips.add(ip)
        bb = struct.pack('<QQ', e[1], e[2])
        op = struct.unpack_from('<H', bb, 0)[0]
        rel = struct.unpack_from('<i', bb, 2)[0]
        edges[(ip, ip + rel)] += 1
    print('\n轨迹里不同 IP %d，CFG 边 %d 种（重复边 %d）'
          % (len(seq_ips), len(edges), sum(1 for _, c in edges.items() if c > 1)))
    # 与槽表清单交叉：轨迹中的 IP 有多少已可解码
    covered = len(seq_ips & set(byip))
    print('轨迹 IP 已被槽表覆盖: %d/%d' % (covered, len(seq_ips)))

    with open(os.path.join(outdir, 'v24_summary.json'), 'w') as f:
        json.dump({'n_insn_unique': len(byip), 'ok_op': ok_op,
                   'ops': dict(ops), 'edges': [[a, b, c] for (a, b), c in
                                               edges.most_common(5000)],
                   'trace_ips': len(seq_ips), 'covered': covered}, f)
    print('已写 v24_summary.json')

if __name__ == '__main__':
    main()

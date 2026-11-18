# -*- coding: utf-8 -*-
"""
resolve_map.py —— 把运行期 dump 出来的表，闭合为 opcode -> handler 映射

输入（两种都认）
  tables.json         dump_runtime.py 的输出（首选，带 slot / 字节流 / 判定）
  table_*.bin         原始表（每项 8 字节），作为补充

三件事
  1) 表项解码：保护器可能对表项做变换（xor/sub/add 常量，或存 32 位 RVA）。
     不硬编码常量 —— 用「解出来的地址必须全部落在可执行段」这个约束**反解**：
     枚举 H[0] 的候选（按 64KB 对齐遍历代码段），令 K = raw[0] ^ H[0]，
     再用其余项验证。代码段 ~14MB -> 约 220 个候选，秒级收敛。
  2) 表识别：用字节流里实际出现的 opcode 反查哪张表是 opcode 表
     （凡是流里出现过的 opcode，都必须 < 表长度）。
  3) 字节流反汇编：按 `[u16 opcode][i32 len]` 线性走，输出每条指令。

用法
  python resolve_map.py --json tables.json --out map.json
  python resolve_map.py --dir ./dump --out map.json
"""
import argparse
import base64
import glob
import json
import os
import struct
import sys

MASK64 = 0xFFFFFFFFFFFFFFFF
# handler 地址按 16 字节对齐（实际观测如此）；反解时按此步长枚举 H[0]
H0_STEP = 16
FAST_N = 4                      # 反解时先用前几项粗筛，通过再全量验证


# ---------------------------------------------------------------- 编码反解

def _frac_in(vals, lo, hi, fn):
    hit = 0
    for v in vals:
        t = fn(v)
        if lo <= t < hi:
            hit += 1
    return hit / len(vals) if vals else 0.0


def solve_transform(vals, lo, hi, min_frac=0.9, entries=None, max_cand=48):
    """
    求 raw -> 真地址 的变换。

    注意「平移歧义」：若整表下移 0x1000 后仍全部落在代码段内，那么两个不同的
    xor 常量都能让 frac=1.0。所以只靠范围约束无法唯一定解 —— 必须用
    静态 handler 入口集合（entries）做交叉验证，取命中数最多的候选。

    返回 (名称, 函数, 命中率, 候选列表)。
    """
    vals_nz = [v for v in vals if v]
    n = len(vals_nz)
    if n < 4:
        return None, None, 0.0, []

    # 1) 明文绝对地址
    f = _frac_in(vals_nz, lo, hi, lambda v: v)
    if f >= min_frac:
        return 'raw', (lambda v: v), f, [('raw', f, 0)]

    # 2) 32 位 RVA
    for base in (0x140000000, 0, lo - (lo & 0xFFFFFFFF)):
        f = _frac_in(vals_nz, lo, hi, lambda v, b=base: (v & 0xFFFFFFFF) + b)
        if f >= min_frac:
            return ('rva+%#x' % base,
                    (lambda v, b=base: (v & 0xFFFFFFFF) + b), f,
                    [('rva+%#x' % base, f, 0)])

    # 3) 约束反解 + entries 消歧
    v0 = vals_nz[0]
    fast = vals_nz[:FAST_N]
    need = max(1, len(fast) - 1)
    cands = []

    h0 = lo & ~(H0_STEP - 1)
    while h0 < hi:
        for name, fn in (
                ('xor', (lambda v, K=v0 ^ h0: v ^ K)),
                ('sub', (lambda v, C=(v0 - h0) & MASK64: (v - C) & MASK64)),
                ('add', (lambda v, A=(h0 - v0) & MASK64: (v + A) & MASK64))):
            if sum(1 for v in fast if lo <= fn(v) < hi) < need:
                continue
            f = _frac_in(vals_nz, lo, hi, fn)
            if f < min_frac:
                continue
            # 用 entries 数命中；没有 entries 就数「落在代码段的项数」
            if entries:
                sc = sum(1 for v in vals_nz if fn(v) in entries)
            else:
                sc = 0
            if name == 'xor':
                label = 'xor %#x' % (v0 ^ h0)
            elif name == 'sub':
                label = 'sub %#x' % ((v0 - h0) & MASK64)
            else:
                label = 'add %#x' % ((h0 - v0) & MASK64)
            cands.append((label, f, sc, fn))
            # 命中过半就能确信，立刻收手（真实数据里正解会命中几百项，
            # 错误平移只能碰巧撞上几个，这个差距非常大）
            if entries and sc >= max(4, len(vals_nz) // 2):
                return label, fn, f, [(c[0], round(c[1], 3), c[2]) for c in cands]
            if len(cands) >= max_cand and entries:
                break
        h0 += H0_STEP
        if len(cands) >= max_cand and not entries:
            break

    if not cands:
        return None, None, 0.0, []

    # 有 entries：命中数优先；否则：先到先得（并提示歧义）
    if entries:
        cands.sort(key=lambda x: (-x[2], -x[1]))
    best = cands[0]
    summary = [(c[0], round(c[1], 3), c[2]) for c in cands[:8]]
    return best[0], best[3], best[1], summary


# ---------------------------------------------------------------- 表判定

def opcode_width_hint(ops, nentries):
    """
    流里最大 opcode 与表长的关系：表长必须 > max(op) 才是 opcode 表。
    返回 (是否兼容, 提示)
    """
    if not ops:
        return True, '无流可比'
    mx = max(ops)
    if nentries <= mx:
        return False, '表长 %d <= max(op)=%#x，不是 opcode 表' % (nentries, mx)
    # 表长最接近的 2 的幂
    p = 1
    while p <= mx:
        p <<= 1
    return True, 'max(op)=%#x -> 至少 %d 项（实际 %d）' % (mx, p, nentries)


def walk(raw, max_steps=65536):
    """按 [u16][i32] 走流，返回 [(off, op, len)]"""
    out = []
    off = 0
    while off + 6 <= len(raw) and len(out) < max_steps:
        op = struct.unpack_from('<H', raw, off)[0]
        ln = struct.unpack_from('<i', raw, off + 2)[0]
        if not (0 < op < 0x4000 and 6 <= ln <= 0x400):
            break
        out.append((off, op, ln))
        off += ln
    return out, off


# ---------------------------------------------------------------- 输入

def load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def tables_from_json(d):
    """从 dump_runtime 的 tables.json 提取 {label: (table_va, [entries])}"""
    best = d.get('best') or {}
    out = {}
    for slot, v in (best.get('tables') or {}).items():
        ents = v.get('entries') or []
        if ents:
            out['table_%s' % slot] = (int(v['table_va'], 16), list(ents))
    return out


def streams_from_json(d):
    best = d.get('best') or {}
    out = {}
    for slot, v in (best.get('streams') or {}).items():
        raw = base64.b64decode(v['b64'])
        out['stream_%s' % slot] = (int(v['ip'], 16), raw)
    return out


def tables_from_dir(path):
    out = {}
    for p in sorted(glob.glob(os.path.join(path, 'table_*.bin'))):
        raw = open(p, 'rb').read()
        n = len(raw) // 8
        if n:
            out[os.path.splitext(os.path.basename(p))[0]] = (
                0, list(struct.unpack_from('<%dQ' % n, raw)))
    return out


def streams_from_dir(path):
    out = {}
    for p in sorted(glob.glob(os.path.join(path, 'stream_*.bin'))):
        out[os.path.splitext(os.path.basename(p))[0]] = (0, open(p, 'rb').read())
    return out


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json', help='dump_runtime.py 输出的 tables.json')
    ap.add_argument('--dir', help='dump 目录（table_*.bin / stream_*.bin）')
    ap.add_argument('--entries', default='handler_entries.json',
                    help='静态 handler 入口集合（可选，用于交叉验证）')
    ap.add_argument('--ranges', default='',
                    help='可执行段，形如 0x1419D4000-0x142780000，逗号分隔；'
                         '留空则从 tables.json 的 code_ranges 读')
    ap.add_argument('--out', default='map.json')
    ap.add_argument('--handlers', default='handlers.py',
                    help='输出 opcode->handler 的 Python 表')
    ap.add_argument('--disasm', type=int, default=40, help='每段流打印多少条')
    a = ap.parse_args()

    d = {}
    if a.json and os.path.exists(a.json):
        d = load_json(a.json)
        tabs = tables_from_json(d)
        strs = streams_from_json(d)
        print('[*] 读 %s：%d 张表 / %d 段流' % (a.json, len(tabs), len(strs)))
    elif a.dir:
        tabs = tables_from_dir(a.dir)
        strs = streams_from_dir(a.dir)
        print('[*] 读目录 %s：%d 张表 / %d 段流' % (a.dir, len(tabs), len(strs)))
    else:
        sys.exit('[-] 给 --json 或 --dir')

    if not tabs:
        sys.exit('[-] 没有任何表。检查 dump 是否抓到 ctx。')

    # 代码段范围
    ranges = []
    if a.ranges:
        for part in a.ranges.split(','):
            lo, hi = part.split('-')
            ranges.append((int(lo, 16), int(hi, 16)))
    elif d.get('code_ranges'):
        ranges = [(int(x, 16), int(y, 16)) for x, y in d['code_ranges']]
    else:
        sys.exit('[-] 不知道代码段范围，用 --ranges 指定')
    print('[*] 可执行段 %s' % [('%#x-%#x' % r) for r in ranges])

    def in_code(v):
        return any(lo <= v < hi for lo, hi in ranges)

    # 流里出现过的 opcode 全集（用来判定哪张表是 opcode 表）
    all_ops = set()
    stream_info = {}
    for name, (ip, raw) in strs.items():
        ins, used = walk(raw)
        ops = [x[1] for x in ins]
        all_ops |= set(ops)
        stream_info[name] = {'ip': ip, 'insns': ins, 'used': used,
                             'maxop': max(ops) if ops else 0}
        print('[*] %s ip=%#x 走通 %d 条 / %d 字节，opcode %d 种，最大 %#x'
              % (name, ip, len(ins), used, len(set(ops)), max(ops) if ops else 0))

    # 静态 handler 入口集合（用于给编码反解消歧 + 交叉验证）。
    # 静态分析基于 ImageBase=0x140000000；运行期可能因 ASLR 换基址，要平移。
    entries = None
    delta = 0
    if d.get('module_base'):
        delta = int(d['module_base'], 16) - 0x140000000
    if os.path.exists(a.entries):
        entries = set()
        for e in json.load(open(a.entries, encoding='utf-8')):
            entries.add(int(e['entry'], 16) + delta)
            entries.add(int(e['site'], 16) + delta)
        print('[*] 静态 handler 入口 %d 个（ASLR 平移 %+#x）' % (len(entries), delta))
    else:
        print('[!] 没有 %s —— 编码反解无法消歧，只能取首个满足约束的解' % a.entries)

    # 逐表解码
    result = {'ranges': [[x, y] for x, y in ranges],
              'json_verdict': d.get('verdict'),
              'delta': delta,
              'tables': {}, 'streams': {}, 'opcode_table': None}

    for name, (tva, vals) in sorted(tabs.items()):
        lo, hi = ranges[0]
        tname, fn, frac, cands = solve_transform(vals, lo, hi, entries=entries)
        print('\n[%s] %d 项 @ %#x' % (name, len(vals), tva))
        if not fn or frac < 0.5:
            print('    编码未解出（最佳 %s，命中 %.0f%%）—— 表项可能加过密，'
                  '或表本身不是 handler 表' % (tname, frac * 100))
            result['tables'][name] = {'table_va': hex(tva), 'n': len(vals),
                                      'transform': tname, 'frac': frac,
                                      'entries': {}}
            continue
        print('    编码 %s（命中 %.1f%%）' % (tname, frac * 100))
        if len(cands) > 1:
            print('    候选（名称, 命中率, entries 命中）: %s' % cands[:6])
        m = {i: fn(v) for i, v in enumerate(vals) if v and in_code(fn(v))}
        print('    可解码 %d/%d 项，唯一 handler %d 个'
              % (len(m), len(vals), len(set(m.values()))))

        ok, hint = opcode_width_hint(all_ops, len(vals))
        print('    opcode 位宽: %s（%s）' % ('兼容' if ok else '不兼容', hint))

        known = 0
        if entries:
            known = sum(1 for v in m.values() if v in entries)
            print('    命中静态 handler 入口 %d/%d' % (known, len(m)))

        result['tables'][name] = {'table_va': hex(tva), 'n': len(vals),
                                  'transform': tname, 'frac': frac,
                                  'candidates': cands,
                                  'n_decoded': len(m), 'n_uniq': len(set(m.values())),
                                  'op_width_ok': ok, 'known_hits': known,
                                  'entries': {hex(k): hex(v) for k, v in sorted(m.items())}}
        for k in sorted(m)[:8]:
            print('      [%4d] %#x' % (k, m[k]))

    # 挑 opcode 表：优先「流里 opcode 全覆盖 且 唯一 handler 多」的那张
    best = None
    for name, t in result['tables'].items():
        if not t.get('entries'):
            continue
        n = t['n']
        if not t.get('op_width_ok', True):
            continue                      # 表长装不下流里的 opcode，直接排除
        covered = sum(1 for o in all_ops if o < n)
        # 覆盖流 opcode 只说明「装得下」，任何等长表都满足；
        # 真正的判据是与静态 handler 入口的命中数
        score = ((covered / len(all_ops) if all_ops else 0) * 1000
                 + t.get('known_hits', 0) * 10
                 + t['n_uniq'] * 0.001)
        if best is None or score > best[0]:
            best = (score, name, covered)
    if best:
        _, name, covered = best
        print('\n[+] 最像 opcode 表: %s（覆盖流中 %d/%d 种 opcode）'
              % (name, covered, len(all_ops)))
        result['opcode_table'] = name

        # 输出 handlers.py
        t = result['tables'][name]
        lines = ['# 自动生成：opcode -> handler 地址（来自运行期 dump）',
                 '# 表 %s  变换 %s  项数 %d' % (name, t['transform'], t['n']),
                 'HANDLERS = {']
        for k in sorted(t['entries'], key=lambda x: int(x, 16)):
            lines.append('    %s: %s,' % (k, t['entries'][k]))
        lines.append('}')
        with open(a.handlers, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
        print('    写 %s（%d 项）' % (a.handlers, len(t['entries'])))

        # 用这张表反汇编流
        hmap = {int(k, 16): int(v, 16) for k, v in t['entries'].items()}
        for sname, si in stream_info.items():
            print('\n[%s] 前 %d 条：' % (sname, a.disasm))
            for off, op, ln in si['insns'][:a.disasm]:
                h = hmap.get(op)
                print('   +%04x  op=%03x len=%3d  -> %s' % (
                    off, op, ln, ('%#x' % h) if h else '未映射'))
            result['streams'][sname] = {
                'ip': hex(si['ip']), 'n_insn': len(si['insns']),
                'bytes': si['used'],
                'disasm': [{'off': o, 'op': op, 'len': l,
                            'h': (hex(hmap[op]) if op in hmap else None)}
                           for o, op, l in si['insns'][:2000]]}

    with open(a.out, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=1)
    print('\n[+] 已写 %s' % a.out)
    return 0


if __name__ == '__main__':
    sys.exit(main())

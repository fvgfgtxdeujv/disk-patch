#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
X86IL VM 字节码反汇编器 —— 流水线最后一环。

输入
----
  --stream stream.bin / tables.json    VM 程序字节流（[u16 opcode][i32 len][operands]）
  --map map.json                       resolve_map.py 的输出（opcode → handler 地址）
  --handlers handlers.py               x86il_deobf_v2.py --emit 的语义表（可选）
  --base 0x...                         字节流的 VA（tables.json 的 ip 字段）

输出
----
  1) 线性反汇编：[off] op=0x12(名称) len=10  args hex
  2) 统计：opcode 直方图、ctx 偏移直方图、大立即数排行
  3) 授权定位线索（--license）：
     - cmp/eq 类 opcode 的密集段（判定树）
     - 大立即数（≥0x10000，候选密钥/魔数/到期时间戳）
     - 引用 ctx 高偏移区的指令（授权状态通常存在 ctx 特定槽位）

用法
----
  python3 x86il_disasm.py --stream stream_0x73.bin --map map.json --base 0x141a14000
  python3 x86il_disasm.py --stream s.bin --map map.json --license --out lic.txt
"""

import argparse
import base64
import json
import struct
import sys
from collections import Counter, defaultdict

HDR = 6          # u16 opcode + i32 len


def load_stream(path):
    """兼容 .bin 与 tables.json/b64"""
    if path.endswith('.json'):
        d = json.load(open(path, encoding='utf-8'))
        best = d.get('best') or {}
        streams = best.get('streams') or {}
        if not streams:
            raise SystemExit('tables.json 里没有流')
        items = []
        for slot, v in sorted(streams.items()):
            raw = base64.b64decode(v['b64'])
            items.append((slot, int(v['ip'], 16), raw))
        return items
    raw = open(path, 'rb').read()
    return [('file', None, raw)]


def load_map(path):
    """map.json → {opcode: handler_va}，取 opcode_table"""
    if not path:
        return {}
    d = json.load(open(path, encoding='utf-8'))
    t = d.get('opcode_table') or {}
    return {int(k, 0): int(v, 0) for k, v in (t.get('entries') or {}).items()}


def load_handlers(path):
    """handlers.py → {opcode: {'name':…, 'summary':…}}（有就带语义）"""
    if not path:
        return {}
    ns = {}
    exec(open(path, encoding='utf-8').read(), ns)
    h = ns.get('HANDLERS') or {}
    # handlers.py 可能以 handler 地址为键，这里由调用方按 map 对齐
    return h


def parse(raw, limit=None):
    """线性走流。返回 [(off, op, length, payload_bytes)]"""
    out = []
    off = 0
    n = len(raw) if limit is None else min(len(raw), limit)
    while off + HDR <= n:
        op = raw[off] | (raw[off + 1] << 8)
        ln = struct.unpack_from('<i', raw, off + 2)[0]
        if not (0 < op < 0x4000) or not (HDR <= ln <= 0x400):
            break
        payload = raw[off + HDR:off + ln]
        out.append((off, op, ln, payload))
        off += ln
    return out


def imms(payload):
    """粗提取立即数：4 字节对齐 u32 + 8 字节 qword（重叠去重）"""
    vals = []
    for o in range(0, len(payload) - 3):
        vals.append(struct.unpack_from('<I', payload, o)[0])
    for o in range(0, len(payload) - 7):
        vals.append(struct.unpack_from('<Q', payload, o)[0])
    return vals


def ctx_refs(payload):
    """粗提取 ctx 偏移访问：所有 u32/i32 值中落在 [0,0x1000) 的（槽位范围）"""
    refs = []
    for o in range(0, len(payload) - 3):
        v = struct.unpack_from('<i', payload, o)[0]
        if 0 <= v < 0x1000:
            refs.append(v)
    return refs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--stream', required=True)
    ap.add_argument('--map')
    ap.add_argument('--handlers')
    ap.add_argument('--base', help='流的 VA（hex）')
    ap.add_argument('--limit', type=int, default=0, help='只解析前 N 字节')
    ap.add_argument('--license', action='store_true', help='输出授权定位线索')
    ap.add_argument('--out', default='-', help='反汇编输出文件（- = stdout）')
    ap.add_argument('--max-insn', type=int, default=100000)
    a = ap.parse_args()

    streams = load_stream(a.stream)
    opmap = load_map(a.map)
    base = int(a.base, 0) if a.base else None

    outf = sys.stdout if a.out == '-' else open(a.out, 'w', encoding='utf-8')

    for slot, ip, raw in streams:
        if base is None and ip:
            base = ip
        insns = parse(raw, a.limit or None)[:a.max_insn]
        va0 = base if base is not None else 0
        print('=== 流槽 %s  ip=%s  %d 字节  %d 条指令 ==='
              % (slot, hex(ip) if ip else '?', len(raw), len(insns)), file=outf)

        op_hist = Counter()
        imm_hist = Counter()
        ctx_hist = Counter()
        for off, op, ln, payload in insns:
            op_hist[op] += 1
            name = 'op_%02x' % op
            txt = '%#010x  %-8s len=%-4d %s' % (
                va0 + off, name, ln, payload.hex(' ')[:96])
            print(txt, file=outf)
            for v in imms(payload):
                if v >= 0x10000:
                    imm_hist[v] += 1
            for r in ctx_refs(payload):
                ctx_hist[r] += 1

        print(file=outf)
        print('--- opcode 直方图 (top 30) ---', file=outf)
        for op, c in op_hist.most_common(30):
            print('  op_%02x x%-5d %s' % (op, c, hex(opmap[op]) if op in opmap else ''),
                  file=outf)
        print('--- 大立即数 (top 40，候选密钥/魔数/时间戳) ---', file=outf)
        for v, c in imm_hist.most_common(40):
            print('  %#018x x%d' % (v, c), file=outf)
        print('--- ctx 偏移访问 (top 30) ---', file=outf)
        for r, c in ctx_hist.most_common(30):
            print('  ctx[0x%03x] x%d' % (r, c), file=outf)

        if a.license:
            print('\n--- 授权定位线索 ---', file=outf)
            # 1) 判定树：相邻出现的比较类 opcode（名字未知，先用稀疏度）
            sparse = [op for op, c in op_hist.items() if c <= 3]
            print('  低频 opcode（专用指令候选，含授权判定）: %s'
                  % ['op_%02x(%d)' % (op, op_hist[op]) for op in sparse[:30]],
                  file=outf)
            # 2) 时间戳形立即数
            ts = [v for v in imm_hist if 1_500_000_000 <= v <= 4_000_000_000]
            print('  Unix 时间戳形立即数: %s' % [hex(v) for v in ts[:20]], file=outf)
            # 3) 大常量（非地址范围）
            big = [v for v in imm_hist
                   if v > 0x10000 and not (0x140000000 <= v < 0x144000000)]
            print('  非地址大立即数 top20: %s'
                  % ['%#x(x%d)' % (v, imm_hist[v]) for v in big[:20]], file=outf)

    if a.out != '-':
        print('[+] 已写 %s' % a.out)
        outf.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())

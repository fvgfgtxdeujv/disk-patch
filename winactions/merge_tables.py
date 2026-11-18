# -*- coding: utf-8 -*-
"""
merge_tables.py —— 把 dump_ctx.py 抓回来的表合并成 opcode -> handler 映射

输入：tables.json（GitHub Actions 产物）
      {
        "ctx_va": "0x...",
        "tables": {
          "0x8":  {"table_va": "0x...", "entries": [0x...]},
          "0xF5": {"table_va": "0x...", "entries": [0x...]}
        }
      }

输出：
  * handlers.py —— 形如 {opcode: handler_va}，直接给 x86il_deobf_v2.py 用
  * 控制台报告：每张表的项数、是否有重复/别名、opcode 宽度推断

用法：
  python merge_tables.py tables.json --image-base 0x140000000 --out handlers.py
  python merge_tables.py tables.json --vmp-rva 0x1D34000 --code-base 0x141D34000
"""
import json
import argparse
import collections


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('tables')
    ap.add_argument('--out', default='handlers.py')
    ap.add_argument('--image-base', default=None, help='模块基址，默认 0x140000000')
    ap.add_argument('--vmp-rva', default=None, help='VM 代码区 RVA，默认 0x1D34000')
    ap.add_argument('--code-base', default=None, help='直接给 VM 代码区基址')
    ap.add_argument('--dump-rva', default=None,
                    help='静态 dump 用的 .vmp RVA，默认 0x1D34000')
    ap.add_argument('--runtime-vmp-rva', default=None,
                    help='运行期真实 .vmp RVA（dump_ctx.py 的 vmp_rva 字段）')
    ap.add_argument('--json', default=None)
    a = ap.parse_args()

    d = json.load(open(a.tables, encoding='utf-8'))
    tables = d.get('tables') or {}
    if not tables:
        print('[!] tables.json 里没有 tables 字段')
        return 1

    img = int(a.image_base, 16) if a.image_base else 0x140000000
    rva = int(a.vmp_rva, 16) if a.vmp_rva else 0x1D34000
    code_base = int(a.code_base, 16) if a.code_base else img + rva

    # ---- 坐标系换算 ----
    # 运行期 handler 是绝对 VA：module_base + 真实RVA
    # 静态 dump 的坐标系起点是 0x140000000 + dump_rva
    # 两者 .vmp 起点不同，必须换算，否则 handler 地址全对不上。
    rb = d.get('module_base')
    rv = d.get('vmp_rva') or a.runtime_vmp_rva
    dv = a.dump_rva
    shift = 0
    if rb and rv:
        rbase = int(str(rb), 16)
        rrva = int(str(rv), 16)
        drva = int(dv, 16) if dv else 0x1D34000
        shift = (0x140000000 + drva) - (rbase + rrva)
        print('[*] 坐标换算：运行期 .vmp = 0x%X + 0x%X，dump 坐标 = 0x140000000 + 0x%X，偏移 %+d (0x%X)'
              % (rbase, rrva, drva, shift, abs(shift)))
        print('    handler 地址将按 dump 坐标系输出（静态分析工具用这个）')
    elif a.runtime_vmp_rva:
        print('[!] 缺 module_base，换算可能不准')

    merged = {}
    per_table = []
    for slot, info in sorted(tables.items()):
        ents = info.get('entries') or []
        per_table.append((slot, info.get('table_va'), len(ents)))
        for i, v in enumerate(ents):
            merged.setdefault(i, []).append(v + shift)

    _ctx = d.get('ctx_va', '?')
    print('[*] 上下文 %s  代码区基址 0x%X'
          % (_ctx if str(_ctx).startswith('0x') else '0x' + str(_ctx), code_base))
    print('[*] 表 %d 张' % len(per_table))
    for slot, tva, n in per_table:
        print('    ctx+%-6s table %-12s %d 项' % (slot, tva, n))

    if not merged:
        print('[!] 没读到任何表项')
        return 1

    # 项数决定 opcode 宽度：>256 项基本是 16 位
    maxn = max(merged)
    bits = 8 if maxn < 256 else 16
    print('[*] 最大 opcode 0x%X -> 推断 %d 位' % (maxn, bits))

    # 同一 opcode 在多张表里不一致的情况
    conflict = {k: v for k, v in merged.items() if len(set(v)) > 1}
    alias = collections.defaultdict(list)
    for k, v in merged.items():
        alias[v[0]].append(k)
    dup = {k: v for k, v in alias.items() if len(v) > 1}

    print('[*] 合并后 opcode %d 个' % len(merged))
    print('[*] 多表冲突 %d 个%s' % (len(conflict),
          ('（取第一张表的值为准）' if conflict else '')))
    print('[*] 别名（多个 opcode 同一 handler）%d 组%s'
          % (len(dup), ('，最大一组 %d 个' % max(len(v) for v in dup.values())) if dup else ''))

    L = ['# -*- coding: utf-8 -*-',
         '"""',
         'opcode -> handler 映射，由 dump_ctx.py + merge_tables.py 生成',
         '',
         '来源：%s' % a.tables,
         '上下文：%s' % d.get('ctx_va', '?'),
         '代码区基址：0x%X' % code_base,
         'opcode 宽度：%d 位' % bits,
         '"""',
         '',
         'CODE_BASE = 0x%X' % code_base,
         '',
         'HANDLERS = {']
    for k in sorted(merged):
        v = merged[k][0]
        L.append('    0x%0*X: 0x%X,' % (4 if bits > 8 else 2, k, v))
    L += ['}', '',
          'ALIASES = {']
    for h, ops in sorted(dup.items()):
        L.append('    0x%X: [%s],' % (h, ', '.join('0x%X' % o for o in ops)))
    L += ['}', '']

    open(a.out, 'w', encoding='utf-8').write('\n'.join(L) + '\n')
    print('[+] 已生成 %s' % a.out)

    if a.json:
        json.dump({'code_base': code_base, 'bits': bits,
                   'handlers': {'0x%X' % k: '0x%X' % v[0] for k, v in merged.items()},
                   'conflicts': len(conflict), 'aliases': len(dup)},
                  open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print('[+] 已生成 %s' % a.json)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

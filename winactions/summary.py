# -*- coding: utf-8 -*-
"""summary.py —— 把 tables.json / map.json 的要点打印成人能看的样子"""
import json
import os
import sys


def show_tables(path):
    d = json.load(open(path, encoding='utf-8'))
    v = d.get('verdict') or {}
    b = d.get('best') or {}
    print('--- tables.json ---')
    print('  模块基址 : %s' % d.get('module_base'))
    print('  可执行段 : %s' % d.get('code_ranges'))
    print('  判定     : 表稳定=%s 流在动=%s 轮数=%s'
          % (v.get('tables_stable'), v.get('stream_moving'), v.get('rounds')))
    print('  最佳 ctx : %s  score=%s  来源=%s'
          % (b.get('ctx'), b.get('score'), b.get('how')))
    tabs = b.get('tables') or {}
    strs = b.get('streams') or {}
    print('  表 %d 张 / 流 %d 段' % (len(tabs), len(strs)))
    for k, t in sorted(tabs.items()):
        print('    table  %-8s va=%-14s 项数=%d'
              % (k, t.get('table_va'), len(t.get('entries') or [])))
    for k, s in sorted(strs.items()):
        print('    stream %-8s ip=%-14s 走通=%d 步/%d 字节'
              % (k, s.get('ip'), s.get('walk_steps', 0), len(s.get('b64') or '') * 3 // 4))


def show_map(path):
    m = json.load(open(path, encoding='utf-8'))
    print('--- map.json ---')
    print('  opcode 表 : %s' % m.get('opcode_table'))
    for n, t in sorted((m.get('tables') or {}).items()):
        print('    %-14s n=%-5s 变换=%-22s 解码=%-5s 唯一=%-5s 已知命中=%s'
              % (n, t.get('n'), t.get('transform'), t.get('n_decoded'),
                 t.get('n_uniq'), t.get('known_hits')))
        cands = t.get('candidates') or []
        if len(cands) > 1:
            print('      候选: %s' % (cands[:4],))
    streams = m.get('streams') or {}
    for n, s in sorted(streams.items()):
        print('    %-14s ip=%s 指令=%d' % (n, s.get('ip'), s.get('n_insn', 0)))
        dis = (s.get('disasm') or [])[:10]
        for ins in dis:
            print('        +%04x op=%03x len=%3d -> %s'
                  % (ins['off'], ins['op'], ins['len'], ins.get('h')))


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else '.'
    for name, fn in (('tables.json', show_tables), ('map.json', show_map)):
        p = name if os.path.isabs(name) else os.path.join(d, name)
        if os.path.exists(p):
            try:
                fn(p)
            except Exception as e:
                print('[!] %s 解析失败: %s' % (name, e))
        else:
            print('[!] 没有 %s' % p)
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""handler 去噪符号分析器。
模板化模式匹配（代码是机器生成的同构模板）：
  T1: mov R,rbp; add R,C; mov R,[R](/movzx)      -> R = ctx[C]
  T2: mov R,[rbp槽链] + add R,c                   -> R = IP+c
  T3: movzx R2, word/dword ptr [R]               -> R2 = mem[R]
  T4: mov [R], R2 / add [R],R2 / xor...          -> mem[R] op= R2
  T5: cmp al,[槽],imm; jbe L; add R,imm          -> 条件噪声
  T6: jmp R                                       -> 派发
按槽位角色分类输出，噪声槽的读写折叠为 [noise]。
"""
import os, re, json
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

HANDLER_DIR = '/workspace/dgwork/handlers_v82'
OUT = '/workspace/dgwork/out/sem'
MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = False
OPS = sorted([101, 197, 210, 256, 263, 297, 395, 407, 409, 418,
              424, 430, 446, 478, 508, 545, 547, 649, 80, 90])
CODE = 0x10000000

ROLES = {0xbc: 'IP', 0xf5: 'TBL', 0x6d: 'KEY', 0xa2: 'FLAG', 0x8: 'HCACHE'}
NOISE = {0xa0, 0xa4, 0x138, 0x13b, 0x140, 0x121, 0x178}


def insns(op):
    code = open(os.path.join(HANDLER_DIR, 'handler_%d.bin' % op), 'rb').read()
    return [(i.address - CODE, i.mnemonic, i.op_str, i.size)
            for i in MD.disasm(code, CODE)]


def analyze(op):
    I = insns(op)
    out, regs = [], {}
    i = 0
    # 辅助：槽名
    def slot(c):
        if c in ROLES: return ROLES[c]
        if c in NOISE: return 'N%#x' % c
        return 'S%#x' % c

    def note(s):
        out.append(s)

    while i < len(I):
        off, m, o, sz = I[i]
        seq = I[i:i + 6]
        txt = [x[1] + ' ' + x[2] for x in seq]
        # T1: mov R, rbp / add R, C / mov R,[R]
        if (m == 'mov' and o.endswith(', rbp') and len(seq) >= 3 and
                seq[1][1] == 'add' and seq[2][1] == 'mov'):
            R = o.split(',')[0].strip()
            c2s = seq[1][2].split(', ')[1]
            try:
                c = int(c2s, 0)
            except ValueError:
                # add R, rbp 形态（指针槽寻址）交由后续规则处理
                i += 1
                continue
            l3 = txt[2]
            if l3.startswith('mov ' + R + ', qword ptr [' + R) or \
               l3.startswith('mov ' + R + ', [' + R):
                regs[R] = ('ctx', c, 8)
                note('  %-6s = ctx[%s]' % (R, slot(c)))
                i += 3
                continue
            if l3.startswith('movzx') or l3.startswith('mov ' + R + 'w') or \
               l3.startswith('mov ' + R + 'd'):
                w = 2 if 'w' in l3.split(' ')[1] else 4
                regs[R] = ('ctx', c, w)
                note('  %-6s = ctx[%s] (u%d)' % (R, slot(c), w * 8))
                i += 3
                continue
            # ctx 地址寄存器：R = rbp + c（未解引用）
            regs[R] = ('addr', c)
            note('  addr(%-6s) = rbp+%#x' % (R, c))
            i += 2
            continue
        # IP 加载+偏移：R 已是 ('ctx',0xbc,8) 且 add R, c
        if m == 'add' and o.split(', ')[0] in regs:
            R, c2 = o.split(', ')
            v = regs[R]
            try:
                c2v = int(c2, 0)
            except ValueError:
                c2v = None
            if v and v[0] == 'ctx' and v[1] == 0xbc and c2v is not None:
                regs[R] = ('ip', c2v)
                note('  %-6s = IP+%#x' % (R, c2v))
                i += 1
                continue
            if v and v[0] in ('ip',) and c2v is not None:
                regs[R] = ('ip', v[1] + c2v)
                note('  %-6s = IP+%#x' % (R, regs[R][1]))
                i += 1
                continue
        # 读内存: movzx R, word ptr [R2] / mov R, [R2]
        if m in ('mov', 'movzx') and '[' in o and o.split(', ')[0] in I[i - 1][2] + ' ':
            pass
        if m in ('mov', 'movzx') and ', ' in o:
            dst, src = o.split(', ', 1)
            if src.startswith(('[', 'word ptr [', 'dword ptr [', 'byte ptr [',
                               'qword ptr [')) and dst in regs:
                sreg = re.sub(r'^(qword|dword|word|byte) ptr ', '', src).strip('[]')
                base = regs.get(sreg)
                w = 8 if 'qword' in src else 4 if 'dword' in src else \
                    2 if 'word' in src else 1
                if base and base[0] == 'ip':
                    val = None
                    regs[dst] = ('fld', base[1], w)
                    note('  %-6s = *(IP+%#x) u%d   <<< 字节码字段'
                         % (dst, base[1], w * 8))
                elif base and base[0] == 'ctx':
                    regs[dst] = ('ctx', base[1], w)
                    note('  %-6s = ctx[%s] u%d' % (dst, slot(base[1]), w * 8))
                elif base and base[0] == 'ptr':
                    regs[dst] = ('mem1', base[1], w)
                    note('  %-6s = [ctx+%s] u%d   <<< 指针槽解引用1'
                         % (dst, base[1], w * 8))
                elif base and base[0] == 'mem1':
                    regs[dst] = ('mem2', base[1], w)
                    note('  %-6s = [*%s] u%d   <<< 二级解引用'
                         % (dst, base[1], w * 8))
                elif base and base[0] == 'tblidx':
                    regs[dst] = ('tab', base[1], w)
                    note('  %-6s = table[%s] u%d   <<< 派发表读'
                         % (dst, base[1], w * 8))
                else:
                    regs[dst] = ('mem?', src, w)
                    note('  %-6s = [%s] u%d' % (dst, src, w * 8))
                i += 1
                continue
        # 算术: op R, X
        if m in ('add', 'sub', 'xor', 'or', 'and', 'shl', 'shr', 'imul',
                 'movabs', 'mov', 'cmp', 'test', 'pushfq', 'push', 'pop'):
            if m == 'pushfq':
                note('  pushfq (保存标志)')
                i += 1
                continue
            if m == 'mov' and ', ' in o and o.endswith(', rbp'):
                regs[o.split(',')[0].strip()] = ('rbp',)
                i += 1
                continue
            if m == 'mov' and ', ' in o and not o.split(', ')[1].startswith('['):
                dst, src = o.split(', ', 1)
                if src in regs:
                    regs[dst] = regs[src]
                elif src.lstrip('0x').isdigit() or re.match(r'^0x[0-9a-f]+$', src) or src.isdigit():
                    try:
                        regs[dst] = ('imm', int(src, 0))
                    except ValueError:
                        regs[dst] = ('imm?', src)
                else:
                    regs[dst] = ('reg?', src)
                # 折叠纯噪声赋值
                i += 1
                continue
            if m == 'mov' and ', ' in o and o.split(', ')[1].startswith('['):
                dst, src = o.split(', ', 1)
                sreg = re.sub(r'^(qword|dword|word|byte) ptr ', '', src).strip('[]')
                base = regs.get(sreg)
                w = 8 if 'qword' in src else 4 if 'dword' in src else \
                    2 if 'word' in src else 1
                if base and base[0] == 'ctx':
                    note('  ctx[%s] = %s (u%d)' % (slot(base[1]), dst, w * 8))
                elif base and base[0] == 'ip':
                    note('  *(IP+%#x) = %s (u%d)  <<< 写字节码'
                         % (base[1], dst, w * 8))
                elif base and base[0] == 'mem1':
                    note('  [ctx+%s] = %s (u%d)  <<< 指针槽写' % (base[1], dst, w * 8))
                else:
                    note('  [%s] = %s (u%d)' % (src, dst, w * 8))
                i += 1
                continue
            if m in ('add', 'sub', 'xor', 'or', 'and') and ', ' in o:
                dst, src = o.split(', ', 1)
                # 内存目标
                if dst.startswith('[') or ' ptr [' in dst:
                    sreg = re.sub(r'^(qword|dword|word|byte) ptr ', '', dst).strip('[]')
                    base = regs.get(sreg)
                    w = 8 if 'qword' in dst else 4 if 'dword' in dst else \
                        2 if 'word' in dst else 1
                    if base and base[0] == 'ctx':
                        c = base[1]
                        if c in NOISE:
                            i += 1
                            continue
                        note('  ctx[%s] %s= %s (u%d)' % (slot(c), m, src, w * 8))
                    elif base and base[0] == 'ip':
                        note('  *(IP+%#x) %s= %s <<< 写字节码' % (base[1], m, src))
                    elif base and base[0] == 'ptr':
                        note('  [ctx+%s] %s= %s (u%d) <<< 指针槽运算'
                             % (base[1], m, src, w * 8))
                    else:
                        note('  [%s] %s= %s' % (dst, m, src))
                    i += 1
                    continue
                # 寄存器算术：仅记录非噪声传播
                v = regs.get(src)
                i += 1
                continue
        # 指针槽成为地址：add R, rbp（指针槽值+rbp）
        if m == 'add' and o.endswith(', rbp'):
            R = o.split(',')[0].strip()
            v = regs.get(R)
            if v and v[0] == 'ctx' and v[2] == 2:
                regs[R] = ('ptr', 'S%#x' % v[1])
                note('  addr1 = rbp + u16(ctx[S%#x])   <<< 指针槽寻址' % v[1])
            i += 1
            continue
        # 二级解引用地址：add R, 4/8 后再写
        if m == 'add' and ', ' in o:
            R, c2 = o.split(', ')
            v = regs.get(R)
            if v and v[0] == 'ptr':
                regs[R] = ('ptr', v[1] + '+%s' % c2)
            i += 1
            continue
        # jmp reg
        if m == 'jmp' and not o.startswith('0x'):
            note('  jmp %s   <<< 间接跳（派发/计算跳转）' % o)
            i += 1
            continue
        if m == 'jmp':
            note('  jmp %s' % o)
            i += 1
            continue
        if m in ('ret',):
            note('  ret   <<< VM 退出')
            i += 1
            continue
        if m.startswith('j'):
            note('  %s %s' % (m, o))
            i += 1
            continue
        if m in ('push', 'pop'):
            note('  %s %s' % (m, o))
            i += 1
            continue
        i += 1
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    rep = ['# handler 去噪核心（模板化符号分析）\n']
    for op in OPS:
        lines = analyze(op)
        rep.append('\n## op %d（%d 行核心）\n' % (op, len(lines)))
        rep.extend(lines)
        with open(os.path.join(OUT, 'clean_%d.txt' % op), 'w') as f:
            f.write('\n'.join(lines) + '\n')
    with open(os.path.join(OUT, 'clean_all.md'), 'w') as f:
        f.write('\n'.join(rep) + '\n')
    print('done → out/sem/clean_all.md')


if __name__ == '__main__':
    main()

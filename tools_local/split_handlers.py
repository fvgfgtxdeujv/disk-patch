# -*- coding: utf-8 -*-
"""把每个 handler 块切成 [主体 | 内联派发器]，并对主体做语义特征提取。

派发器模板（寄存器随机，形态固定）：
    mov  A, rbp
    add  A, <IP槽>
    mov  A, [A]
    movzx B, word ptr [A]      ; opcode = *(u16*)IP
    shl  B, 3
    ...
    mov  C, [ctx+<表槽>]
    add  C, B
    mov  D, [C]
    jmp  D
"""
import json, re, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

VA = 0x1419D4000
P = open('/workspace/dgwork/unpack6201829/DiskGenius_unpacked_vmp.bin', 'rb').read()
N = len(P)
MD = Cs(CS_ARCH_X86, CS_MODE_64)


def insns(start, maxn=260):
    off = start - VA
    out = []
    for i in MD.disasm(P[off:off + 2048], start):
        out.append((i.address, i.mnemonic, i.op_str, i.size))
        if len(out) >= maxn:
            break
    return out


def split2(s):
    a, _, b = s.partition(', ')
    return a, b


def find_dispatcher(seq):
    """滑窗找 `shl REG, 3`（opcode*8），再往前定位读 opcode 与派发器起点。"""
    for i in range(len(seq) - 2):
        _, m, o, _ = seq[i]
        if m != 'shl' or not o.endswith(', 3'):
            continue
        reg = o.split(', ')[0]
        j = None
        for k in range(i - 1, max(-1, i - 6), -1):
            _, mk, ok, _ = seq[k]
            if mk in ('mov', 'movzx') and 'word ptr [' in ok and ok.split(', ')[0].rstrip('wd') == reg.rstrip('wd'):
                j = k
                break
        if j is None:
            continue
        for k in range(j - 1, max(-1, j - 9), -1):
            _, mk, ok, _ = seq[k]
            if mk == 'mov' and ok.endswith(', rbp'):
                return k
        return max(0, j - 2)
    return None


entries = json.load(open('/workspace/dgwork/handler_entries.json'))
print('入口 %d' % len(entries))

ARITH = {'add', 'sub', 'xor', 'and', 'or', 'shl', 'shr', 'sar', 'imul', 'mul', 'div',
         'idiv', 'neg', 'not', 'inc', 'dec', 'rol', 'ror', 'adc', 'sbb', 'bswap'}
MEM = {'mov', 'movzx', 'movsx', 'movsxd', 'lea'}
CTRL = {'jmp', 'je', 'jne', 'jz', 'jnz', 'ja', 'jb', 'jae', 'jbe', 'jg', 'jl', 'jge',
        'jle', 'js', 'jns', 'jo', 'jno', 'jp', 'jnp', 'call', 'ret'}

out = []
disp_ok = 0
body_stats = collections.Counter()
slot_freq = collections.Counter()

for e in entries:
    entry = int(e['entry'], 16)
    site = int(e['site'], 16)
    seq = insns(entry)
    # 截到 site
    seq = [s for s in seq if s[0] <= site]
    if not seq:
        continue
    di = find_dispatcher(seq)
    if di is None:
        body = seq[:-1]
        disp = None
    else:
        disp_ok += 1
        body = seq[:di]

    slots = set()
    ops = collections.Counter()
    for a, m, o, sz in body:
        if m in ARITH:
            ops['arith'] += 1
        if m in MEM:
            ops['mem'] += 1
        if m in CTRL:
            ops['ctrl'] += 1
        mm = re.search(r'\[r\w+ \+ (0x[0-9a-f]+)\]', o)
        for x in re.finditer(r'r\w+, (0x[0-9a-f]+)', o):
            slots.add(int(x.group(1), 16))
    # 主体里"形状"签名：算术/内存/控制流三元组的粗分类
    sig = (min(ops['arith'], 9), min(ops['mem'], 9), min(ops['ctrl'], 3))
    body_stats[sig] += 1
    for s in slots:
        if s < 0x200:
            slot_freq[s] += 1
    out.append({
        'entry': hex(entry), 'site': hex(site),
        'body_len': len(body), 'disp_at': hex(seq[di][0]) if di is not None else None,
        'arith': ops['arith'], 'mem': ops['mem'], 'ctrl': ops['ctrl'],
        'slots': sorted(hex(s) for s in slots if s < 0x200),
    })

print('派发器模板命中 %d / %d (%.1f%%)' % (disp_ok, len(entries), 100.0 * disp_ok / len(entries)))
bl = [o['body_len'] for o in out]
bl.sort()
print('主体长度: min %d  median %d  p90 %d  max %d' % (bl[0], bl[len(bl) // 2], bl[int(len(bl) * .9)], bl[-1]))
print('主体长度分布:', collections.Counter('0' if x == 0 else '1-5' if x <= 5 else '6-20' if x <= 20
                                     else '21-60' if x <= 60 else '61-200' if x <= 200 else '>200' for x in bl))
print('\n最常见 ctx 槽（主体内引用的偏移）：')
for s, c in slot_freq.most_common(20):
    print('   +0x%03X : %d' % (s, c))
print('\n形态 Top15 (arith,mem,ctrl):')
for k, c in body_stats.most_common(15):
    print('   %s : %d' % (k, c))

json.dump(out, open('/workspace/dgwork/handler_bodies.json', 'w'), indent=0)
print('\n已写 handler_bodies.json')

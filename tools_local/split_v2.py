# -*- coding: utf-8 -*-
"""用 4 个已知 IP 槽（0x70/0x73/0xBC/0x1E2）精确定位每个 handler 的内联派发器起点，
   从而把块切成 [handler 主体 | 派发器]，并统计主体里真正干活的指令。
"""
import json, re, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

VA = 0x1419D4000
P = open('/workspace/dgwork/unpack6201829/DiskGenius_unpacked_vmp.bin', 'rb').read()
N = len(P)
MD = Cs(CS_ARCH_X86, CS_MODE_64)
SLOTS = {0x70, 0x73, 0xBC, 0x1E2}

bodies = json.load(open('/workspace/dgwork/handler_bodies.json'))
# 重算，使用更宽松但更强的判据
entries = json.load(open('/workspace/dgwork/handler_entries.json'))


def insns(start, maxn=400):
    off = start - VA
    out = []
    for i in MD.disasm(P[off:off + 3072], start):
        out.append((i.address, i.mnemonic, i.op_str, i.size))
        if len(out) >= maxn:
            break
    return out


def disp_start(seq, site):
    """从 site 往前：找 shl REG,3；再往前找 mov X,rbp + add X,<IP槽>。"""
    idx = None
    for i in range(len(seq) - 1, -1, -1):
        a, m, o, _ = seq[i]
        if a > site:
            continue
        if m == 'shl' and o.endswith(', 3'):
            idx = i
            break
    if idx is None:
        return None
    reg = seq[idx][2].split(', ')[0]
    for k in range(idx - 1, max(-1, idx - 10), -1):
        a, m, o, _ = seq[k]
        if m != 'add':
            continue
        d, s = (o.split(', ') + [''])[:2]
        if not s or not re.fullmatch(r'0x[0-9a-f]+', s):
            continue
        if int(s, 16) not in SLOTS:
            continue
        # 往前找 mov d, rbp
        for j in range(k - 1, max(-1, k - 4), -1):
            a2, m2, o2, _ = seq[j]
            if m2 == 'mov' and o2 == '%s, rbp' % d:
                return j
        return k - 1
    return None


res = []
hit = 0
for e in entries:
    entry = int(e['entry'], 16)
    site = int(e['site'], 16)
    seq = insns(entry)
    seq = [s for s in seq if s[0] <= site]
    if not seq:
        continue
    d = disp_start(seq, site)
    if d is None:
        continue
    hit += 1
    body = seq[:d]
    # 有效指令：排除 mov [X+imm], 0 这类清零填充与纯常量搬运
    real = []
    for a, m, o, sz in body:
        if m == 'mov' and re.search(r'\[r\w+ \+ 0x[0-9a-f]+\], 0$', o):
            continue
        if m in ('nop', 'int3'):
            continue
        real.append((a, m, o))
    res.append({
        'entry': hex(entry), 'site': hex(site),
        'disp': hex(seq[d][0]), 'body': len(body), 'real': len(real),
        'sample': ['%s %s' % (m, o) for _, m, o in real[-8:]],
    })

res.sort(key=lambda x: x['real'])
print('定位到派发器 %d / %d (%.1f%%)' % (hit, len(entries), 100.0 * hit / len(entries)))
if res:
    bl = sorted(x['body'] for x in res)
    rl = sorted(x['real'] for x in res)
    print('主体长度 median %d  p90 %d' % (bl[len(bl) // 2], bl[int(len(bl) * .9)]))
    print('有效指令 median %d  p90 %d  max %d' % (rl[len(rl) // 2], rl[int(len(rl) * .9)], rl[-1]))
    print('\n有效指令 <=5 的样本（最可能是纯 handler）：')
    for x in res[:6]:
        print('  %s -> disp %s  body %d real %d' % (x['entry'], x['disp'], x['body'], x['real']))
        for s in x['sample']:
            print('        %s' % s)
json.dump(res, open('/workspace/dgwork/handler_split.json', 'w'), indent=0)
print('\n已写 handler_split.json')

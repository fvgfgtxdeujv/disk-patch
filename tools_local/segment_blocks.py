# -*- coding: utf-8 -*-
"""把 .vmp 线性切成「以控制流跳转结尾的直线块」，再看哪些块的块尾是 IP 站点。
   假设：物理流连续，块首 = 上一块尾的下一条指令；真 handler 的块尾必是 IP 站点。
"""
import json, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

VA = 0x1419D4000
P = open('/workspace/dgwork/unpack6201829/DiskGenius_unpacked_vmp.bin', 'rb').read()
N = len(P)
MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.skipdata = True

sites = {int(s['at'], 16) for s in json.load(open('/workspace/dgwork/ipslots_new.json'))['sites']}

TERM = {'jmp', 'ret', 'retf', 'hlt', 'ud2', 'int3'}
blocks = []            # (start, end_insn_addr, term_mnemonic, n_insn)
cur_start = None
cur_n = 0
off = 0
junk_runs = 0
last_was_junk = False

import time
t0 = time.time()
for i in MD.disasm_lite(P, VA):
    addr, size, mn, op = i
    if mn == '.byte':
        if cur_start is not None:
            blocks.append((cur_start, addr, '.byte', cur_n))
            cur_start = None
        off = addr - VA + size
        last_was_junk = True
        continue
    if cur_start is None:
        cur_start = addr
        cur_n = 0
    cur_n += 1
    if mn in TERM:
        blocks.append((cur_start, addr, mn, cur_n))
        cur_start = None
    elif mn == 'call':
        # call 不结束块（handler 内可调 helper），但记录
        pass

print('线性切块 %d 段，耗时 %.1fs' % (len(blocks), time.time() - t0))

site_blocks = [b for b in blocks if b[1] in sites]
print('块尾落在 IP 站点的块：%d / 站点 %d' % (len(site_blocks), len(sites)))

lens = collections.Counter()
for b in site_blocks:
    L = b[3]
    if L <= 5: lens['1-5'] += 1
    elif L <= 20: lens['6-20'] += 1
    elif L <= 60: lens['21-60'] += 1
    elif L <= 200: lens['61-200'] += 1
    else: lens['>200'] += 1
print('真 handler 块长分布：', dict(lens))
print('term 分布：', collections.Counter(b[2] for b in site_blocks))

print('\n前 8 个真 handler 块：')
for b in site_blocks[:8]:
    print('  %#x .. %#x  %d 条  end=%s' % (b[0], b[1], b[3], b[2]))

# 覆盖率：所有站点里有多少被"某个块尾"命中
hit = {b[1] for b in site_blocks}
print('\n站点覆盖率 %.1f%%' % (100.0 * len(hit) / len(sites)))

# 块首集合规模
starts = {b[0] for b in site_blocks}
print('真 handler 块首去重 %d' % len(starts))

json.dump([{'start': hex(b[0]), 'end': hex(b[1]), 'n': b[3]} for b in site_blocks],
          open('/workspace/dgwork/handler_blocks.json', 'w'), indent=0)
print('已写 handler_blocks.json')

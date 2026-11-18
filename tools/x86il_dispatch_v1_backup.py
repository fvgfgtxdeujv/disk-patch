#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================
 x86il_dispatch.py —— VM dispatch 恢复（handler 发现）
================================================================
不依赖固定字节模式，按语义恢复 opcode -> handler 映射。支持五种派发形态：

  1. cmp 链           movzx eax,[IP]; cmp al,0x2C; je h2C; cmp al,0x2D; je h2D
  2. 递减测试链       sub eax,0x10; jz h10; dec eax; jz h11; dec eax; jz h12
  3. 变换链           xor eax,0x5A; cmp eax,0x4A; je h10   （opcode 被混淆过）
  4. 二分派发         cmp eax,0x40; ja hi; cmp eax,0x20; jbe lo ...
  5. 跳表             jmp qword ptr [rax*8+table]  /  jmp dword ptr [rax*4+table]

附带：
  - 选择子（selector）自动跟踪，多种寄存器宽度（al/cl/r12b/eax/r10d）
  - switch 形态 cmp; jne next; jmp handler
  - opcode 别名标注（多个 opcode 指向同一 handler）
  - 候选 handler 打分（看是否访问 VM 上下文、是否以 jmp 收尾）
  - 与 x86il_deobf_v2.py 自动对接：同目录存在时 v2 的 --scan/--batch 直接使用

用法
----
  python3 x86il_dispatch.py payload.bin
  python3 x86il_dispatch.py payload.bin --json map.json --emit handlers.py
  python3 x86il_dispatch.py --selftest          # 自检（5 种形态 + 精度）
  python3 x86il_dispatch.py payload.bin --verbose --code-base 0x141D34000
"""
import sys, re, os, json, struct, argparse, collections

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM, X86_REG_RIP, X86_REG_EIP

REG64 = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp'] + ['r%d' % i for i in range(8, 16)]
_SUB = {}
for _f, _ps in [('rax', ['eax', 'ax', 'al', 'ah']), ('rbx', ['ebx', 'bx', 'bl', 'bh']),
                ('rcx', ['ecx', 'cx', 'cl', 'ch']), ('rdx', ['edx', 'dx', 'dl', 'dh']),
                ('rsi', ['esi', 'si', 'sil']), ('rdi', ['edi', 'di', 'dil']),
                ('rbp', ['ebp', 'bp', 'bpl']), ('rsp', ['esp', 'sp', 'spl'])]:
    for _p in _ps:
        _SUB[_p] = _f
for _i in range(8, 16):
    for _s in ('d', 'w', 'b'):
        _SUB['r%d%s' % (_i, _s)] = 'r%d' % _i

_W8 = set('al bl cl dl ah bh ch dh sil dil bpl spl'.split()) | set('r%db' % i for i in range(8, 16))
_W16 = set('ax bx cx dx si di bp sp'.split()) | set('r%dw' % i for i in range(8, 16))
_W32 = set('eax ebx ecx edx esi edi ebp esp'.split()) | set('r%dd' % i for i in range(8, 16))


def reg_width(n):
    if n in _W8:
        return 8
    if n in _W16:
        return 16
    if n in _W32:
        return 32
    return 64


def canon(n):
    return _SUB.get(n, n)


IMG_VA = 0x140000000
VMP_RVA = 0x1D34000
CODE_BASE_VA = IMG_VA + VMP_RVA

# 无条件/条件跳转分类
JC = {
    'je': 'e', 'jz': 'e', 'jne': 'ne', 'jnz': 'ne',
    'ja': 'a', 'jnbe': 'a', 'jae': 'ae', 'jnb': 'ae', 'jnc': 'ae',
    'jb': 'b', 'jc': 'b', 'jnae': 'b', 'jbe': 'be', 'jna': 'be',
    'jg': 'g', 'jnle': 'g', 'jge': 'ge', 'jnl': 'ge',
    'jl': 'l', 'jnge': 'l', 'jle': 'le', 'jng': 'le',
    'jo': 'o', 'jno': 'no', 'js': 's', 'jns': 'ns',
    'jp': 'p', 'jpe': 'p', 'jnp': 'np', 'jpo': 'np',
}
UPPER = {'a', 'ae', 'g', 'ge'}      # jcc 后「值更大」的一侧
LOWER = {'b', 'be', 'l', 'le'}      # jcc 后「值更小」的一侧


class Ins:
    __slots__ = ('addr', 'size', 'mn', 'ostr', 'ops', 'bytes')

    def __init__(self, i):
        self.addr = i.address
        self.size = i.size
        self.mn = i.mnemonic
        self.ostr = i.op_str
        self.bytes = bytes(i.bytes)
        try:
            self.ops = i.operands          # 仅 detail 模式下可用
        except Exception:
            self.ops = None


def make_md(detail=False):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = detail
    return md


class Scanner:
    """dispatch 恢复器"""

    def __init__(self, payload, code_base=CODE_BASE_VA, max_insn=3_000_000,
                 block_limit=400, verbose=False):
        self.p = payload
        self.base = code_base
        self.md_fast = make_md(False)
        self.md_det = make_md(True)
        self.max_insn = max_insn
        self.block_limit = block_limit
        self.verbose = verbose
        self.n_insn = 0
        self.entries = []          # dict(opcode, target, via, sel, at, masked, note)
        self.tables = []           # 跳表
        self.unresolved = []
        self._det_cache = {}

    # ---------- 取带操作数的指令 ----------
    def det(self, i):
        k = (i.addr, i.bytes)
        if k in self._det_cache:
            return self._det_cache[k]
        d = None
        for x in self.md_det.disasm(i.bytes, i.addr):
            d = Ins(x)
            break
        if len(self._det_cache) < 200000:
            self._det_cache[k] = d
        return d

    def emit(self, opcode, target_va, via, sel, at, masked=None, note=''):
        if not (self.base <= target_va < self.base + len(self.p)):
            self.unresolved.append({'opcode': opcode, 'via': via, 'at': at,
                                    'reason': 'target 0x%X 不在载荷内' % target_va})
            return
        self.entries.append({'opcode': opcode, 'target': target_va - self.base,
                             'va': target_va, 'via': via, 'sel': sel,
                             'at': at, 'masked': masked, 'note': note,
                             'blk': self._blk})

    # ---------- 单块扫描 ----------
    def scan_block(self, start_va, sel=None, lo=0, hi=0xFF, acc=0, xf=None, depth=0):
        """
        从 start_va 起顺序解释，直到块结束。
        状态: sel 选择子寄存器 / [lo,hi] 取值区间 / acc 已累积偏移 / xf opcode 变换
        """
        if depth > 24:
            return
        addr = start_va
        self._blk = start_va
        last_imm = None
        n = 0
        while n < self.block_limit:
            n += 1
            off = addr - self.base
            if off < 0 or off >= len(self.p):
                return
            raw = None
            for x in self.md_fast.disasm(self.p[off:off + 16], addr):
                raw = Ins(x)
                break
            if raw is None:
                return
            self.n_insn += 1
            if self.n_insn > self.max_insn:
                return
            m = raw.mn
            nxt = addr + raw.size

            # ---- 选择子写入 ----
            if m in ('movzx', 'movsx', 'mov', 'movsxd') or (m == 'and' and sel is None):
                d = self.det(raw)
                if d and d.ops and d.ops[0].type == X86_OP_REG and len(d.ops) == 2 \
                        and d.ops[1].type == X86_OP_MEM \
                        and reg_width(self.md_det.reg_name(d.ops[0].reg)) <= 32:
                    newsel = canon(self.md_det.reg_name(d.ops[0].reg))
                    # 读的是内存（VM 上下文里的 opcode 字节）
                    if newsel != sel:
                        sel, lo, hi, acc, xf = newsel, 0, 0xFF, 0, None
                    last_imm = None
                    addr = nxt
                    continue

            if m in ('cmp', 'test', 'sub', 'add', 'xor', 'or', 'and',
                     'dec', 'inc', 'imul', 'lea') and sel is not None:
                d = self.det(raw)
                if d and d.ops and d.ops[0].type == X86_OP_REG \
                        and canon(self.md_det.reg_name(d.ops[0].reg)) == sel:
                    if m == 'cmp' and len(d.ops) == 2 and d.ops[1].type == X86_OP_IMM:
                        last_imm = d.ops[1].imm & 0xFFFFFFFFFFFFFFFF
                    elif m == 'test':
                        last_imm = 0          # test sel,sel 等价 cmp sel,0
                    elif m == 'sub' and d.ops[1].type == X86_OP_IMM:
                        acc += d.ops[1].imm
                        last_imm = None
                    elif m == 'add' and d.ops[1].type == X86_OP_IMM:
                        acc -= d.ops[1].imm
                        last_imm = None
                    elif m == 'xor' and d.ops[1].type == X86_OP_IMM:
                        xf = ('xor', d.ops[1].imm & 0xFFFFFFFFFFFFFFFF)
                        last_imm = None
                    elif m == 'and' and d.ops[1].type == X86_OP_IMM:
                        xf = ('and', d.ops[1].imm & 0xFFFFFFFFFFFFFFFF)
                        lo, hi = 0, d.ops[1].imm & ((1 << reg_width(sel)) - 1)
                        last_imm = None
                    elif m == 'dec':
                        acc += 1
                        last_imm = None
                    elif m == 'inc':
                        acc -= 1
                        last_imm = None
                    else:
                        last_imm = None
                    addr = nxt
                    continue

            # ---- 条件跳转 ----
            if m in JC:
                d = self.det(raw)
                if not d or not d.ops or d.ops[0].type != X86_OP_IMM:
                    return
                tgt = d.ops[0].imm & 0xFFFFFFFFFFFFFFFF
                cond = JC[m]
                imm = last_imm
                last_imm = None

                if cond == 'e':
                    # jz 命中单一值：
                    #   cmp sel,imm; jz  -> opcode = imm
                    #   sub/dec sel,imm; jz -> opcode = 累计偏移
                    v = acc + (imm if imm is not None else 0)
                    via = 'cmp-je' if imm is not None else 'dec-chain'
                    self.emit(self.trans(v, xf), tgt, via, sel, addr)
                    addr = nxt
                    continue

                if cond == 'ne':
                    # 取反分支：目标继续比较，fallthrough 命中 imm
                    if imm is not None:
                        self.emit(self.trans(acc + imm, xf), nxt, 'cmp-jne', sel, addr)
                    self._push(tgt, sel, lo, hi, acc, xf, depth)
                    return

                if cond in UPPER:
                    # ja/jae: 取反侧 [lo, imm]，命中侧 [imm+1, hi]
                    edge = imm if imm is not None else lo
                    if cond == 'a':
                        lo_t, hi_t = edge + 1, hi
                        hi = edge
                    else:
                        lo_t, hi_t = edge, hi
                        hi = edge - 1
                    self._push(tgt, sel, lo_t, hi_t, acc, xf, depth)
                    addr = nxt
                    continue

                if cond in LOWER:
                    edge = imm if imm is not None else lo
                    if cond == 'b':
                        lo_t, hi_t = lo, edge - 1
                        lo = edge
                    else:
                        lo_t, hi_t = lo, edge
                        lo = edge + 1
                    self._push(tgt, sel, lo_t, hi_t, acc, xf, depth)
                    addr = nxt
                    continue

                # 其它条件（jo/js/jp）不参与派发
                addr = nxt
                continue

            # ---- 无条件跳转 ----
            if m == 'jmp':
                d = self.det(raw)
                if not d or not d.ops:
                    return
                if d.ops[0].type == X86_OP_IMM:
                    tgt = d.ops[0].imm & 0xFFFFFFFFFFFFFFFF
                    if lo == hi:
                        # 区间收敛到单值 -> 该值就是 opcode，target 是 handler
                        self.emit(self.trans(acc + lo, xf), tgt, 'interval-jmp', sel, addr)
                        return
                    # 未收敛：视为派发链的下一段起点
                    self._push(tgt, sel, lo, hi, acc, xf, depth)
                    return
                # 寄存器/内存间接跳转 -> 跳表
                if d.ops[0].type == X86_OP_MEM:
                    self.handle_jumptable(d, sel, acc, xf, addr)
                else:
                    self.unresolved.append({'opcode': None, 'via': 'jmp-reg', 'at': addr,
                                            'reason': '间接跳转 %s %s' % (m, raw.ostr)})
                return

            if m in ('ret', 'retn', 'int3', 'ud2', 'hlt'):
                return

            addr = nxt
            if self.n_insn > self.max_insn:
                return

    def _push(self, va, sel, lo, hi, acc, xf, depth):
        if lo > hi:
            return
        key = (va, lo, hi)
        if key in self._seen:
            return
        self._seen.add(key)
        self._work.append((va, sel, lo, hi, acc, xf, depth + 1))

    @staticmethod
    def trans(v, xf):
        if xf is None:
            return v & 0xFFFFFFFFFFFFFFFF
        op, k = xf
        if op == 'xor':
            return (v ^ k) & 0xFFFFFFFFFFFFFFFF
        if op == 'and':
            return None                     # and 不可逆：原值不唯一
        return v

    # ---------- 跳表 ----------
    def handle_jumptable(self, d, sel, acc, xf, at):
        o = d.ops[0]
        if o.mem.base in (X86_REG_RIP, X86_REG_EIP):
            tva = d.addr + d.size + o.mem.disp
        elif o.mem.base == 0:
            tva = o.mem.disp & 0xFFFFFFFFFFFFFFFF
        else:
            # jmp [reg*8 + disp] —— base 是指针寄存器里的表地址，载荷内无法静态定
            self.unresolved.append({'opcode': None, 'via': 'jump-table', 'at': at,
                                    'reason': '跳表基址在寄存器中: %s' % d.ostr})
            return
        size = o.size                     # 表项宽度（字节）
        if size not in (4, 8):
            self.unresolved.append({'opcode': None, 'via': 'jump-table', 'at': at,
                                    'reason': '表项宽度 %d' % size})
            return
        toff = tva - self.base
        if toff < 0 or toff >= len(self.p):
            self.unresolved.append({'opcode': None, 'via': 'jump-table', 'at': at,
                                    'reason': '表 0x%X 不在载荷内' % tva})
            return
        n = (len(self.p) - toff) // size
        found = 0
        for k in range(min(n, 256)):
            raw = self.p[toff + k * size: toff + (k + 1) * size]
            if len(raw) < size:
                break
            if size == 8:
                v = struct.unpack('<Q', raw)[0]
                tgt = v
            else:
                v = struct.unpack('<i', raw)[0]
                tgt = (tva + v) & 0xFFFFFFFFFFFFFFFF
            if tgt == 0:
                break
            if not (self.base <= tgt < self.base + len(self.p)):
                break
            self.emit(self.trans(acc + k, xf), tgt, 'jump-table', sel, at + k)
            found += 1
        self.tables.append({'at': at, 'table_va': tva, 'entry_size': size,
                            'entries': found, 'expr': d.ostr})

    # ---------- 入口 ----------
    def run(self, seeds=None):
        self._seen = set()
        self._work = collections.deque()
        if seeds:
            for s in seeds:
                self._push(s, None, 0, 0xFF, 0, None, 0)
        else:
            self.linear_seed()
        while self._work:
            va, sel, lo, hi, acc, xf, depth = self._work.popleft()
            self.scan_block(va, sel, lo, hi, acc, xf, depth)
        return self.result()

    def linear_seed(self):
        """先线性扫一遍：凡是写选择子 + 后续比较的位置都作为块起点"""
        off = 0
        n = 0
        while off < len(self.p):
            raw = None
            for x in self.md_fast.disasm(self.p[off:off + 16], self.base + off):
                raw = Ins(x)
                break
            if raw is None:
                off += 1
                continue
            n += 1
            if n > self.max_insn:
                return
            if raw.mn in ('movzx', 'movsx', 'mov', 'movsxd'):
                d = self.det(raw)
                if d and len(d.ops) == 2 and d.ops[0].type == X86_OP_REG \
                        and d.ops[1].type == X86_OP_MEM \
                        and reg_width(self.md_det.reg_name(d.ops[0].reg)) <= 32:
                    # 只把「读内存取选择子」当种子
                    self._push(self.base + off, None, 0, 0xFF, 0, None, 0)
            off += raw.size

    def result(self):
        # 同一 opcode 可能命中多处，按目标聚合
        handlers = collections.OrderedDict()
        for e in sorted(self.entries, key=lambda x: (x['opcode'] is None, x['opcode'] or 0)):
            op = e['opcode']
            handlers.setdefault(op, []).append(e)
        return {
            'entries': self.entries,
            'handlers': handlers,
            'tables': self.tables,
            'unresolved': self.unresolved,
            'stats': {'instructions': self.n_insn,
                      'entries': len(self.entries),
                      'opcodes': len([k for k in handlers if k is not None]),
                      'blocks': len(self._seen)},
        }


# ============================================================
# handler 打分
# ============================================================
def score_handler(payload, off, code_base=CODE_BASE_VA, look=24):
    """看目标像不像 handler：访问 VM 上下文 + 以 jmp 收尾"""
    md = make_md(True)
    s = 0
    n = 0
    accessed_ctx = 0
    ends_jmp = 0
    for i in md.disasm(payload[off:off + 200], code_base + off):
        n += 1
        if n > look:
            break
        if i.mnemonic == 'jmp':
            ends_jmp = 1
            break
        if i.mnemonic in ('ret', 'int3'):
            break
        for o in i.operands:
            if o.type == X86_OP_MEM and o.mem.base:
                bn = md.reg_name(o.mem.base)
                if canon(bn) == 'rbp':
                    accessed_ctx += 1
    s += min(accessed_ctx, 4)
    s += 3 if ends_jmp else 0
    if 3 <= n <= 40:
        s += 1
    return s, n, accessed_ctx, ends_jmp


def discover(payload, code_base=CODE_BASE_VA, verbose=False, min_cases=1):
    sc = Scanner(payload, code_base, verbose=verbose)
    r = sc.run()
    # 每个派发块的分支数：真派发块通常 >= 2 个分支，孤立 cmp/je 多为普通逻辑
    cnt = collections.Counter(e['blk'] for e in r['entries'])
    for e in r['entries']:
        e['block_cases'] = cnt[e['blk']]
    r['block_cases'] = dict(cnt)
    r['min_cases'] = min_cases
    # 打分
    scored = collections.OrderedDict()
    for op, lst in r['handlers'].items():
        best = None
        for e in lst:
            if e.get('block_cases', 1) < min_cases:
                continue
            sc_, n_, ctx_, j_ = score_handler(payload, e['target'], code_base)
            e2 = dict(e)
            e2['score'] = sc_
            e2['insns'] = n_
            e2['ctx_refs'] = ctx_
            e2['ends_jmp'] = j_
            if best is None or e2['score'] > best['score'] or \
                    (e2['score'] == best['score'] and
                     e2.get('block_cases', 1) > best.get('block_cases', 1)):
                best = e2
        if best is None:
            continue
        scored[op] = {'best': best, 'all': lst}
    r['scored'] = scored
    return r


# ============================================================
# 兼容层：给 x86il_deobf_v2.py 用
# ============================================================
def discover_handlers_compat(payload, code_base=CODE_BASE_VA, verbose=False):
    """返回 x86il_deobf_v2 需要的 {opcode: [(offset, count), ...]}"""
    r = discover(payload, code_base, verbose)
    out = {}
    for op, d in r['scored'].items():
        if op is None:
            continue
        cnt = collections.Counter()
        for e in d['all']:
            cnt[e['target']] += 1
        best = d['best']
        items = sorted(cnt.items(), key=lambda x: (-x[1], x[0]))
        if best and best['target'] in cnt:
            items = [(best['target'], cnt.pop(best['target']))] + \
                    sorted(cnt.items(), key=lambda x: (-x[1], x[0]))
        out[op] = items
    return out


# ============================================================
# 报告
# ============================================================
def report(r, verbose=False):
    st = r['stats']
    print("[*] 处理指令 %d 条，块状态 %d 个，命中 opcode %d 个，条目 %d 条"
          % (st['instructions'], st['blocks'], st['opcodes'], st['entries']))

    unknown = [e for e in r['entries'] if e['opcode'] is None]
    if verbose and r['tables']:
        print("\n[跳表]")
        for t in r['tables']:
            print("   @0x%-8X 表 0x%-10X %d 字节/项  解析 %d 项  (%s)"
                  % (t['at'], t['table_va'], t['entry_size'], t['entries'], t['expr']))

    print("\n[opcode -> handler]")
    print("   %-6s %-10s %-6s %-5s %-12s %s" % ('op', 'handler', 'score', 'insn', 'via', '备注'))
    print("   " + "-" * 66)
    alias = collections.defaultdict(list)
    for op, d in sorted(r['scored'].items(), key=lambda x: (x[0] is None, x[0] or 0)):
        b = d['best']
        alias[b['target']].append(op)
        name = '0x%02X' % op if op is not None else '??'
        note = b.get('note') or ''
        if b['masked'] is not None and op is None:
            note = 'masked=0x%X' % b['masked']
        print("   %-6s 0x%-8X %-6d %-5d %-12s %s"
              % (name, b['target'], b['score'], b['insns'], b['via'], note))

    dup = {k: v for k, v in alias.items() if len(v) > 1 and all(x is not None for x in v)}
    if dup:
        print("\n[别名] 多个 opcode 指向同一 handler")
        for tgt, ops in dup.items():
            print("   0x%-8X <- %s" % (tgt, ', '.join('0x%02X' % o for o in ops)))

    if r['unresolved']:
        print("\n[未解析] %d 条" % len(r['unresolved']))
        if verbose:
            c = collections.Counter(u['reason'].split(':')[0] for u in r['unresolved'])
            for k, v in c.most_common(10):
                print("   %-40s %d" % (k, v))

    if unknown:
        print("\n[opcode 未确定] %d 条（opcode 被 and 掩码，原值不唯一）" % len(unknown))


def emit_python(r, path, code_base):
    L = ['# -*- coding: utf-8 -*-',
         '"""opcode -> handler 映射，由 x86il_dispatch.py 生成"""',
         '', 'CODE_BASE = 0x%X' % code_base, '',
         'HANDLERS = {']
    for op, d in sorted(r['scored'].items(), key=lambda x: (x[0] is None, x[0] or 0)):
        if op is None:
            continue
        b = d['best']
        L.append('    0x%02X: {"handler": 0x%X, "score": %d, "via": %r},'
                 % (op, b['target'], b['score'], b['via']))
    L += ['}', '',
          'ALIASES = {']
    alias = collections.defaultdict(list)
    for op, d in r['scored'].items():
        if op is not None:
            alias[d['best']['target']].append(op)
    for tgt, ops in sorted(alias.items()):
        if len(ops) > 1:
            L.append('    0x%X: [%s],' % (tgt, ', '.join('0x%02X' % o for o in ops)))
    L += ['}', '']
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(L) + '\n')
    print("[+] 已生成 %s" % path)


# ============================================================
# 自检：五种派发形态 + 精度
# ============================================================
def _build(asm_src, code_base=CODE_BASE_VA, link=True):
    import subprocess, tempfile
    with tempfile.TemporaryDirectory() as d:
        sp = os.path.join(d, 'a.s'); op = os.path.join(d, 'a.o')
        ep = os.path.join(d, 'a.elf'); bp = os.path.join(d, 'a.bin')
        with open(sp, 'w') as f:
            f.write(".intel_syntax noprefix\n.globl _start\n_start:\n" + asm_src + "\n")
        subprocess.run(['as', '--64', '-o', op, sp], check=True)
        if link:
            r = subprocess.run(['ld', '-Ttext=0x%X' % code_base, '-e', '0', '-o', ep, op],
                               capture_output=True, text=True)
            if r.returncode != 0:
                with open(sp) as _f:
                    _src = _f.read()
                raise RuntimeError('ld 失败:\n%s\n--- 源码 ---\n%s' % (r.stderr, _src))
            subprocess.run(['objcopy', '-O', 'binary', '--only-section=.text', ep, bp], check=True)
        else:
            subprocess.run(['objcopy', '-O', 'binary', '--only-section=.text', op, bp], check=True)
        with open(bp, 'rb') as f:
            return f.read()


def _labels_offsets(asm_src, names, code_base=CODE_BASE_VA):
    """用 nm 风格的偏移：在生成的 bin 里按顺序定位标签不方便，这里用固定 nop 填充对齐"""
    return None


def selftest(verbose=True):
    ok = 0; fail = 0

    def check(name, cond, extra=''):
        nonlocal ok, fail
        if cond:
            ok += 1
            print("   [PASS] %-34s %s" % (name, extra))
        else:
            fail += 1
            print("   [FAIL] %-34s %s" % (name, extra))

    # 每个 handler 用固定 16 字节 nop 填充，便于用「标签序号」算偏移
    def mk(cases, tail='jmp vm_exit'):
        """cases: [(opcode_or_expr, body)]，返回汇编 + 每个 handler 的标签名"""
        src = []
        for k, (_, body) in enumerate(cases):
            src.append("h%d:" % k)
            src.append("    " + body.replace("\n", "\n    "))
            src.append("    " + tail)
            src.append("    .balign 16, 0x90")
        return "\n".join(src)

    print("[*] x86il_dispatch 自检")

    # ---------- 1. cmp 链（不同选择子宽度） ----------
    body = ("mov rax, [rbp+0x92]\n"
            "movzx ecx, byte ptr [rax]\n"
            "cmp cl, 0x10\n je h0\n"
            "cmp cl, 0x11\n je h1\n"
            "cmp cl, 0x12\n je h2\n"
            "jmp vm_exit\n")
    handlers = ("mov rax, [rbp+0x0]\n mov [rbp+0x10], rax",
                "mov rax, [rbp+0x8]\n mov [rbp+0x10], rax",
                "mov rax, [rbp+0x0]\n add rax, rcx\n mov [rbp+0x10], rax")
    src = body + mk([(None, h) for h in handlers]) + "\nvm_exit:\n    ret\n"
    payload = _build(src)
    r = discover(payload)
    ops = sorted(k for k in r['scored'] if k is not None)
    check("cmp 链 (cl)", ops == [0x10, 0x11, 0x12], str(['0x%02X' % o for o in ops]))

    # ---------- 2. 递减测试链 ----------
    body = ("mov rax, [rbp+0x92]\n"
            "movzx eax, byte ptr [rax]\n"
            "sub eax, 0x10\n jz h0\n"
            "dec eax\n jz h1\n"
            "dec eax\n jz h2\n"
            "jmp vm_exit\n")
    src = body + mk([(None, h) for h in handlers]) + "\nvm_exit:\n    ret\n"
    r = discover(_build(src))
    ops = sorted(k for k in r['scored'] if k is not None)
    check("递减测试链 (sub/dec)", ops == [0x10, 0x11, 0x12], str(['0x%02X' % o for o in ops]))

    # ---------- 3. opcode 变换（xor） ----------
    body = ("mov rax, [rbp+0x92]\n"
            "movzx eax, byte ptr [rax]\n"
            "xor eax, 0x5A\n"
            "cmp eax, 0x4A\n je h0\n"     # 0x4A ^ 0x5A = 0x10
            "cmp eax, 0x4B\n je h1\n"     # 0x4B ^ 0x5A = 0x11
            "jmp vm_exit\n")
    src = body + mk([(None, h) for h in handlers]) + "\nvm_exit:\n    ret\n"
    r = discover(_build(src))
    ops = sorted(k for k in r['scored'] if k is not None)
    check("opcode 变换 (xor 0x5A)", ops == [0x10, 0x11], str(['0x%02X' % o for o in ops]))

    # ---------- 4. switch 形态 cmp; jne next; jmp handler ----------
    body = ("mov rax, [rbp+0x92]\n"
            "movzx eax, byte ptr [rax]\n"
            "cmp al, 0x20\n jne 1f\n jmp h0\n"
            "1: cmp al, 0x21\n jne 2f\n jmp h1\n"
            "2: jmp vm_exit\n")
    src = body + mk([(None, h) for h in handlers]) + "\nvm_exit:\n    ret\n"
    r = discover(_build(src))
    ops = sorted(k for k in r['scored'] if k is not None)
    check("switch (jne + jmp)", ops == [0x20, 0x21], str(['0x%02X' % o for o in ops]))

    # ---------- 5. 跳表 ----------
    body = ("mov rax, [rbp+0x92]\n"
            "movzx eax, byte ptr [rax]\n"
            "jmp qword ptr [rax*8 + table]\n")
    table = "table:\n    .quad h0, h1, h2\n    .quad 0\n"
    src = body + mk([(None, h) for h in handlers]) + "\n" + table + "\nvm_exit:\n    ret\n"
    # 跳表的 32 位位移要求代码基址落在 2GB 内，单独用 0x400000 构建
    r = discover(_build(src, code_base=0x400000), 0x400000)
    ops = sorted(k for k in r['scored'] if k is not None)
    check("跳表 (qword)", ops == [0x00, 0x01, 0x02], str(['0x%02X' % o for o in ops]))

    # ---------- 6. 二分派发 ----------
    body = ("mov rax, [rbp+0x92]\n"
            "movzx eax, byte ptr [rax]\n"
            "cmp al, 0x81\n jae 9f\n"
            "cmp al, 0x40\n jae 5f\n"
            "cmp al, 0x20\n jae 3f\n"
            "jmp vm_exit\n"
            "3: cmp al, 0x20\n je h0\n jmp vm_exit\n"
            "5: cmp al, 0x40\n je h1\n jmp vm_exit\n"
            "9: jmp vm_exit\n")
    src = body + mk([(None, h) for h in handlers]) + "\nvm_exit:\n    ret\n"
    r = discover(_build(src))
    ops = sorted(k for k in r['scored'] if k is not None)
    check("二分派发 (ja/jae)", ops == [0x20, 0x40], str(['0x%02X' % o for o in ops]))

    # ---------- 7. 别名 ----------
    body = ("mov rax, [rbp+0x92]\n"
            "movzx eax, byte ptr [rax]\n"
            "cmp al, 0x30\n je h0\n"
            "cmp al, 0x31\n je h0\n"
            "jmp vm_exit\n")
    src = body + mk([(None, handlers[0])]) + "\nvm_exit:\n    ret\n"
    r = discover(_build(src))
    alias = {}
    for op, d in r['scored'].items():
        if op is not None:
            alias.setdefault(d['best']['target'], []).append(op)
    has_alias = any(len(v) > 1 for v in alias.values())
    check("opcode 别名", has_alias, str({hex(k): [hex(x) for x in v] for k, v in alias.items()}))

    # ---------- 8. 精度：普通函数里的 cmp/je 不应被当成 dispatcher ----------
    src = ("fn:\n"
           "    mov rax, [rdi+0x8]\n"      # 读的是普通结构体，用 rdi 做基址
           "    cmp rax, 0x5\n je fn2\n"
           "    cmp rax, 0x6\n je fn3\n"
           "    ret\n"
           "fn2:\n    ret\n"
           "fn3:\n    ret\n")
    r = discover(_build(src))
    ops = [k for k in r['scored'] if k is not None]
    check("精度：非 VM 比较不误报", len(ops) == 0, str(['0x%02X' % o for o in ops]))

    print("\n[*] 结果: %d passed, %d failed" % (ok, fail))
    return fail == 0


# ============================================================
# CLI
# ============================================================
def main():
    ap = argparse.ArgumentParser(
        description='VM dispatch 恢复（handler 发现）',
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument('payload', nargs='?')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--json', metavar='FILE')
    ap.add_argument('--emit', metavar='FILE')
    ap.add_argument('--code-base', metavar='HEX', default=None)
    ap.add_argument('--image-base', metavar='HEX', default=None)
    ap.add_argument('--vmp-rva', metavar='HEX', default=None)
    ap.add_argument('--max-insn', type=int, default=3_000_000)
    ap.add_argument('--verbose', '-v', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        sys.exit(0 if selftest() else 1)
    if not args.payload:
        ap.print_help()
        return

    global CODE_BASE_VA
    ib = int(args.image_base, 16) if args.image_base else IMG_VA
    vr = int(args.vmp_rva, 16) if args.vmp_rva else VMP_RVA
    cb = int(args.code_base, 16) if args.code_base else (ib + vr)
    CODE_BASE_VA = cb

    with open(args.payload, 'rb') as f:
        payload = f.read()
    print("[*] 载荷 %s  %.1f MB  代码基址 0x%X"
          % (args.payload, len(payload) / 1048576, cb))

    r = discover(payload, cb, verbose=args.verbose)
    report(r, args.verbose)

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump({'code_base': cb,
                       'handlers': {('0x%02X' % op if op is not None else '?'):
                                    d['best'] for op, d in r['scored'].items()},
                       'tables': r['tables'], 'stats': r['stats']},
                      f, ensure_ascii=False, indent=2, default=str)
        print("[+] 已生成 %s" % args.json)
    if args.emit:
        emit_python(r, args.emit, cb)


if __name__ == '__main__':
    main()

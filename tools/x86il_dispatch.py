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
  - 选择子（selector）自动跟踪，支持 8/16/32 位宽度（al/cl/r12b/eax/r10d/r13w）
  - switch 形态 cmp; jne next; jmp handler（要求落空侧紧跟一条 jmp）
  - opcode 别名标注（多个 opcode 指向同一 handler）
  - 候选 handler 打分（看是否访问 VM 上下文、是否以 jmp 收尾）
  - 与 x86il_deobf_v2.py 自动对接：v2 的 --scan/--batch 默认走这里

v1.1 性能与精度（详见 REPORT_dispatch_v2.md）
  - 种子改为「派发核正则预筛 -> 聚类 -> 回溯选择子装载」，不再逐字节回退
  - 热路径用 disasm_lite + 字符串解析，不做 detail 反汇编
  - 4MB 混合载荷 81.7s -> 7.2s；4MB 纯随机 45.4s -> 0.4s
  - 新增 16 位 opcode 支持、选择子必须真正参与比较的约束

用法
----
  python3 x86il_dispatch.py payload.bin
  python3 x86il_dispatch.py payload.bin --json map.json --emit handlers.py
  python3 x86il_dispatch.py --selftest            # 自检（10 项）
  python3 x86il_dispatch.py payload.bin -v --seed-mode regex --min-cases 2
  python3 x86il_dispatch.py payload.bin --sel-bits 16 --code-base 0x141D34000
"""
import sys, re, os, json, struct, argparse, collections, time

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

# ------------------------------------------------------------
# 候选点预筛（v1.1 性能优化）
# ------------------------------------------------------------
# 选择子装载候选：movzx / movsx / mov / movsxd，允许任意 REX 前缀。
# 只做「字节级定位」，是否真是指令由 capstone 复核。
_SEL_LOAD_RE = re.compile(
    rb'(?:\x40|\x41|\x42|\x43|\x44|\x45|\x46|\x47|\x48|\x49|\x4a|\x4b|\x4c|\x4d|\x4e|\x4f)?'
    rb'(?:\x0f\xb6|\x0f\xb7|\x0f\xbe|\x0f\xbf|\x8a|\x8b|\x63)')

# 派发核候选：「比较类运算 + 紧跟 jcc」，这是五种派发形态的公共子形态
_DISPATCH_CORE_RE = re.compile(
    rb'(?:'
    rb'\x80[\xf8-\xff].'            # cmp r/m8, imm8
    rb'|\x83[\xf8-\xff].'           # cmp r/m32, imm8
    rb'|\x80[\xe8-\xef].'           # sub r/m8, imm8
    rb'|\x83[\xe8-\xef].'           # sub r/m32, imm8
    rb'|\x48\x83[\xf8-\xff].'       # cmp r64, imm8
    rb'|\x4c\x83[\xf8-\xff].'
    rb'|\x49\x83[\xf8-\xff].'
    rb'|\x4d\x83[\xf8-\xff].'
    rb'|\x48\x83[\xe8-\xef].'       # sub r64, imm8
    rb'|\x4c\x83[\xe8-\xef].'
    rb'|\x49\x83[\xe8-\xef].'
    rb'|\x4d\x83[\xe8-\xef].'
    rb'|\x80[\xf0-\xf7].'           # xor r/m8, imm8
    rb'|\x83[\xf0-\xf7].'           # xor r/m32, imm8
    rb'|\x81[\xf8-\xff]..'          # cmp r/m16, imm16（66 前缀形态）
    rb'|\x81[\xf8-\xff]....'        # cmp r/m32, imm32
    rb'|\x81[\xe8-\xef]..'          # sub r/m16, imm16
    rb'|\x81[\xe8-\xef]....'        # sub r/m32, imm32
    rb'|\x81[\xf0-\xf7]..'          # xor r/m16, imm16
    rb'|\x81[\xf0-\xf7]....'        # xor r/m32, imm32
    rb'|\x3c.'                      # cmp al, imm8
    rb'|\x3d....'                   # cmp eax, imm32
    rb'|\x2c.'                      # sub al, imm8
    rb'|\x2d....'                   # sub eax, imm32
    rb'|\x34.'                      # xor al, imm8
    rb'|\x35....'                   # xor eax, imm32
    rb'|\xff[\xc8-\xcf]'            # dec r32
    rb'|\x48\xff[\xc8-\xcf]'        # dec r64
    rb'|\xff[\xc0-\xc7]'            # inc r32
    rb'|\x48\xff[\xc0-\xc7]'        # inc r64
    rb')'
    rb'(?:\x90|\x66\x90){0,2}'      # 可选 nop 填充
    rb'(?:[\x70-\x7f]|\x0f[\x80-\x8f])')   # jcc rel8 / jcc rel32

# 跳表形态：jmp [reg*scale + disp]（ff 24 / 25 + SIB），给跳表补种子
_JMP_TABLE_RE = re.compile(rb'\xff[\x24\x25]')

# jmp r64（FF /4）：modrm 的 reg 字段 = 100，即 0xE0..0xFF 且低 3 位是目的寄存器
_JMP_REG_RE = re.compile(rb'\xff[\xe0-\xff]')

# shl r32/r64, 3：跳表索引「乘 8」的典型编码
_SHL3_RE = re.compile(rb'(?:\x48|\x49|\x4c|\x4d)?\xc1[\xe0-\xe7]\x03')

SEL_BITS_DEFAULT = 8        # 选择子宽度（位）；真实载荷常见 16

# IP 槽站点集合（绝对虚址）。由 ipslot.py 产出，用于 handler 打分：
# 真实 handler 的块必然终止于「add [ctx+IP], len; jmp reg」这一形态。
IPSITE_ADDRS = set()

_MEMSZ = {'byte ptr': 1, 'word ptr': 2, 'dword ptr': 4, 'qword ptr': 8,
          'xmmword ptr': 16, 'tbyte ptr': 10}
_REGS = set(REG64) | set(_SUB)


def _split2(ostr):
    """'ecx, 0x20' -> ('ecx', '0x20')；无逗号返回 (None, None)"""
    a, sep, b = ostr.partition(', ')
    if not sep:
        return None, None
    return a, b


def _imm(s):
    """把操作数字符串解析成立即数；不是立即数返回 None"""
    if not s:
        return None
    t = s.strip()
    if not (t[0].isdigit() or t[0] == '-'):
        return None
    try:
        return int(t, 0) & 0xFFFFFFFFFFFFFFFF
    except ValueError:
        return None


_SZWORD = {'byte': 1, 'word': 2, 'dword': 4, 'qword': 8, 'tbyte': 10,
           'xmmword': 16, 'oword': 16, 'ymmword': 32, 'zmmword': 64}


def _memsz(s):
    i = s.find(' ptr')
    if i < 0:
        return None
    j = s.rfind(' ', 0, i)
    return _SZWORD.get(s[j + 1:i])


def _dedup(seeds, gap=4):
    """(offset, sel_bits) 去重，间隔过近的只保留一个"""
    seen = {}
    for off, sb in seeds:
        seen.setdefault(off, sb)
    out, last = [], -1 << 62
    for off in sorted(seen):
        if off - last >= gap:
            out.append((off, seen[off]))
            last = off
    return out


_WIDTH = {n: 8 for n in _W8}
_WIDTH.update({n: 16 for n in _W16})
_WIDTH.update({n: 32 for n in _W32})


def reg_width(n):
    return _WIDTH.get(n, 64)


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

    def __init__(self, i, keep_bytes=True):
        self.addr = i.address
        self.size = i.size
        self.mn = i.mnemonic
        self.ostr = i.op_str
        self.bytes = bytes(i.bytes) if keep_bytes else b''
        try:
            self.ops = i.operands          # 仅 detail 模式下可用
        except Exception:
            self.ops = None


def make_md(detail=False, skipdata=False):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = detail
    md.skipdata = skipdata
    return md


class Scanner:
    """dispatch 恢复器"""

    def __init__(self, payload, code_base=CODE_BASE_VA, max_insn=3_000_000,
                 block_limit=400, verbose=False, seed_mode='regex',
                 seed_horizon=64, sel_bits=SEL_BITS_DEFAULT):
        self.p = payload
        self.mv = memoryview(payload)      # 零拷贝切片
        self.base = code_base
        self.md_fast = make_md(False)
        self.md_lite = make_md(False)
        self.md_lite.detail = False
        self.md_det = make_md(True)
        self.max_insn = max_insn
        self.block_limit = block_limit
        self.verbose = verbose
        self.seed_mode = seed_mode         # regex | legacy | both
        self.seed_horizon = seed_horizon
        self.sel_bits = sel_bits
        self.n_insn = 0
        self.entries = []          # dict(opcode, target, via, sel, at, masked, note)
        self.tables = []           # 跳表
        self.dispatch_points = []  # 第六种形态的派发点（含未解析基址的）
        self.unresolved = []
        self.seed_stats = {}
        self._det_cache = {}
        self._sb = sel_bits        # 当前块的选择子位宽

    def _is_jmp_at(self, va):
        """落空的下一条指令是不是无条件跳转（字节级判断，零解码成本）"""
        off = va - self.base
        if off < 0 or off + 1 >= len(self.p):
            return False
        b = self.p[off]
        if b in (0xE9, 0xEB):
            return True
        if b == 0xFF and (self.p[off + 1] & 0x38) == 0x20:
            return True
        return False

    def det_at(self, va, size_hint=15):
        """按虚址做一次 detail 反汇编（只在跳表等少数路径上用）"""
        k = (va, -1)
        if k in self._det_cache:
            return self._det_cache[k]
        off = va - self.base
        d = None
        for x in self.md_det.disasm(self.mv[off:off + size_hint], va):
            d = Ins(x)
            break
        self._det_cache[k] = d
        return d

    # ---------- 取带操作数的指令 ----------
    def det(self, i):
        k = (i.addr, i.size)
        if k in self._det_cache:
            return self._det_cache[k]
        d = None
        off = i.addr - self.base
        for x in self.md_det.disasm(self.mv[off:off + 16], i.addr):
            d = Ins(x)
            break
        if len(self._det_cache) < 400000:
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
                             'blk': self._blk, 'sel_bits': self._sb})

    # ---------- 单块扫描 ----------
    def scan_block(self, start_va, sel=None, lo=0, hi=None, acc=0, xf=None,
                   depth=0, sb=None):
        """
        从 start_va 起顺序解释，直到块结束。
        状态: sel 选择子寄存器 / [lo,hi] 取值区间 / acc 已累积偏移 / xf opcode 变换
              sb 选择子位宽（8 / 16 / 32）
        """
        if depth > 24:
            return
        sb = sb or self.sel_bits
        self._sb = sb
        if hi is None:
            hi = (1 << sb) - 1
        addr = start_va
        self._blk = start_va
        self._saw_sel = False          # 本块是否真的比较过选择子
        saw = False                    # 同上，热路径用局部变量
        # 第六种派发形态的状态：mov rD,[tbl+idx*8]; jmp rD
        scaled = set()                 # 被 shl 3 过的寄存器
        tbase = {}                     # 表基址寄存器 -> 索引寄存器
        baseva = {}                    # 寄存器 -> 已知绝对地址（movabs / lea rip）
        tbl = None                     # (目标寄存器, 索引寄存器, 表绝对地址或 None)
        last_imm = None
        n = 0
        lim = len(self.p)
        CH = 32                     # 一次解码的字节数：批量解码比单条快约 6 倍
        buf = ()
        bi = 0
        while n < self.block_limit:
            n += 1
            off = addr - self.base
            if off < 0 or off >= lim:
                return
            if bi >= len(buf) or buf[bi][0] != addr:
                buf = list(self.md_lite.disasm_lite(self.mv[off:off + CH], addr))
                bi = 0
                if not buf or buf[0][0] != addr:
                    return
            _, size, m, ostr = buf[bi]
            bi += 1
            # 早退：真派发块在选择子装载后一两条指令内必然比较选择子，
            # 24 条还没比较过说明这是 junk 代码里的伪核
            if n > 24 and not saw and not tbl and not tbase and not scaled:
                return
            self.n_insn += 1
            if self.n_insn > self.max_insn:
                return
            nxt = addr + size

            # ---- 跳表派发：mov rD,[tbl+idx*8]; jmp rD ----
            # 真实 VM 把 `jmp [tbl+idx*8]` 拆成「算地址 -> mov 取表项 -> jmp reg」，
            # 现有的 handle_jumptable 只认 jmp [mem]，整类形态会漏光。
            if m in ('shl', 'add', 'mov', 'movabs', 'lea'):
                dstr, sstr = _split2(ostr)
                if m == 'shl' and dstr and sstr and sstr.strip() == '3':
                    scaled.add(canon(dstr))
                elif m == 'add' and dstr and sstr and canon(sstr) in scaled:
                    tbase[canon(dstr)] = canon(sstr)
                elif m == 'movabs' and dstr:
                    v = _imm(sstr)
                    if v is not None:
                        baseva[canon(dstr)] = v
                    else:
                        baseva.pop(canon(dstr), None)
                elif m == 'lea' and dstr and sstr and '[' in sstr:
                    inner = sstr[sstr.index('[') + 1:sstr.rindex(']')]
                    if '*8' in inner:
                        parts = [x.strip() for x in inner.split('+')]
                        idx = None
                        base = None
                        for x in parts:
                            if x.endswith('*8') and x[:-2] in _REGS:
                                idx = canon(x[:-2])
                            elif x in _REGS:
                                base = canon(x)
                        if idx is not None:
                            tbase[canon(dstr)] = idx
                            if base in baseva:
                                baseva[canon(dstr)] = baseva[base]
                            elif base == 'rip':
                                mm = re.search(r'0x[0-9a-fA-F]+', inner)
                                if mm:
                                    baseva[canon(dstr)] = addr + size + int(mm.group(0), 16)
                elif m == 'mov' and dstr and sstr and '[' in sstr:
                    inner = sstr[sstr.index('[') + 1:sstr.rindex(']')].strip()
                    hit = None
                    if inner in tbase:                      # 折叠形态：[tblreg]
                        hit = (tbase[inner], baseva.get(inner))
                    elif '*8' in inner:                     # 直接形态：[tblreg + idx*8]
                        parts = [x.strip() for x in inner.split('+')]
                        idx = b2 = None
                        for x in parts:
                            if x.endswith('*8') and x[:-2] in _REGS:
                                idx = canon(x[:-2])
                            elif x in _REGS:
                                b2 = canon(x)
                            elif x == 'rip':
                                mm = re.search(r'0x[0-9a-fA-F]+', x)
                        if idx is not None:
                            hit = (idx, baseva.get(b2) if b2 else None)
                            if b2 is None and 'rip' in inner:
                                mm = re.search(r'0x[0-9a-fA-F]+', inner.split('*8')[-1])
                                if mm:
                                    hit = (idx, addr + size + int(mm.group(0), 16))
                    if hit is not None:
                        tbl = (canon(dstr), hit[0], hit[1], sel)
                        self.dispatch_points.append(
                            {'kind': 'table-read', 'at': addr, 'dest': canon(dstr),
                             'idx': hit[0], 'base': hit[1],
                             'resolved': hit[1] is not None})
                        last_imm = None
                        addr = nxt
                        continue

            # ---- 选择子写入（纯字符串判定，不做 detail 反汇编）----
            if m in ('movzx', 'movsx', 'mov', 'movsxd'):
                dstr, sstr = _split2(ostr)
                if dstr is not None and sstr is not None and '[' in sstr \
                        and (dstr in _REGS or dstr in _SUB):
                    msz = _memsz(sstr) or 8
                    dw = reg_width(dstr)
                    # 32 位以内直写，或 movzx r64, r/m8|r/m16（真实载荷常见形态）
                    if dw <= 32 or (dw == 64 and 1 <= msz <= 4):
                        newsel = canon(dstr)
                        nsb = 8 * msz
                        if newsel != sel or nsb != sb:
                            sel, sb, lo, acc, xf = newsel, nsb, 0, 0, None
                            hi = (1 << sb) - 1
                            self._sb = sb
                        last_imm = None
                        addr = nxt
                        continue

            if sel is not None and m in ('cmp', 'test', 'sub', 'add', 'xor', 'or',
                                         'and', 'dec', 'inc', 'imul', 'lea'):
                dstr, sstr = _split2(ostr)
                if dstr is None:            # dec/inc 单操作数
                    dstr, sstr = ostr, None
                if canon(dstr) == sel:
                    saw = True
                    self._saw_sel = True
                    if m == 'cmp':
                        last_imm = _imm(sstr)
                    elif m == 'test':
                        last_imm = 0                     # test sel,sel 等价 cmp sel,0
                    elif m == 'sub':
                        v = _imm(sstr)
                        if v is not None:
                            acc += v
                        last_imm = None
                    elif m == 'add':
                        v = _imm(sstr)
                        if v is not None:
                            acc -= v
                        last_imm = None
                    elif m == 'xor':
                        v = _imm(sstr)
                        if v is not None:
                            xf = ('xor', v)
                        last_imm = None
                    elif m == 'and':
                        v = _imm(sstr)
                        if v is not None:
                            xf = ('and', v)
                            lo, hi = 0, v & ((1 << sb) - 1)
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
                tgt = _imm(ostr)
                if tgt is None:
                    return
                cond = JC[m]
                imm = last_imm
                last_imm = None

                if cond == 'e':
                    # jz 命中单一值：
                    #   cmp sel,imm; jz  -> opcode = imm
                    #   sub/dec sel; jz  -> opcode = 累计偏移
                    if not saw:
                        addr = nxt
                        continue
                    v = acc + (imm if imm is not None else 0)
                    via = 'cmp-je' if imm is not None else 'dec-chain'
                    self.emit(self.trans(v, xf), tgt, via, sel, addr)
                    addr = nxt
                    continue

                if cond == 'ne':
                    # 取反分支：目标继续比较，fallthrough 命中 imm。
                    # 必须紧跟一条无条件 jmp 才算 switch，否则 junk 代码里的
                    # cmp al,X / jne 会被大量误判（真实载荷上尤其明显）
                    if imm is not None and saw and self._is_jmp_at(nxt):
                        self.emit(self.trans(acc + imm, xf), nxt, 'cmp-jne', sel, addr)
                    self._push(tgt, sel, lo, hi, acc, xf, depth, sb)
                    return

                if cond in UPPER:
                    edge = imm if imm is not None else lo
                    if cond == 'a':
                        lo_t, hi_t = edge + 1, hi
                        hi = edge
                    else:
                        lo_t, hi_t = edge, hi
                        hi = edge - 1
                    self._push(tgt, sel, lo_t, hi_t, acc, xf, depth, sb)
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
                    self._push(tgt, sel, lo_t, hi_t, acc, xf, depth, sb)
                    addr = nxt
                    continue

                # 其它条件（jo/js/jp）不参与派发
                addr = nxt
                continue

            # ---- 无条件跳转 ----
            if m == 'jmp':
                tgt = _imm(ostr)
                if tgt is not None:
                    if lo == hi:
                        # 区间收敛到单值 -> 该值就是 opcode，target 是 handler
                        if saw:
                            self.emit(self.trans(acc + lo, xf), tgt,
                                      'interval-jmp', sel, addr)
                        return
                    # 未收敛：视为派发链的下一段起点
                    self._push(tgt, sel, lo, hi, acc, xf, depth, sb)
                    return
                if '[' in ostr:
                    d = self.det_at(addr)
                    if d is not None:
                        self.handle_jumptable(d, sel, acc, xf, addr)
                    return
                # 第六种形态：跳表表项已经取到寄存器里
                if tbl is not None and canon(ostr) == tbl[0]:
                    dest, idx, bva, sel_at_read = tbl
                    if idx == sel_at_read or sel_at_read is None:
                        if bva is not None:
                            self.read_table(bva, addr, idx, sel, acc, xf)
                        else:
                            self.dispatch_points.append(
                                {'kind': 'dispatch', 'at': addr, 'idx': idx,
                                 'base': None, 'resolved': False})
                    return
                self.unresolved.append({'opcode': None, 'via': 'jmp-reg', 'at': addr,
                                        'reason': '间接跳转 %s' % ostr})
                return

            if m in ('ret', 'retn', 'int3', 'ud2', 'hlt'):
                return

            addr = nxt
            if self.n_insn > self.max_insn:
                return

    def _push(self, va, sel, lo, hi, acc, xf, depth, sb=None):
        if lo > hi:
            return
        key = (va, lo, hi)
        if key in self._seen:
            return
        self._seen.add(key)
        self._work.append((va, sel, lo, hi, acc, xf, depth + 1, sb))

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
        if sel is not None and o.mem.index:
            iname = canon(self.md_det.reg_name(o.mem.index))
            if iname != sel:
                self.unresolved.append({'opcode': None, 'via': 'jump-table', 'at': at,
                                        'reason': '索引寄存器 %s 不是选择子 %s'
                                                  % (iname, sel)})
                return
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

    def read_table(self, table_va, at, idx, sel, acc, xf, maxn=256):
        """表基址已静态确定时，直接把 opcode -> handler 读出来"""
        toff = table_va - self.base
        if toff < 0 or toff >= len(self.p):
            self.unresolved.append({'opcode': None, 'via': 'mov-table', 'at': at,
                                    'reason': '表 0x%X 不在载荷内' % table_va})
            return
        found = 0
        for k in range(maxn):
            o = toff + k * 8
            if o + 8 > len(self.p):
                break
            v = struct.unpack_from('<Q', self.p, o)[0]
            if not (self.base <= v < self.base + len(self.p)):
                break
            self.emit(self.trans(acc + k, xf), v, 'mov-table', sel, at + k)
            found += 1
        self.tables.append({'at': at, 'table_va': table_va, 'entry_size': 8,
                            'entries': found, 'expr': 'mov rD,[tbl+idx*8]; jmp rD'})

    # ---------- 入口 ----------
    def run(self, seeds=None):
        self._seen = set()
        self._work = collections.deque()
        if seeds:
            for s in seeds:
                off, sb = s if isinstance(s, tuple) else (s, self.sel_bits)
                self._push(self.base + off, None, 0, (1 << sb) - 1, 0, None, 0, sb)
        else:
            self.seed()
        while self._work:
            va, sel, lo, hi, acc, xf, depth, sb = self._work.popleft()
            self.scan_block(va, sel, lo, hi, acc, xf, depth, sb)
        return self.result()

    def seed(self):
        if self.seed_mode == 'legacy':
            self.linear_seed()
        elif self.seed_mode == 'both':
            self.linear_seed()
            self.fast_seed()
        else:
            self.fast_seed()

    # ---------- v1.1：候选点正则预筛 ----------
    def _sel_at(self, off):
        """校验 off 处确实是一条「寄存器 <- 内存」的装载，返回 (addr, size, sel_bits)

        全程走 lite 解码 + 字符串判定，不做 detail 反汇编——这条路径每次预筛
        要跑几万遍，detail 会让整个预筛慢一倍以上。
        """
        loc = off - self.base
        t = None
        for t in self.md_lite.disasm_lite(self.mv[loc:loc + 16], off):
            break
        if t is None:
            return None
        addr, size, m, ostr = t
        if m not in ('movzx', 'movsx', 'mov', 'movsxd'):
            return None
        dstr, sstr = _split2(ostr)
        if dstr is None or sstr is None or '[' not in sstr:
            return None
        if dstr not in _REGS and dstr not in _SUB:
            return None
        msz = _memsz(sstr) or 8
        dw = reg_width(dstr)
        if not (dw <= 32 or (dw == 64 and 1 <= msz <= 4)):
            return None
        return (addr, size), 8 * msz

    def fast_seed(self):
        """
        不再逐字节线性回退，改为三阶段：
          1) C 层正则定位「比较类运算 + jcc」构成的派发核（几乎零成本）
          2) 相邻核聚类（32 字节内算同一派发块）
          3) 每个派发块向前回溯找选择子装载，命中才作为种子
        另补一类种子：选择子装载后直接跟 jmp [reg*scale+disp] 的跳表形态。
        """
        p = self.p
        t0 = time.time()

        cores = [m.start() for m in _DISPATCH_CORE_RE.finditer(p)]
        clusters = []
        last = -1 << 62
        for c in cores:
            if c - last > 32:
                clusters.append(c)
            last = c
        t_pre = time.time() - t0

        back = max(8, min(self.seed_horizon, 48))
        seeds = []
        # 每个核都要回溯：相邻派发器可能只隔十几个字节，按距离聚类会漏
        for c in cores:
            lo = c - back if c > back else 0
            cands = [lo + m.start() for m in _SEL_LOAD_RE.finditer(p[lo:c])]
            for hit in reversed(cands):
                r = self._sel_at(self.base + hit)
                if r is None:
                    continue
                (ia, isz), sb = r
                if ia + isz > self.base + c:
                    continue
                seeds.append((hit, sb))
                break

        extra = 0
        for m in _JMP_TABLE_RE.finditer(p):
            j = m.start()
            if j + 2 >= len(p):
                break
            sib = p[j + 2]
            if (sib & 7) not in (4, 5):      # base=100/101 -> 纯 disp32 表基址
                continue
            lo = j - 20 if j > 20 else 0
            cands = [lo + x.start() for x in _SEL_LOAD_RE.finditer(p[lo:j])]
            for hit in reversed(cands):
                r = self._sel_at(self.base + hit)
                if r is None:
                    continue
                seeds.append((hit, r[1]))
                extra += 1
                break

        # ---- 第六种形态的种子：mov rD,[tbl+idx*8] 后紧跟 jmp rD ----
        # 这类块里没有 cmp/jcc，派发核正则扫不到，必须单独找
        tseeds = self._table_seeds()
        seeds.extend(tseeds)

        seeds = _dedup(seeds)
        self.seed_stats = {'cores': len(cores), 'clusters': len(clusters),
                           'table_seeds2': len(tseeds),
                           'seeds': len(seeds), 'table_seeds': extra,
                           'prescan_s': round(t_pre, 3)}
        if self.verbose:
            print("[seed] 派发核 %d  聚类 %d  种子 %d（含跳表 %d）预筛 %.2fs"
                  % (len(cores), len(clusters), len(seeds), extra, t_pre))
        for off, sb in seeds:
            self._push(self.base + off, None, 0, (1 << sb) - 1, 0, None, 0, sb)

    def _table_seeds(self):
        """
        第六种形态的种子。

        真实代码里 `mov rD,[tbl+idx*8]` 和 `jmp rD` 之间隔着二十多条 junk，
        「紧邻」假设不成立，所以改用更靠前的锚点：`shl rX, 3`（索引左移 3 位）
        和 `mov rD,[rA]; jmp rD` 的紧邻形态各扫一遍。
        """
        p = self.p
        out = []
        for m in _SHL3_RE.finditer(p):
            out.append((m.start(), self.sel_bits))
        for m in _JMP_REG_RE.finditer(p):
            j = m.start()
            jstart = None
            reg = None
            order = (j - 1, j) if (j >= 1 and 0x40 <= p[j - 1] <= 0x4F) else (j, j - 1)
            for st in order:
                if st < 0:
                    continue
                for x in self.md_lite.disasm_lite(self.mv[st:j + 4], self.base + st):
                    if x[0] + x[1] == self.base + j + 2 and x[2] == 'jmp' \
                            and x[3] in _REGS:
                        jstart, reg = st, x[3]
                    break
                if jstart is not None:
                    break
            if reg is None:
                continue
            mstart = None
            for L in range(8, 1, -1):
                st = jstart - L
                if st < 0:
                    continue
                for x in self.md_lite.disasm_lite(self.mv[st:jstart], self.base + st):
                    if x[0] + x[1] == self.base + jstart and x[2] == 'mov':
                        dstr, sstr = _split2(x[3])
                        if dstr == reg and sstr and '[' in sstr:
                            mstart = st
                    break
                if mstart is not None:
                    break
            if mstart is not None:
                out.append((mstart, self.sel_bits))
        return out

    def linear_seed(self):
        """先线性扫一遍：凡是写选择子 + 后续比较的位置都作为块起点（v1 老路径）"""
        off = 0
        n = 0
        while off < len(self.p):
            raw = None
            for x in self.md_fast.disasm(self.mv[off:off + 16], self.base + off):
                raw = Ins(x, keep_bytes=False)
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
                        and d.ops[1].type == X86_OP_MEM:
                    dw = reg_width(self.md_det.reg_name(d.ops[0].reg))
                    msz = d.ops[1].size or 8
                    if dw <= 32 or (dw == 64 and 1 <= msz <= 4):
                        self._push(self.base + off, None, 0, (1 << (8 * msz)) - 1,
                                   0, None, 0, 8 * msz)
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
            'dispatch_points': self.dispatch_points,
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
    """
    看目标像不像 handler。三条判据：
      1) 访问 VM 上下文（[rbp+k]）—— 只对上下文基址在 rbp 的变体有效
      2) 以 jmp 收尾
      3) 块尾落在 IP 槽站点上 —— 对上下文基址被换掉的变体同样有效，
         是真实载荷上唯一还站得住的判据
    """
    md = make_md(True)
    s = 0
    n = 0
    accessed_ctx = 0
    ends_jmp = 0
    hit_ip = 0
    for i in md.disasm(payload[off:off + 200], code_base + off):
        n += 1
        if n > look:
            break
        if i.mnemonic == 'jmp':
            ends_jmp = 1
            if i.address in IPSITE_ADDRS:
                hit_ip = 1
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
    s += 10 if hit_ip else 0          # 终止于 IP 槽站点：强证据
    if 3 <= n <= 40:
        s += 1
    return s, n, accessed_ctx, ends_jmp, hit_ip


def discover(payload, code_base=CODE_BASE_VA, verbose=False, min_cases=1,
             seed_mode='regex', max_insn=3_000_000, sel_bits=SEL_BITS_DEFAULT):
    sc = Scanner(payload, code_base, verbose=verbose, seed_mode=seed_mode,
                 max_insn=max_insn, sel_bits=sel_bits)
    r = sc.run()
    # 每个派发块的分支数：真派发块通常 >= 2 个分支，孤立 cmp/je 多为普通逻辑
    cnt = collections.Counter(e['blk'] for e in r['entries'])
    for e in r['entries']:
        e['block_cases'] = cnt[e['blk']]
    r['block_cases'] = dict(cnt)
    r['min_cases'] = min_cases
    r['seed_stats'] = getattr(sc, 'seed_stats', {})
    # 打分
    scored = collections.OrderedDict()
    for op, lst in r['handlers'].items():
        best = None
        for e in lst:
            if e.get('block_cases', 1) < min_cases:
                continue
            sc_, n_, ctx_, j_, ip_ = score_handler(payload, e['target'], code_base)
            e2 = dict(e)
            e2['score'] = sc_
            e2['insns'] = n_
            e2['ctx_refs'] = ctx_
            e2['ends_jmp'] = j_
            e2['ip_site'] = ip_
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
def discover_handlers_compat(payload, code_base=CODE_BASE_VA, verbose=False,
                             min_cases=2, seed_mode='regex', **kw):
    """返回 x86il_deobf_v2 需要的 {opcode: [(offset, count), ...]}"""
    r = discover(payload, code_base, verbose, min_cases=min_cases,
                 seed_mode=seed_mode, **kw)
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
def opname(op, sel_bits=8):
    """按选择子位宽格式化 opcode：8 位两位，16 位四位"""
    if op is None:
        return '??'
    return ('0x%04X' if sel_bits and sel_bits > 8 else '0x%02X') % op


def report(r, verbose=False):
    st = r['stats']
    print("[*] 处理指令 %d 条，块状态 %d 个，命中 opcode %d 个，条目 %d 条"
          % (st['instructions'], st['blocks'], st['opcodes'], st['entries']))
    ss = r.get('seed_stats') or {}
    if ss:
        print("[*] 种子：派发核 %d -> 聚类 %d -> 种子 %d（跳表 %d），预筛 %.2fs"
              % (ss.get('cores', 0), ss.get('clusters', 0), ss.get('seeds', 0),
                 ss.get('table_seeds', 0), ss.get('prescan_s', 0.0)))

    dp = r.get('dispatch_points') or []
    tab = [x for x in dp if x['kind'] == 'dispatch']
    if tab:
        res = sum(1 for x in tab if x['resolved'])
        print("[*] 第六种形态（mov rD,[tbl+idx*8]; jmp rD）派发点 %d 个，"
              "表基址可静态解析 %d 个" % (len(tab), res))

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
        name = opname(op, b.get('sel_bits', 8)) if op is not None else '??'
        note = b.get('note') or ''
        if b['masked'] is not None and op is None:
            note = 'masked=0x%X' % b['masked']
        print("   %-6s 0x%-8X %-6d %-5d %-12s %s"
              % (name, b['target'], b['score'], b['insns'], b['via'], note))

    dup = {k: v for k, v in alias.items() if len(v) > 1 and all(x is not None for x in v)}
    if dup:
        print("\n[别名] 多个 opcode 指向同一 handler")
        for tgt, ops in dup.items():
            print("   0x%-8X <- %s" % (tgt, ', '.join(opname(o) for o in ops)))

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
        L.append('    %s: {"handler": 0x%X, "score": %d, "via": %r, "sel_bits": %d},'
                 % (opname(op, b.get('sel_bits', 8)), b['target'], b['score'],
                    b['via'], b.get('sel_bits', 8)))
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

    # ---------- 9. 16 位选择子（真实 DiskGenius 载荷的形态） ----------
    body = ("mov rax, [rbp+0x92]\n"
            "movzx r13, word ptr [rax]\n"
            "cmp r13w, 0x1020\n je h0\n"
            "cmp r13, 0x1021\n je h1\n"
            "jmp vm_exit\n")
    r = discover(_build(body + mk([(None, h) for h in handlers]) + "\nvm_exit:\n ret\n"))
    ops = sorted(k for k in r['scored'] if k is not None)
    check("16 位选择子 (movzx r64, word)", ops == [0x1020, 0x1021],
          str([opname(o, 16) for o in ops]))

    # ---------- 10. 精度：选择子从未参与比较时不得发 opcode ----------
    body = ("mov rax, [rbp+0x92]\n"
            "movzx ecx, byte ptr [rax]\n"
            "dec edx\n jz h0\n"          # 比较的是 edx，不是选择子 rcx
            "jmp vm_exit\n")
    r = discover(_build(body + mk([(None, h) for h in handlers]) + "\nvm_exit:\n ret\n"))
    ops = [k for k in r['scored'] if k is not None]
    check("精度：选择子未参与比较", ops == [], str(['0x%02X' % o for o in ops]))

    # ---------- 11. 第六种形态：mov rD,[tbl+idx*8]; jmp rD ----------
    body = ("mov rax, [rbp+0x92]\n"
            "movzx r12d, byte ptr [rax]\n"
            "mov r10, rbp\n"
            "shl r12, 3\n"
            "add r10, r12\n"
            "mov r11, qword ptr [r10]\n"
            "jmp r11\n")
    src = body + mk([(None, h) for h in handlers]) + "\nvm_exit:\n ret\n"
    sc = Scanner(_build(src), CODE_BASE_VA)
    r = sc.run()
    dps = [d for d in r['dispatch_points'] if d['kind'] == 'dispatch']
    check("跳表拆成 mov+jmp reg", len(dps) >= 1,
          '%d 个派发点（基址运行期）' % len(dps))

    # ---------- 12. 表基址可解析时直接读出 opcode->handler ----------
    import struct as _st
    buf = bytearray(b'\x90' * 64)
    for _k, _v in enumerate((0x10, 0x11, 0x12, 0x13)):
        _st.pack_into('<Q', buf, _k * 8, CODE_BASE_VA + _v)
    sc2 = Scanner(bytes(buf), CODE_BASE_VA)
    sc2._blk = CODE_BASE_VA
    sc2._sb = 8
    sc2.read_table(CODE_BASE_VA, CODE_BASE_VA, 0, None, 0, None)
    ops2 = sorted(e['opcode'] for e in sc2.entries)
    check("表基址可解析时读表", ops2 == [0, 1, 2, 3],
          str([opname(o) for o in ops2]))

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
    ap.add_argument('--seed-mode', choices=('regex', 'legacy', 'both'), default='regex',
                    help='种子策略：regex=正则预筛（默认，快） legacy=逐字节回退 both=并集')
    ap.add_argument('--min-cases', type=int, default=2,
                    help='派发块至少要有几个分支才认（默认 2，抑制孤立误报）')
    ap.add_argument('--ipslots', metavar='JSON',
                    help='ipslot.py 产出的站点表，用于 handler 打分（强烈建议在真实载荷上给）')
    ap.add_argument('--sel-bits', type=int, default=8, choices=(8, 16, 32),
                    help='选择子位宽，真实 VM 常见 16')
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

    if args.ipslots:
        IPSITE_ADDRS.clear()
        IPSITE_ADDRS.update(d['at'] for d in json.load(open(args.ipslots, encoding='utf-8'))['sites'])
        print("[*] 载入 IP 槽站点 %d 个" % len(IPSITE_ADDRS))

    r = discover(payload, cb, verbose=args.verbose, min_cases=args.min_cases,
                 seed_mode=args.seed_mode, max_insn=args.max_insn,
                 sel_bits=args.sel_bits)
    report(r, args.verbose)

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            dps = [d for d in r['dispatch_points'] if d['kind'] == 'dispatch']
            json.dump({'code_base': cb,
                       'handlers': {('0x%02X' % op if op is not None else '?'):
                                    d['best'] for op, d in r['scored'].items()},
                       'tables': r['tables'],
                       'dispatch_points': [{'at': '0x%X' % d['at'], 'idx': d['idx'],
                                            'resolved': d['resolved']} for d in dps],
                       'stats': r['stats']},
                      f, ensure_ascii=False, indent=2, default=str)
        print("[+] 已生成 %s" % args.json)
    if args.emit:
        emit_python(r, args.emit, cb)


if __name__ == '__main__':
    main()

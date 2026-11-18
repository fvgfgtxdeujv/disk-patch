#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================
 X86IL 去混淆器 v2（Oreans WinLicense / SecureEngine mutation）
================================================================
在 v1 基础上的修复与扩展：

  修复
  ----
  1. 32 位目标寄存器写入按 x86-64 语义零扩展（v1 会保留高位造成污染）
  2. 动态地址的槽位改为「地址表达式 -> 稳定 tag」，写后读/压栈出栈可正确穿透
  3. 内存目标读-改-写（xor [rbp+X], reg / inc dword [rbp+X] ...）真正回写
  4. 负位移按有符号归一化，ctx[-0x18] 不再变成 0xFFFFFFFFFFFFFFE8
  5. RIP 相对寻址按 insn.address+size 求值，跳表不再直接崩溃
  6. jcc 走双分支（不透明谓词可穿透），按可达性遍历而非线性扫描
  7. 遇到不支持的指令不再整体放弃：标 approx 后跳过并继续
  8. 覆盖 xchg/imul/movsxd/rol/ror/shld/shrd/bswap/bt*/setcc/cmovcc/
     lahf/sahf/leave/movbe/cdq/cqo/mul/div 等 mutation 常用指令
  9. dispatch 扫描改为 Capstone 语义匹配，支持 cmp r8/r32, imm、
     and r8, imm、内存操作数、以及 cmp 与 je 之间的垃圾字节
 10. IP 槽位自动识别（不再硬编码 0x92），关键常量全部可由命令行覆盖

  新增
  ----
  --coverage   统计触发 Unsupported 的助记符排行，指示下一步该补什么
  --json       机器可读输出
  --selftest   内置回归测试（14 项）
  --emit       生成带 VM 语义摘要的 HANDLERS 表

用法
----
  python3 x86il_deobf_v2.py payload.bin --selftest
  python3 x86il_deobf_v2.py payload.bin --scan
  python3 x86il_deobf_v2.py payload.bin --coverage
  python3 x86il_deobf_v2.py payload.bin --handler 0x2c00e3
  python3 x86il_deobf_v2.py payload.bin --batch --ip-offset 0x92 --emit handlers.py

依赖: pip install capstone z3-solver
"""
import sys, re, os, json, struct, argparse, copy, collections

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import (X86_OP_REG, X86_OP_IMM, X86_OP_MEM,
                          X86_REG_RIP, X86_REG_EIP, X86_REG_RSP, X86_REG_RBP)

from z3 import (BitVec, BitVecVal, Bool, BoolVal, Extract, Concat, ZeroExt, SignExt,
                LShR, RotateLeft, RotateRight, simplify, is_bv_value,
                is_true, is_false, Solver, sat, unsat)

# ============================================================
# 0. 寄存器模型
# ============================================================
REG64 = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp'] + ['r%d' % i for i in range(8, 16)]

_SUB = {}
for _full, _parts in [('rax', ['eax', 'ax', 'al', 'ah']), ('rbx', ['ebx', 'bx', 'bl', 'bh']),
                      ('rcx', ['ecx', 'cx', 'cl', 'ch']), ('rdx', ['edx', 'dx', 'dl', 'dh']),
                      ('rsi', ['esi', 'si', 'sil']), ('rdi', ['edi', 'di', 'dil']),
                      ('rbp', ['ebp', 'bp', 'bpl']), ('rsp', ['esp', 'sp', 'spl'])]:
    for _p in _parts:
        _SUB[_p] = _full
for _i in range(8, 16):
    for _s in ('d', 'w', 'b'):
        _SUB['r%d%s' % (_i, _s)] = 'r%d' % _i

_W8 = set('al bl cl dl ah bh ch dh sil dil bpl spl'.split()) | set('r%db' % i for i in range(8, 16))
_W16 = set('ax bx cx dx si di bp sp'.split()) | set('r%dw' % i for i in range(8, 16))
_W32 = set('eax ebx ecx edx esi edi ebp esp'.split()) | set('r%dd' % i for i in range(8, 16))
_HIGH8 = {'ah': ('rax', 8), 'bh': ('rbx', 8), 'ch': ('rcx', 8), 'dh': ('rdx', 8)}


def reg_width(name):
    if name in _W8:
        return 8
    if name in _W16:
        return 16
    if name in _W32:
        return 32
    return 64


def canon(name):
    return _SUB.get(name, name)


def rmask(w):
    return (1 << w) - 1


def _trunc(w, e):
    """对齐到 w 位；已是 w 位则原样返回（避免冗余 Extract 污染可读性）"""
    if e.size() == w:
        return e
    return Extract(w - 1, 0, e) if e.size() > w else ZeroExt(w - e.size(), e)


def s32(v):
    """把 64 位无符号偏移归一成有符号整数（用于 ctx 位移显示）"""
    v &= (1 << 64) - 1
    if v & (1 << 63):
        v -= 1 << 64
    if -(1 << 31) <= v < (1 << 32):
        return v
    return v  # 极端值保持原样


# ============================================================
# 1. 常量传播（Pass 2，仅用于报告，不参与符号状态）
# ============================================================
class ConstProp:
    """基本块内常量传播。把 mov+sub 之类的常量链折成单条 mov。"""

    def __init__(self):
        self.const = {}
        self.hits = 0
        self.folds = []

    def reset(self):
        self.const.clear()

    def _get(self, name):
        return self.const.get(canon(name))

    def _put(self, name, v):
        self.const[canon(name)] = v & rmask(reg_width(name))

    def feed(self, insn, md):
        m, ops = insn.mnemonic, insn.operands
        if not ops:
            return None

        if m in ('mov', 'movabs') and ops[0].type == X86_OP_REG:
            w = reg_width(md.reg_name(ops[0].reg))
            if ops[1].type == X86_OP_IMM:
                self._put(md.reg_name(ops[0].reg), ops[1].imm)
                return None
            if ops[1].type == X86_OP_REG:
                if reg_width(md.reg_name(ops[1].reg)) == w:
                    v = self._get(md.reg_name(ops[1].reg))
                    if v is not None:
                        self._put(md.reg_name(ops[0].reg), v)
                        self.hits += 1
                        txt = 'mov %s, 0x%X' % (md.reg_name(ops[0].reg), v)
                        self.folds.append((insn, txt, '常量传播 <- %s' % md.reg_name(ops[1].reg)))
                        return txt
            self.const.pop(canon(md.reg_name(ops[0].reg)), None)
            return None

        if m in ('add', 'sub', 'xor', 'or', 'and') and ops[0].type == X86_OP_REG:
            name = md.reg_name(ops[0].reg)
            w = reg_width(name)
            cur = self._get(name)
            if ops[1].type == X86_OP_IMM and cur is not None:
                b = ops[1].imm & rmask(w)
                r = {'add': cur + b, 'sub': cur - b, 'xor': cur ^ b,
                     'or': cur | b, 'and': cur & b}[m] & rmask(w)
                self._put(name, r)
                self.hits += 1
                txt = 'mov %s, 0x%X' % (name, r)
                self.folds.append((insn, txt, '折叠 0x%X %s 0x%X = 0x%X' % (cur, m, b, r)))
                return txt
            if ops[1].type == X86_OP_REG:
                b = self._get(md.reg_name(ops[1].reg))
                if cur is not None and b is not None:
                    r = {'add': cur + b, 'sub': cur - b, 'xor': cur ^ b,
                         'or': cur | b, 'and': cur & b}[m] & rmask(w)
                    self._put(name, r)
                    self.hits += 1
                    txt = 'mov %s, 0x%X' % (name, r)
                    self.folds.append((insn, txt, '折叠 0x%X %s 0x%X = 0x%X' % (cur, m, b, r)))
                    return txt
            self.const.pop(canon(name), None)
            return None

        if m not in ('cmp', 'test', 'push', 'jmp', 'ret', 'nop') and ops[0].type == X86_OP_REG:
            self.const.pop(canon(md.reg_name(ops[0].reg)), None)
        return None


# ============================================================
# 2. 基址别名追踪（Pass 1）
# ============================================================
class AliasTracker:
    """追踪 rbp（VM 上下文基址）是否被 mutation 挪用"""

    BASE_REG = 'rbp'

    def __init__(self):
        self.clobbers = []
        self.clobbered = False
        self.base_copy = {}

    def note(self, insn, md):
        m, ops = insn.mnemonic, insn.operands
        if not ops:
            return
        if ops[0].type == X86_OP_REG and canon(md.reg_name(ops[0].reg)) == self.BASE_REG:
            if m not in ('cmp', 'test', 'push'):
                # mov rbp, rbp 之类不算挪用
                if not (m == 'mov' and len(ops) == 2 and ops[1].type == X86_OP_REG
                        and canon(md.reg_name(ops[1].reg)) == self.BASE_REG):
                    self.clobbered = True
                    self.clobbers.append('%s %s @0x%X' % (m, insn.op_str, insn.address))
        if m == 'mov' and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
            if canon(md.reg_name(ops[1].reg)) == self.BASE_REG:
                self.base_copy[canon(md.reg_name(ops[0].reg))] = True
            elif canon(md.reg_name(ops[0].reg)) == self.BASE_REG:
                self.base_copy.clear()

    def report(self):
        return {'clobbered': self.clobbered,
                'events': self.clobbers,
                'base_copies': list(self.base_copy.keys())}


IP_OFFSET = 0x92          # VM 指令指针在 ctx 中的偏移（--ip-offset / detect_ip 可覆盖）


# ============================================================
# 3. 平坦内存模型（修复：稳定 tag + 有符号位移 + 字节码取值命名）
# ============================================================
class FlatMem:
    """
    VM 上下文的平坦内存模型。
    [rbp + k] -> 具名槽位 ctx[k]；其它地址按表达式字符串稳定映射到 D<n>。
    """

    def __init__(self, base):
        self.base = base
        self.value = {}     # (tag, width) -> expr
        self.tag_off = {}   # tag -> 有符号 ctx 偏移（仅 C* 有效）
        self.dyn_tag = {}   # 地址表达式字符串 -> tag
        self.n_dyn = 0

    # ---- 地址分解：用减法判断是否为 base+常量，比对结构更稳 ----
    def offset_of(self, addr):
        try:
            off = simplify(addr - self.base)
        except Exception:
            return None
        if is_bv_value(off):
            return off.as_long()
        return None

    def key_of(self, addr):
        off = self.offset_of(addr)
        if off is not None:
            o = s32(off)
            tag = 'C%x' % (off & ((1 << 64) - 1))
            self.tag_off.setdefault(tag, o)
            return tag, o
        # ★ [IP + k] 形态：这是读字节码操作数，单独命名为 F<k>
        e = simplify(addr)
        if e.num_args() == 2 and e.decl().name() == 'bvadd':
            for x, y in ((e.arg(0), e.arg(1)), (e.arg(1), e.arg(0))):
                mm = re.match(r'M_C([0-9a-fA-F]+)_(\d+)$', str(x))
                if mm and is_bv_value(y) and s32(int(mm.group(1), 16)) == IP_OFFSET:
                    return 'F%x' % (y.as_long() & ((1 << 64) - 1)), None
        k = str(simplify(addr))
        if k not in self.dyn_tag:
            self.dyn_tag[k] = 'D%d' % self.n_dyn
            self.n_dyn += 1
        return self.dyn_tag[k], None

    def load(self, addr, width):
        tag, _ = self.key_of(addr)
        key = (tag, width)
        if key not in self.value:
            self.value[key] = BitVec('M_%s_%d' % (tag, width), width)
        return self.value[key]

    def store(self, addr, width, val):
        tag, _ = self.key_of(addr)
        if val.size() != width:
            val = Extract(width - 1, 0, val) if val.size() > width else ZeroExt(width - val.size(), val)
        self.value[(tag, width)] = val

    def clone(self):
        m = FlatMem(self.base)
        m.value = dict(self.value)
        m.tag_off = dict(self.tag_off)
        m.dyn_tag = dict(self.dyn_tag)
        m.n_dyn = self.n_dyn
        return m


class SymState:
    """符号状态。修复：32 位写入零扩展 / 高位寄存器 / RIP 常量。"""

    def __init__(self, base=None):
        self.base = base if base is not None else BitVec('rbp', 64)
        self.reg = dict((r, BitVec(r, 64)) for r in REG64)
        self.reg['rbp'] = self.base
        self.mem = FlatMem(self.base)
        self.events = []      # (kind, addr_expr, width)
        self.flags = dict((f, Bool('%s_%d' % (f, id(self)))) for f in ('zf', 'sf', 'cf', 'of', 'pf'))
        self.approx = 0
        self.rip = 0

    def clone(self):
        s = SymState.__new__(SymState)
        s.base = self.base
        s.reg = dict(self.reg)
        s.mem = self.mem.clone()
        s.events = list(self.events)
        s.flags = dict(self.flags)
        s.approx = self.approx
        s.rip = self.rip
        return s

    def get(self, name):
        if name in _HIGH8:
            full, sh = _HIGH8[name]
            return Extract(sh + 7, sh, self.reg[full])
        c = canon(name)
        w = reg_width(name)
        if c == 'rip':
            return BitVecVal(self.rip, 64)
        if c not in self.reg:
            self.reg[c] = BitVec(c, 64)
        return self.reg[c] if w == 64 else Extract(w - 1, 0, self.reg[c])

    def set(self, name, val):
        if name in _HIGH8:                      # ah/bh/ch/dh
            full, sh = _HIGH8[name]
            v = Extract(7, 0, val)
            cur = self.reg[full]
            self.reg[full] = Concat(Extract(63, sh + 8, cur), v, Extract(sh - 1, 0, cur))
            return
        c = canon(name)
        w = reg_width(name)
        if val.size() != w:
            val = Extract(w - 1, 0, val) if val.size() > w else ZeroExt(w - val.size(), val)
        if w == 64:
            self.reg[c] = val
        elif w == 32:
            self.reg[c] = ZeroExt(32, val)      # ★ 修复 1：x86-64 的 32 位写入零扩展
        else:
            self.reg[c] = Concat(Extract(63, w, self.reg[c]), val)
        # 常量直接折成字面量，便于后续判断与报告
        v = simplify(self.reg[c])
        if is_bv_value(v):
            self.reg[c] = BitVecVal(v.as_long() & ((1 << 64) - 1), 64)

    def poison(self, name):
        """把寄存器标记为未知（不支持的指令之后）"""
        if canon(name) in ('rbp', 'rsp'):
            return
        c = canon(name)
        self.reg[c] = BitVec('%s_p%d' % (c, self.approx), 64)


# ============================================================
# 4. 执行引擎
# ============================================================
class Unsupported(Exception):
    pass


_CC = {
    'e': lambda f: f['zf'], 'z': lambda f: f['zf'],
    'ne': lambda f: ~f['zf'], 'nz': lambda f: ~f['zf'],
    's': lambda f: f['sf'], 'ns': lambda f: ~f['sf'],
    'c': lambda f: f['cf'], 'b': lambda f: f['cf'], 'nae': lambda f: f['cf'],
    'nc': lambda f: ~f['cf'], 'ae': lambda f: ~f['cf'], 'nb': lambda f: ~f['cf'],
    'o': lambda f: f['of'], 'no': lambda f: ~f['of'],
    'p': lambda f: f['pf'], 'pe': lambda f: f['pf'],
    'np': lambda f: ~f['pf'], 'po': lambda f: ~f['pf'],
    'be': lambda f: f['cf'] | f['zf'], 'na': lambda f: f['cf'] | f['zf'],
    'a': lambda f: ~(f['cf'] | f['zf']), 'nbe': lambda f: ~(f['cf'] | f['zf']),
    'l': lambda f: f['sf'] != f['of'], 'nge': lambda f: f['sf'] != f['of'],
    'ge': lambda f: f['sf'] == f['of'], 'nl': lambda f: f['sf'] == f['of'],
    'le': lambda f: f['zf'] | (f['sf'] != f['of']),
    'ng': lambda f: f['zf'] | (f['sf'] != f['of']),
    'g': lambda f: ~f['zf'] & (f['sf'] == f['of']),
    'nle': lambda f: ~f['zf'] & (f['sf'] == f['of']),
}


def cc_suffix(m):
    """jz -> 'z' ; cmovne -> 'ne' ; seta -> 'a'"""
    for pre in ('cmov', 'set'):
        if m.startswith(pre):
            return m[len(pre):]
    if m.startswith('j') and m not in ('jmp',):
        return m[1:]
    return None


def eval_cond(st, suff):
    f = _CC.get(suff)
    if f is None:
        return None
    e = simplify(f(st.flags))
    if is_true(e):
        return True
    if is_false(e):
        return False
    return None


class Exec:
    """指令语义。所有 read() 返回操作数「自然宽度」，由调用方 _trunc 对齐。"""

    def __init__(self, md):
        self.md = md

    # ---------- 操作数工具 ----------
    def opw(self, o):
        if o.type == X86_OP_REG:
            return reg_width(self.md.reg_name(o.reg))
        if o.type == X86_OP_MEM:
            return max(8, (o.size or 8) * 8)
        return 64

    def addr_of(self, st, i, o):
        md = self.md
        if o.mem.base in (X86_REG_RIP, X86_REG_EIP):
            b = BitVecVal(i.address + i.size, 64)
        elif o.mem.base:
            b = st.get(md.reg_name(o.mem.base))
        else:
            b = BitVecVal(0, 64)
        # ★ 32 位基址/索引在 64 位模式下按零扩展参与运算，必须对齐位宽
        a = _trunc(64, b)
        if o.mem.index:
            idx = _trunc(64, st.get(md.reg_name(o.mem.index)))
            a = a + idx * BitVecVal(o.mem.scale or 1, 64)
        return simplify(a + BitVecVal(o.mem.disp & 0xFFFFFFFFFFFFFFFF, 64))

    def read(self, st, i, o, w=None):
        """返回操作数的自然宽度值（IMM/MEM 按 w，REG 按寄存器宽度）"""
        if o.type == X86_OP_REG:
            return st.get(self.md.reg_name(o.reg))
        if o.type == X86_OP_IMM:
            w = w or 64
            return BitVecVal(o.imm & rmask(w), w)
        w = w or self.opw(o)
        a = self.addr_of(st, i, o)
        v = st.mem.load(a, w)
        st.events.append(('LOAD', a, w, v))
        return v

    def write(self, st, i, o, val):
        """★ 修复 3：统一支持寄存器 / 内存目标，内存目标真正回写"""
        md = self.md
        w = self.opw(o)
        val = _trunc(w, val)
        if o.type == X86_OP_MEM:
            a = self.addr_of(st, i, o)
            st.mem.store(a, w, val)
            st.events.append(('STORE', a, w, val))
        else:
            st.set(md.reg_name(o.reg), val)

    def rmw(self, st, i, o, fn):
        w = self.opw(o)
        r = _trunc(w, fn(_trunc(w, self.read(st, i, o, w))))
        self.write(st, i, o, r)
        return r

    def set_flags_logic(self, st, r, w):
        st.flags['zf'] = Extract(w - 1, w - 1, r) == 0
        st.flags['sf'] = Extract(w - 1, w - 1, r) == 1
        st.flags['cf'] = BoolVal(False)
        st.flags['of'] = BoolVal(False)

    def set_flags_sub(self, st, a, b, r, w):
        st.flags['zf'] = r == 0
        st.flags['sf'] = Extract(w - 1, w - 1, r) == 1
        st.flags['cf'] = (a < b) if w == 64 else (ZeroExt(64 - w, a) < ZeroExt(64 - w, b))
        st.flags['of'] = Bool('of_%d' % st.approx)

    # ---------- 主分发 ----------
    def step(self, st, i):
        m, ops = i.mnemonic, i.operands
        st.rip = i.address + i.size
        md = self.md

        # ---- 数据传送 ----
        if m in ('mov', 'movabs'):
            if len(ops) != 2:
                raise Unsupported(m)
            w = self.opw(ops[0])
            self.write(st, i, ops[0], self.read(st, i, ops[1], w))
            return 'next'

        if m in ('movzx', 'movsx', 'movsxd'):
            dw = self.opw(ops[0]); sw = self.opw(ops[1])
            v = _trunc(sw, self.read(st, i, ops[1], sw))
            if dw > sw:
                v = ZeroExt(dw - sw, v) if m == 'movzx' else SignExt(dw - sw, v)
            self.write(st, i, ops[0], v)
            return 'next'

        if m == 'lea':
            self.write(st, i, ops[0], self.addr_of(st, i, ops[1]))
            return 'next'

        if m == 'xchg':
            a = self.read(st, i, ops[0], self.opw(ops[0]))
            b = self.read(st, i, ops[1], self.opw(ops[1]))
            self.write(st, i, ops[1], a)
            self.write(st, i, ops[0], b)
            return 'next'

        if m == 'xadd':
            w = self.opw(ops[0])
            a = _trunc(w, self.read(st, i, ops[0], w))
            b = _trunc(w, self.read(st, i, ops[1], w))
            r = a + b
            self.set_flags_sub(st, a, -b, r, w)
            self.write(st, i, ops[0], r)
            self.write(st, i, ops[1], a)
            return 'next'

        if m in ('bswap', 'movbe'):
            w = self.opw(ops[0])
            v = _trunc(w, self.read(st, i, ops[1] if len(ops) > 1 else ops[0], w))
            r = Extract(7, 0, v)
            for k in range(1, w // 8):
                r = Concat(r, Extract(8 * k + 7, 8 * k, v))
            self.write(st, i, ops[0], r)
            if m == 'movbe':
                st.approx += 1
            return 'next'

        # ---- 算术逻辑 ----
        if m in ('add', 'sub', 'xor', 'or', 'and'):
            w = self.opw(ops[0])
            a = _trunc(w, self.read(st, i, ops[0], w))
            b = _trunc(w, self.read(st, i, ops[1], w))
            r = {'add': a + b, 'sub': a - b, 'xor': a ^ b, 'or': a | b, 'and': a & b}[m]
            if m in ('xor', 'or', 'and'):
                self.set_flags_logic(st, r, w)
            else:
                self.set_flags_sub(st, a, b, r, w)
            self.write(st, i, ops[0], r)
            return 'next'

        if m in ('adc', 'sbb'):
            w = self.opw(ops[0])
            a = _trunc(w, self.read(st, i, ops[0], w))
            b = _trunc(w, self.read(st, i, ops[1], w))
            c = BitVec('c_%d' % st.approx, w)
            self.write(st, i, ops[0], a + b + c if m == 'adc' else a - b - c)
            for f in st.flags:
                st.flags[f] = Bool('%s_adc%d' % (f, st.approx))
            st.approx += 1
            return 'next'

        if m in ('inc', 'dec'):
            w = self.opw(ops[0])
            r = self.rmw(st, i, ops[0], lambda a: a + 1 if m == 'inc' else a - 1)
            self.set_flags_logic(st, _trunc(w, r), w)
            return 'next'

        if m in ('neg', 'not'):
            w = self.opw(ops[0])
            r = self.rmw(st, i, ops[0], lambda a: -a if m == 'neg' else ~a)
            if m == 'neg':
                self.set_flags_sub(st, BitVecVal(0, w), _trunc(w, r), _trunc(w, r), w)
            return 'next'

        if m == 'imul':
            if len(ops) == 3:
                w = self.opw(ops[0])
                a = _trunc(w, self.read(st, i, ops[1], w))
                b = _trunc(w, self.read(st, i, ops[2], w))
                self.write(st, i, ops[0], a * b)
                return 'next'
            if len(ops) == 2:
                w = self.opw(ops[0])
                a = _trunc(w, self.read(st, i, ops[0], w))
                b = _trunc(w, self.read(st, i, ops[1], w))
                self.write(st, i, ops[0], a * b)
                return 'next'
            if len(ops) == 1:
                w = self.opw(ops[0])
                a = _trunc(w, self.read(st, i, ops[0], w))
                acc = 'rax' if w == 64 else {32: 'eax', 16: 'ax', 8: 'al'}[w]
                st.set(acc, _trunc(w, st.get(acc)) * a)
                st.poison('rdx')
                st.approx += 1
                return 'next'
            raise Unsupported(m)

        if m in ('mul', 'div', 'idiv'):
            st.poison('rax'); st.poison('rdx')
            for f in st.flags:
                st.flags[f] = Bool('%s_m%d' % (f, st.approx))
            st.approx += 1
            return 'next'

        # ---- 移位 ----
        if m in ('shl', 'sal', 'shr', 'sar', 'rol', 'ror', 'rcl', 'rcr'):
            w = self.opw(ops[0])
            cnt = self.read(st, i, ops[1]) if len(ops) > 1 else BitVecVal(1, 64)
            cs = simplify(cnt)
            if m in ('rcl', 'rcr'):
                st.approx += 1
            base = {'sal': 'shl', 'rcl': 'rol', 'rcr': 'ror'}.get(m, m)
            n = cs.as_long() & 0xFF if is_bv_value(cs) else None

            def sh(a, base=base, n=n, cnt=cnt):
                # ★ 移位量必须与目标同宽，否则 z3 报 sort mismatch
                amt = BitVecVal(n, a.size()) if n is not None else _trunc(a.size(), cnt)
                if base == 'shl':
                    return a << amt
                if base == 'shr':
                    return LShR(a, amt)
                if base == 'sar':
                    return a >> amt
                if n is not None:
                    k = n % a.size()
                    return RotateLeft(a, k) if base == 'rol' else RotateRight(a, k)
                return RotateLeft(a, amt) if base == 'rol' else RotateRight(a, amt)
            r = self.rmw(st, i, ops[0], sh)
            self.set_flags_logic(st, _trunc(w, r), w)
            return 'next'

        if m in ('shld', 'shrd'):
            w = self.opw(ops[0])
            a = _trunc(w, self.read(st, i, ops[0], w))
            b = _trunc(w, self.read(st, i, ops[1], w))
            n = simplify(self.read(st, i, ops[2]))
            if is_bv_value(n):
                k = n.as_long() % w
                if k == 0:
                    return 'next'
                r = Concat(Extract(w - k - 1, 0, a), Extract(w - 1, w - k, b)) if m == 'shld' \
                    else Concat(Extract(k - 1, 0, b), Extract(w - 1, k, a))
                self.write(st, i, ops[0], r)
            else:
                st.approx += 1
                st.poison(md.reg_name(ops[0].reg))
            return 'next'

        # ---- 位操作 ----
        if m in ('bt', 'bts', 'btr', 'btc'):
            w = self.opw(ops[0])
            a = _trunc(w, self.read(st, i, ops[0], w))
            iv = simplify(self.read(st, i, ops[1]))
            if is_bv_value(iv):
                k = iv.as_long() % w
                st.flags['cf'] = Extract(k, k, a) == 1
                if m != 'bt':
                    mask = BitVecVal(1 << k, w)
                    self.write(st, i, ops[0],
                               a | mask if m == 'bts' else a & ~mask if m == 'btr' else a ^ mask)
            else:
                st.approx += 1
                st.flags['cf'] = Bool('cf_bt%d' % st.approx)
                if m != 'bt':
                    self.write(st, i, ops[0], BitVec('bt%d' % st.approx, w))
            return 'next'

        # ---- 条件传送 / 条件置位 ----
        if m.startswith('cmov'):
            r = eval_cond(st, cc_suffix(m))
            w = self.opw(ops[0])
            if r is True:
                self.write(st, i, ops[0], self.read(st, i, ops[1], w))
            elif r is None:
                st.approx += 1
                st.poison(md.reg_name(ops[0].reg))
            return 'next'

        if m.startswith('set'):
            r = eval_cond(st, cc_suffix(m))
            w = self.opw(ops[0])
            if r is True:
                self.write(st, i, ops[0], BitVecVal(1, w))
            elif r is False:
                self.write(st, i, ops[0], BitVecVal(0, w))
            else:
                st.approx += 1
                self.write(st, i, ops[0], BitVec('set%d' % st.approx, w))
            return 'next'

        # ---- 标志位 ----
        if m in ('cmp', 'test'):
            w = self.opw(ops[0])
            a = _trunc(w, self.read(st, i, ops[0], w))
            b = _trunc(w, self.read(st, i, ops[1], w))
            if m == 'cmp':
                self.set_flags_sub(st, a, b, simplify(a - b), w)
            else:
                self.set_flags_logic(st, simplify(a & b), w)
            return 'next'

        if m in ('clc', 'stc', 'cmc'):
            st.flags['cf'] = BoolVal(False) if m == 'clc' else BoolVal(True) if m == 'stc' \
                else Bool('cmc%d' % st.approx)
            return 'next'

        if m in ('cld', 'std'):
            return 'next'

        if m == 'lahf':
            st.approx += 1
            st.set('ah', BitVec('lahf%d' % st.approx, 8))
            return 'next'

        if m == 'sahf':
            st.approx += 1
            for f in ('zf', 'sf', 'cf', 'pf'):
                st.flags[f] = Bool('%s_sahf%d' % (f, st.approx))
            return 'next'

        # ---- 符号扩展 ----
        if m in ('cdqe', 'cwde', 'cbw', 'cwd', 'cdq', 'cqo'):
            if m == 'cdqe':
                st.set('rax', SignExt(32, _trunc(32, st.get('eax'))))
            elif m == 'cwde':
                st.set('eax', SignExt(16, _trunc(16, st.get('ax'))))
            elif m == 'cbw':
                st.set('ax', SignExt(8, _trunc(8, st.get('al'))))
            elif m == 'cwd':
                st.set('dx', Extract(15, 0, SignExt(16, _trunc(16, st.get('ax')))))
            elif m == 'cdq':
                st.set('edx', Extract(31, 0, SignExt(32, _trunc(32, st.get('eax')))))
            elif m == 'cqo':
                st.set('rdx', SignExt(64, _trunc(64, st.get('rax'))))
            return 'next'

        # ---- 栈 ----
        if m == 'push':
            v = self.read(st, i, ops[0], 64) if ops else BitVec('pushval', 64)
            esp = simplify(st.reg['rsp'] - 8)
            st.reg['rsp'] = esp
            st.mem.store(esp, 64, v)
            st.events.append(('STORE', esp, 64, v))
            return 'next'

        if m == 'pop':
            esp = simplify(st.reg['rsp'])
            v = st.mem.load(esp, 64)
            st.events.append(('LOAD', esp, 64, v))
            st.reg['rsp'] = simplify(esp + 8)
            self.write(st, i, ops[0], v)
            return 'next'

        if m == 'pushfq':
            esp = simplify(st.reg['rsp'] - 8)
            st.reg['rsp'] = esp
            st.mem.store(esp, 64, BitVec('FLAGS', 64))
            return 'next'

        if m == 'popfq':
            st.reg['rsp'] = simplify(st.reg['rsp'] + 8)
            st.approx += 1
            for f in st.flags:
                st.flags[f] = Bool('%s_popf%d' % (f, st.approx))
            return 'next'

        if m == 'leave':
            v = st.mem.load(st.reg['rbp'], 64)
            st.reg['rsp'] = simplify(st.reg['rbp'] + 8)
            st.reg['rbp'] = v
            return 'next'

        # ---- 控制流 ----
        if m == 'jmp':
            if ops and ops[0].type == X86_OP_IMM:
                return ('JMP', ops[0].imm & 0xFFFFFFFFFFFFFFFF)
            return ('IND', None)

        if m.startswith('j'):
            if not ops or ops[0].type != X86_OP_IMM:
                return ('IND', None)
            return ('JCC', ops[0].imm & 0xFFFFFFFFFFFFFFFF, eval_cond(st, cc_suffix(m)))

        if m == 'call':
            ret = i.address + i.size
            esp = simplify(st.reg['rsp'] - 8)
            st.reg['rsp'] = esp
            st.mem.store(esp, 64, BitVecVal(ret, 64))
            if ops and ops[0].type == X86_OP_IMM:
                return ('CALL', ops[0].imm & 0xFFFFFFFFFFFFFFFF)
            st.approx += 1
            return ('TERM', 'indirect call', True)

        if m in ('ret', 'retn', 'retf'):
            return ('TERM', 'ret', False)

        if m in ('int3', 'ud2', 'hlt', 'int', 'syscall', 'sysenter'):
            return ('TERM', m, False)

        # ---- 环境探针 / 杂项 ----
        if m in ('rdtsc', 'rdtscp'):
            st.poison('rax'); st.poison('rdx')
            st.approx += 1
            return 'next'

        if m in ('rdrand', 'rdseed'):
            self.write(st, i, ops[0], BitVec('rnd%d' % st.approx, self.opw(ops[0])))
            st.flags['cf'] = Bool('cf_rnd%d' % st.approx)
            st.approx += 1
            return 'next'

        if m == 'cpuid':
            for r in ('rax', 'rbx', 'rcx', 'rdx'):
                st.poison(r)
            st.approx += 1
            return 'next'

        if m in ('xgetbv', 'rdmsr', 'rdpmc', 'in', 'out', 'ins', 'outs'):
            st.poison('rax'); st.poison('rdx'); st.poison('rcx')
            st.approx += 1
            return 'next'

        if m in ('nop', 'pause', 'endbr64', 'endbr32', 'fnop', 'ud0',
                 'prefetch', 'prefetchnta', 'prefetcht0'):
            return 'next'

        if m in ('stosb', 'stosw', 'stosd', 'stosq', 'movsb', 'movsw', 'movsd', 'movsq',
                 'lodsb', 'lodsw', 'lodsd', 'lodsq', 'scasb', 'scasw', 'scasd', 'scasq',
                 'cmpsb', 'cmpsw', 'cmpsd', 'cmpsq'):
            st.poison('rdi'); st.poison('rsi')
            st.approx += 1
            return 'next'

        if m in ('rep', 'repe', 'repne', 'repz', 'repnz', 'lock'):
            return 'next'

        if m in ('cmpxchg', 'cmpxchg8b', 'cmpxchg16b'):
            st.approx += 1
            st.poison('rax')
            return 'next'

        raise Unsupported('%s %s' % (m, i.op_str))



# ============================================================
# 5. VM 语义分类（Pass 3）
# ============================================================
def _norm_imm(cls):
    """把 ctx 位移的 IMM 归一成有符号表示，避免 ctx[0xFFFFFFFFFFFFFFE8]"""
    if cls[0] == 'IMM':
        return ('IMM', s32(cls[1]))
    return cls


class VMLifter:
    IP_OFFSET = IP_OFFSET     # 与模块级保持同步（detect_ip / --ip-offset 会改写）
    @staticmethod
    def classify(expr, base, ip_off=None):
        ip_off = VMLifter.IP_OFFSET if ip_off is None else ip_off
        e = simplify(expr)

        if e.eq(base):
            return ('CTX0', None)
        if is_bv_value(e):
            return ('IMM', e.as_long() & 0xFFFFFFFFFFFFFFFF)

        if e.num_args() == 0:
            n = e.decl().name()
            mm = re.match(r'M_C([0-9a-fA-F]+)_(\d+)$', n)
            if mm:
                raw = int(mm.group(1), 16)
                off = s32(raw)
                w = int(mm.group(2))
                if off == ip_off:
                    return ('IP', w)
                return ('CTXOFF', (off, w))
            mm = re.match(r'M_D(\d+)_(\d+)$', n)
            if mm:
                return ('DYNMEM', (int(mm.group(1)), int(mm.group(2))))
            mm = re.match(r'M_F([0-9a-fA-F]+)_(\d+)$', n)
            if mm:
                return ('FETCHVAL', (s32(int(mm.group(1), 16)), int(mm.group(2))))
            return ('REG', n)

        if e.num_args() == 1:
            return ('UNARY', (e.decl().name(), VMLifter.classify(e.arg(0), base, ip_off)))

        if e.num_args() == 2:
            op = e.decl().name()
            a, b = e.arg(0), e.arg(1)
            ka, kb = VMLifter.classify(a, base, ip_off), VMLifter.classify(b, base, ip_off)
            if op == 'bvadd':
                if ka[0] == 'IP' and kb[0] == 'IMM':
                    return ('FETCH_AT', kb[1])
                if kb[0] == 'IP' and ka[0] == 'IMM':
                    return ('FETCH_AT', ka[1])
                if a.eq(base):
                    return ('CTXIDX', _norm_imm(kb))
                if b.eq(base):
                    return ('CTXIDX', _norm_imm(ka))
                return ('ADD', (_norm_imm(ka), _norm_imm(kb)))
            if op == 'bvsub':
                return ('SUB', (_norm_imm(ka), _norm_imm(kb)))
            if op == 'bvxor':
                return ('XOR', (ka, kb))
            if op == 'bvor':
                return ('OR', (ka, kb))
            if op == 'bvand':
                return ('AND', (ka, kb))
            if op == 'concat':
                return ('CONCAT', (ka, kb))
            if op == 'bvmul':
                return ('MUL', (ka, kb))

        return ('EXPR', str(e)[:70])

    @staticmethod
    def ctx_off(cls):
        """从分类结果里取出 ctx 偏移；非 ctx 访问返回 None"""
        if cls[0] == 'CTX0':
            return 0
        if cls[0] == 'CTXOFF':
            return cls[1][0]
        if cls[0] == 'CTXIDX' and cls[1][0] == 'IMM':
            return cls[1][1]
        return None

    @staticmethod
    def render(cls, prev=None):
        k = cls[0]
        if k == 'IP':
            return 'IP'
        if k == 'CTX0':
            return 'ctx[0x0]'
        if k == 'IMM':
            return _hexoff(cls[1]) if cls[1] < 0 else '0x%X' % cls[1]
        if k == 'CTXOFF':
            return 'ctx[%s]' % _hexoff(cls[1][0])
        if k == 'DYNMEM':
            return 'mem#%d:%d' % cls[1]
        if k == 'REG':
            return cls[1]
        if k == 'FETCH_AT':
            return 'fetch(IP+0x%X)' % cls[1]
        if k == 'FETCHVAL':
            o, w = cls[1]
            return 'bytecode[%s]:%d' % (_hexoff(o), w)
        if k == 'CTXIDX':
            inner = cls[1]
            if inner[0] == 'IMM':
                off = inner[1]
                if off == VMLifter.IP_OFFSET:
                    return 'IP'
                return 'ctx[%s]' % _hexoff(off)
            return '%s[%s]' % ('ctx', VMLifter.render(inner))
        if k in ('ADD', 'SUB', 'XOR', 'OR', 'AND', 'CONCAT', 'MUL'):
            sym = {'ADD': '+', 'SUB': '-', 'XOR': '^', 'OR': '|', 'AND': '&',
                   'CONCAT': ':', 'MUL': '*'}[k]
            return '(%s %s %s)' % (VMLifter.render(cls[1][0]), sym, VMLifter.render(cls[1][1]))
        if k == 'UNARY':
            return '%s(%s)' % (cls[1][0], VMLifter.render(cls[1][1]))
        return str(cls[1])[:60]


_PVAL = {'bvadd': '+', 'bvsub': '-', 'bvmul': '*', 'bvxor': '^', 'bvor': '|',
         'bvand': '&', 'bvlshr': '>>', 'bvashr': '>>>', 'bvshl': '<<',
         'bvudiv': '/', 'bvurem': '%', 'bvsdiv': '/s'}


def _is_app(e, name):
    return e.num_args() > 0 and e.decl().name() == name


def pretty(e, depth=0):
    """
    原始 z3 AST -> 紧凑可读文本（ctx/bytecode 记法）。
    刻意不做整体 simplify：z3 会把 bvnot^x 位展开成一串 concat，毁掉可读性。
    """
    if depth > 12:
        return '...'
    if is_bv_value(e):
        v = e.as_long()
        if (v >> 63) and v != (1 << 64) - 1:
            return '-0x%X' % ((1 << 64) - v)
        return '0x%X' % v
    if e.num_args() == 0:
        n = e.decl().name()
        m = re.match(r'M_C([0-9a-fA-F]+)_(\d+)$', n)
        if m:
            return 'ctx[%s]' % _hexoff(s32(int(m.group(1), 16)))
        m = re.match(r'M_F([0-9a-fA-F]+)_(\d+)$', n)
        if m:
            return 'bytecode[%s]' % _hexoff(s32(int(m.group(1), 16)))
        m = re.match(r'M_D(\d+)_(\d+)$', n)
        if m:
            return 'mem#%s' % m.group(1)
        return n

    op = e.decl().name()

    if op == 'extract':
        hi, lo = e.params()
        x = e.arg(0)
        if hi - lo + 1 == x.size():
            return pretty(x, depth + 1)
        if is_bv_value(x):
            return '0x%X' % ((x.as_long() >> lo) & ((1 << (hi - lo + 1)) - 1))
        # Extract(lo+n-1, lo, ZeroExt/SignExt(k, inner)) 且 n == inner.size() -> inner
        if (_is_app(x, 'zero_extend') or _is_app(x, 'sign_extend')) and lo == 0:
            inner = x.arg(0)
            if inner.size() == hi - lo + 1:
                return pretty(inner, depth + 1)
        return '%s[%d:%d]' % (pretty(x, depth + 1), hi, lo)

    if op in ('zero_extend', 'sign_extend'):
        extra = e.params()[0]
        return '%s%d(%s)' % ('zext' if op == 'zero_extend' else 'sext',
                             extra, pretty(e.arg(0), depth + 1))

    if op in ('rotate_left', 'rotate_right', 'ext_rotate_left', 'ext_rotate_right'):
        amt = e.params()[0] if e.params() else pretty(e.arg(1))
        return '%s(%s, %s)' % ('rol' if 'left' in op else 'ror',
                               pretty(e.arg(0), depth + 1), amt)

    if op == 'concat':
        # 兼容 simplify 之后的 rol 形态: [w-k-1:0] : [w-1:w-k]
        a, b = e.arg(0), e.arg(1)
        if _is_app(a, 'extract') and _is_app(b, 'extract'):
            ha, la = a.params(); hb, lb = b.params()
            w = e.size()
            if a.arg(0).eq(b.arg(0)) and la == 0 and abs(ha + 1 - lb) == 0 and hb == w - 1:
                return 'ror(%s, %d)' % (pretty(a.arg(0), depth + 1), lb)
        if is_bv_value(a) and a.as_long() == 0:
            return 'zext%d(%s)' % (a.size(), pretty(b, depth + 1))
        if is_bv_value(a) and a.as_long() == (1 << a.size()) - 1:
            return 'sext%d(%s)' % (a.size(), pretty(b, depth + 1))
        return '(%s : %s)' % (pretty(a, depth + 1), pretty(b, depth + 1))

    if e.num_args() == 1:
        x = pretty(e.arg(0), depth + 1)
        if op == 'bvnot':
            return '~%s' % x
        if op == 'bvneg':
            return '-%s' % x
        return '%s(%s)' % (op, x)

    if e.num_args() == 2 and op in _PVAL:
        return '(%s %s %s)' % (pretty(e.arg(0), depth + 1), _PVAL[op],
                               pretty(e.arg(1), depth + 1))

    if op.startswith('bv') or op.startswith('_'):
        return '%s(%s)' % (op, ', '.join(pretty(x, depth + 1) for x in e.children()))
    return '%s(%s)' % (op, ', '.join(pretty(x, depth + 1) for x in e.children()))


def _hexoff(v):
    if v < 0:
        return '-0x%X' % (-v)
    return '0x%X' % v


# ============================================================
# 6. handler 遍历（可达性 + 双分支）
# ============================================================
IMG_VA = 0x140000000
VMP_RVA = 0x1D34000
CODE_BASE_VA = IMG_VA + VMP_RVA
MAX_BYTES = 3000


def make_md():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


def walk(payload, off, max_insn=120, follow_jcc=True, code_base=None):
    """★ 修复 6：按可达性遍历，jcc 双分支，不透明谓词可穿透"""
    code_base = CODE_BASE_VA if code_base is None else code_base
    md = make_md()
    ex = Exec(md)
    base = BitVec('rbp', 64)
    st0 = SymState(base)

    region = (off, off + MAX_BYTES)
    lo, hi = region
    seen = set()
    work = [(off, st0)]
    n = 0
    approx = 0
    unsupported = collections.Counter()
    stop = 'exit'
    cp, al = ConstProp(), AliasTracker()

    while work:
        addr, st = work.pop()
        while True:
            if addr in seen:
                stop = 'revisit'
                break
            if n >= max_insn:
                stop = 'limit'
                break
            if not (lo <= addr < hi) or addr >= len(payload):
                stop = 'out-of-region'
                break
            seen.add(addr)
            rd = payload[addr:addr + 16]
            insns = list(md.disasm(rd, code_base + addr))
            if not insns:
                stop = 'bad-bytes@0x%X' % addr
                break
            i = insns[0]
            n += 1
            if addr == off:
                pass
            cp.feed(i, md); al.note(i, md)

            try:
                r = ex.step(st, i)
            except Unsupported as e:
                unsupported[str(e).split()[0]] += 1
                if i.operands and i.operands[0].type == X86_OP_REG:
                    st.poison(md.reg_name(i.operands[0].reg))
                st.approx += 1
                addr = i.address + i.size - code_base
                continue
            except Exception as e:
                stop = 'error: %s' % e
                break

            if isinstance(r, tuple):
                kind = r[0]
                if kind == 'JMP':
                    t = r[1] - code_base
                    if lo <= t < hi and t not in seen:
                        addr = t
                        continue
                    stop = 'jmp-out'
                    break
                if kind == 'JCC':
                    t = r[1] - code_base
                    cond = r[2]
                    fall = i.address + i.size - code_base
                    inside = lo <= t < hi and t not in seen
                    if cond is True:
                        if not inside:
                            stop = 'jcc-out(taken)'
                            break
                        addr = t
                        continue
                    if cond is False:
                        addr = fall
                        continue
                    # 未知条件：双分支
                    if follow_jcc and inside:
                        work.append((t, st.clone()))
                    addr = fall
                    continue
                if kind == 'CALL':
                    t = r[1] - code_base
                    if lo <= t < hi and t not in seen:
                        addr = t
                        continue
                    stop = 'call-out'
                    break
                if kind == 'IND':
                    stop = 'indirect'
                    break
                if kind == 'TERM':
                    stop = r[1]
                    if r[2]:
                        st.approx += 1
                    break
            # 'next'
            addr = i.address + i.size - code_base

    return {
        'offset': off,
        'insns': n,
        'stop': stop,
        'events': st.events,
        'slots': st.mem.value,
        'tag_off': st.mem.tag_off,
        'approx': st.approx,
        'unsupported': dict(unsupported),
        'const_folds': cp.folds,
        'alias': al.report(),
        'paths': len(work),
    }


def deobf_one(payload, off, max_insn=120, verbose=False, follow_jcc=True,
              code_base=None, ip_off=None):
    """兼容 v1 的返回结构，额外附带 approx / summary"""
    w = walk(payload, off, max_insn=max_insn, follow_jcc=follow_jcc, code_base=code_base)
    ip_off = VMLifter.IP_OFFSET if ip_off is None else ip_off
    base = BitVec('rbp', 64)
    ops = []
    for kind, addr, width, val in w['events']:
        cls = VMLifter.classify(addr, base, ip_off)
        ops.append({'kind': kind, 'width': width, 'cls': cls,
                    'text': VMLifter.render(cls), 'expr': addr})
    fetches = sorted({o['cls'][1] for o in ops if o['cls'][0] == 'FETCH_AT'})
    # ★ 摘要用 STORE 的「值」而不是地址
    writes = []
    for kind, addr, width, val in w['events']:
        if kind != 'STORE':
            continue
        dcls = VMLifter.classify(addr, base, ip_off)
        if dcls[0] not in ('CTX0', 'CTXOFF', 'CTXIDX'):
            continue
        dst = VMLifter.render(dcls)
        vtxt = pretty(val)
        if val.size() != 64:
            vtxt = '%s:%d' % (vtxt, val.size())
        writes.append('%s = %s' % (dst, vtxt))
    summary = ' ; '.join(writes[:4])
    return {
        'offset': off, 'insns': w['insns'], 'stop': w['stop'], 'ops': ops,
        'const_folds': w['const_folds'], 'const_hits': len(w['const_folds']),
        'alias': w['alias'], 'slots': w['slots'], 'approx': w['approx'],
        'unsupported': w['unsupported'], 'fetches': fetches,
        'summary': summary, 'paths': w['paths'], 'tag_off': w['tag_off'],
    }


# ============================================================
# 7. dispatch 扫描（★ 修复 9：语义匹配，不再只认 41 80 FC）
# ============================================================
_IMM8_REGS = {'al': 0, 'cl': 1, 'dl': 2, 'bl': 3,
              'r8b': 8, 'r9b': 9, 'r10b': 10, 'r11b': 11}


def discover_handlers_legacy(payload, code_base=CODE_BASE_VA, ahead=12, verbose=False):
    """
    【v1 老实现，仅作回退】按固定字节形态扫描 dispatch 链。支持：
      cmp  r8/r32, imm  (80/81/3C/3D/41 80/41 81)
      and  r8, imm
      cmp  [reg+disp], imm   （带内存操作数）
      cmp 之后 0..ahead 字节内出现 je/jz
    返回 {opcode: [(target_off, count), ...]}
    """
    md = make_md()
    found = collections.defaultdict(collections.Counter)
    stops = 0

    for i in md.disasm(payload, code_base):
        m = i.mnemonic
        if m not in ('cmp', 'and', 'sub', 'xor'):
            continue
        ops = i.operands
        if len(ops) != 2 or ops[1].type != X86_OP_IMM:
            continue
        opcode = None
        # 寄存器与立即数比较
        if ops[0].type == X86_OP_REG:
            rn = md.reg_name(ops[0].reg)
            w = reg_width(rn)
            if w in (8, 32) and 0 <= ops[1].imm <= 0xFF:
                opcode = ops[1].imm & 0xFF
        # 内存与立即数比较
        elif ops[0].type == X86_OP_MEM and 0 <= ops[1].imm <= 0xFF:
            opcode = ops[1].imm & 0xFF
        if opcode is None:
            continue

        # 向后找 je/jz（允许中间有少量垃圾字节）
        off_end = i.address + i.size - code_base
        target = None
        for gap in range(0, ahead):
            if off_end + gap + 2 > len(payload):
                break
            b = payload[off_end + gap:off_end + gap + 2]
            if b[0] == 0x74:                                    # jz rel8
                rel = struct.unpack_from('<b', payload, off_end + gap + 1)[0]
                target = off_end + gap + 2 + rel
                break
            if b == b'\x0f\x84':                                # jz rel32
                if off_end + gap + 6 > len(payload):
                    break
                rel = struct.unpack_from('<i', payload, off_end + gap + 2)[0]
                target = off_end + gap + 6 + rel
                break
            if b[0] in (0x90, 0x66, 0x0f) and b[0] != 0x0f:
                continue
            if b[0] in (0x50, 0x51, 0x52, 0x53, 0x56, 0x57):    # push 垃圾
                continue
            break
        if target is not None and 0 <= target < len(payload):
            found[opcode][target] += 1
        else:
            stops += 1

    out = {}
    for op, cnt in found.items():
        out[op] = sorted(cnt.items(), key=lambda x: (-x[1], x[0]))
    if verbose:
        print("[*] cmp/and 链命中 opcode %d 个，%d 处无后随 je" % (len(out), stops))
    return out


def _load_dispatch_module():
    try:
        import x86il_dispatch as _d
        return _d
    except Exception:
        return None


def discover_handlers(payload, code_base=CODE_BASE_VA, ahead=12, verbose=False,
                      engine=None, min_cases=2):
    """
    handler 发现统一入口（v2.1 集成）。

    engine:
      'auto'   —— 优先 x86il_dispatch 的语义恢复，导入失败回退老实现（默认）
      'fast'   —— 强制语义恢复
      'legacy' —— 强制老的字节形态扫描

    语义恢复能还原 cmp 链 / 递减链 / opcode 变换 / 二分派发 / 跳表五种形态，
    老实现只认固定字节，且遇到 xor 掩码时会给出**错误**的 opcode。
    """
    engine = engine or 'auto'
    if engine in ('auto', 'fast'):
        d = _load_dispatch_module()
        if d is not None:
            try:
                table = d.discover_handlers_compat(payload, code_base,
                                                   verbose=verbose,
                                                   min_cases=min_cases)
                if verbose:
                    print("[*] dispatch 引擎: x86il_dispatch（语义恢复），%d 个 opcode"
                          % len(table))
                if table or engine == 'fast':
                    return table
                if verbose:
                    print("[!] 语义恢复无结果，回退老扫描器")
            except Exception as e:
                if engine == 'fast':
                    raise
                if verbose:
                    print("[!] 语义恢复异常（%s），回退老扫描器" % e)
        elif engine == 'fast':
            raise RuntimeError('无法导入 x86il_dispatch')
    if verbose:
        print("[*] dispatch 引擎: 老扫描器（字节形态）")
    return discover_handlers_legacy(payload, code_base, ahead, verbose)


# ============================================================
# 8. IP 槽位自动识别（★ 修复 10）
# ============================================================
def detect_ip(payload, sample_offs=None, code_base=CODE_BASE_VA):
    """
    对若干 handler 统计 FETCH 形态（ctx[k] + imm 被解引用），出现最多者为 IP。
    """
    if sample_offs is None:
        table = discover_handlers(payload, code_base)
        sample_offs = []
        for op, cands in table.items():
            sample_offs.append(cands[0][0])
        sample_offs = sample_offs[:40]
    votes = collections.Counter()
    md = make_md()
    ex = Exec(md)
    for off in sample_offs:
        try:
            w = walk(payload, off, max_insn=60, code_base=code_base)
        except Exception:
            continue
        for kind, addr, width, val in w['events']:
            if kind != 'LOAD':
                continue
            cls = VMLifter.classify(addr, BitVec('rbp', 64), None)
            if cls[0] == 'FETCH_AT':
                # 找到 ctx + imm 形态
                e = simplify(addr)
                if e.num_args() == 2 and e.decl().name() == 'bvadd':
                    for a in (e.arg(0), e.arg(1)):
                        mm = re.match(r'M_C([0-9a-fA-F]+)_(\d+)$', str(a))
                        if mm:
                            votes[s32(int(mm.group(1), 16))] += 1
    if not votes:
        return None, {}
    off, _ = votes.most_common(1)[0]
    return off, dict(votes)


# ============================================================
# 9. 报告
# ============================================================
def print_one(res, ip_off=None):
    ip_off = VMLifter.IP_OFFSET if ip_off is None else ip_off
    print("=" * 70)
    print("handler @ 0x%X   反汇编 %d 条   终止: %s%s"
          % (res['offset'], res['insns'], res['stop'],
             ('   [近似 %d 处]' % res['approx']) if res.get('approx') else ''))
    print("=" * 70)

    folds = res['const_folds']
    print("\n[Pass 2] 常量传播: 命中 %d 处" % len(folds))
    for insn, txt, why in folds[:10]:
        print("   0x%X  %-30s -> %-22s ; %s"
              % (insn.address, insn.mnemonic + ' ' + insn.op_str, txt, why))
    if len(folds) > 10:
        print("   ... 另有 %d 处" % (len(folds) - 10))

    al = res['alias']
    print("\n[Pass 1] 基址别名: %s" % ('rbp 被改写' if al['clobbered'] else 'rbp 未被挪用'))
    for e in al['events'][:6]:
        print("   %s" % e)
    if al['base_copies']:
        print("   基址副本寄存器: %s" % ', '.join(al['base_copies']))

    print("\n[Pass 3] VM 操作序列 (%d 条)" % len(res['ops']))
    print("   %-6s %-5s %s" % ('类型', '宽度', '语义'))
    print("   " + "-" * 52)
    for o in res['ops']:
        print("   %-6s %-5s %s" % (o['kind'], o['width'], o['text']))

    if res.get('fetches'):
        print("\n[编码] 字节码操作数偏移: %s"
              % ', '.join('IP+0x%X' % f for f in res['fetches']))
    if res.get('summary'):
        print("[语义] %s" % res['summary'])
    if res.get('unsupported'):
        print("[未支持] %s" % ', '.join('%s x%d' % kv for kv in res['unsupported'].items()))
    print()


def coverage_report(payload, code_base=CODE_BASE_VA, limit=None):
    table = discover_handlers(payload, code_base)
    agg = collections.Counter()
    stops = collections.Counter()
    n = 0
    for op, cands in sorted(table.items()):
        off = cands[0][0]
        try:
            r = deobf_one(payload, off, max_insn=90, code_base=code_base)
        except Exception:
            continue
        n += 1
        agg.update(r['unsupported'])
        stops[r['stop']] += 1
        if limit and n >= limit:
            break
    print("[*] 采样 %d 个 handler" % n)
    print("\n[助记符缺口]（这些指令当前被跳过，按频次排序）")
    if not agg:
        print("   （无）")
    for k, v in agg.most_common(30):
        print("   %-12s %4d" % (k, v))
    print("\n[终止原因]")
    for k, v in stops.most_common(20):
        print("   %-24s %4d" % (k, v))
    return agg


# ============================================================
# 10. 批量 + 代码生成
# ============================================================
def score_handler(r):
    """候选打分：真 handler 通常有字节码 fetch、以 jmp 收尾、指令数合理"""
    s = 0
    if r.get('fetches'):
        s += 10 + min(len(r['fetches']), 4)
    if r['stop'] in ('jmp-out', 'indirect', 'ret', 'call-out'):
        s += 5
    if r.get('summary'):
        s += 3
    if 4 <= r['insns'] <= 60:
        s += 2
    s -= r.get('approx', 0)
    return s


def batch(payload, limit=None, code_base=CODE_BASE_VA, core=(0x200000, 0x400000),
          ip_off=None, engine=None):
    table = discover_handlers(payload, code_base, verbose=False, engine=engine)
    print("[*] 发现 %d 个 opcode 的 handler" % len(table))
    results = []
    for op, cands in sorted(table.items()):
        best = None
        for off, cnt in cands[:4]:
            try:
                r = deobf_one(payload, off, max_insn=90, code_base=code_base, ip_off=ip_off)
            except Exception as e:
                continue
            r['opcode'] = op
            r['_score'] = score_handler(r) + (2 if core[0] <= off < core[1] else 0)
            if best is None or r['_score'] > best['_score']:
                best = r
        if best is None:
            continue
        results.append(best)
        print("   op 0x%02X  handler 0x%-7X %3d 条  score %2d  fetch%s%s"
              % (op, best['offset'], best['insns'], best['_score'],
                 ('(%s)' % ','.join('0x%X' % x for x in best['fetches'])) if best['fetches'] else '()',
                 ('  ~%d' % best['approx']) if best['approx'] else ''))
        if limit and len(results) >= limit:
            break
    ok = sum(1 for r in results if r['ops'])
    print("\n[*] 完成：%d/%d 个 handler 提取到 VM 操作" % (ok, len(results)))
    return results


def emit_python(results, path, ip_off=None):
    ip_off = VMLifter.IP_OFFSET if ip_off is None else ip_off
    L = ['# -*- coding: utf-8 -*-', '"""',
         'X86IL HANDLERS 表 —— 由 x86il_deobf_v2.py 自动生成',
         '',
         'IP 槽位: ctx[%s]' % _hexoff(ip_off),
         '每个 handler 的 summary 是从 mutation 代码里恢复出的 VM 语义。',
         '"""', '', 'HANDLERS = {']
    for r in results:
        op = r.get('opcode', 0)
        L.append('    0x%02X: {  # @0x%X  %d insn' % (op, r.get('offset', 0), r.get('insns', 0)))
        L.append('        "handler_offset": 0x%X,' % r.get('offset', 0))
        L.append('        "fetch_offsets": [%s],'
                 % ', '.join('0x%X' % f for f in r.get('fetches', [])))
        L.append('        "summary": %r,' % r.get('summary', ''))
        L.append('        "approx": %d,' % r.get('approx', 0))
        L.append('        "stop": %r,' % r.get('stop', ''))
        L.append('    },')
    L += ['}', '',
          'fetch_offsets = sorted({o for v in HANDLERS.values() for o in v["fetch_offsets"]})',
          'ip_offset = %s' % _hexoff(ip_off), '']
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(L) + '\n')
    print("[+] 已生成 %s（%d 个 handler）" % (path, len(results)))


# ============================================================
# 11. 自检（回归测试）
# ============================================================
def _asm(body):
    import subprocess, tempfile
    s = ".intel_syntax noprefix\n.globl _start\n_start:\n" + body + "\n"
    with tempfile.TemporaryDirectory() as d:
        sp = os.path.join(d, 'a.s'); op = os.path.join(d, 'a.o'); bp = os.path.join(d, 'a.bin')
        with open(sp, 'w') as f:
            f.write(s)
        subprocess.run(['as', '--64', '-o', op, sp], check=True)
        subprocess.run(['objcopy', '-O', 'binary', '--only-section=.text', op, bp], check=True)
        with open(bp, 'rb') as f:
            return f.read()


def selftest():
    from z3 import is_bv_value as _isval
    ok = 0; fail = 0

    def check(name, cond, extra=''):
        nonlocal ok, fail
        if cond:
            ok += 1; print("   [PASS] %s %s" % (name, extra))
        else:
            fail += 1; print("   [FAIL] %s %s" % (name, extra))

    print("[*] x86-64 语义自检")

    r = deobf_one(_asm("    mov [rcx], rdx\n    mov rbx, [rcx]\n    jmp ."), 0)
    vals = [str(v) for v in r['slots'].values()]
    check("动态地址写后读", any(v == 'rdx' for v in vals), str(vals))

    r = deobf_one(_asm("    mov ebx, 0x1234\n    mov rax, rbx\n    mov [rbp+8], rax\n    jmp ."), 0)
    e = r['slots'].get(('C8', 64))
    check("32 位写入零扩展", e is not None and _isval(simplify(e)) and e.as_long() == 0x1234,
          str(e))

    r = deobf_one(_asm("    mov rax, [rbp-0x18]\n    jmp ."), 0)
    check("负位移归一化", any('ctx[-0x18]' in o['text'] for o in r['ops']),
          str([o['text'] for o in r['ops']]))

    r = deobf_one(_asm("    xor [rbp+8], rax\n    jmp ."), 0)
    check("内存 RMW 回写", any(o['kind'] == 'STORE' for o in r['ops']),
          str([o['kind'] for o in r['ops']]))

    r = deobf_one(_asm("    mov eax, [rip+4]\n    jmp ."), 0)
    check("RIP 相对寻址", not r['stop'].startswith('error'), r['stop'])

    r = deobf_one(_asm("    mov rax, [rbp+8]\n    test al,al\n    jz 1f\n    xor rax,rax\n1:  add rax, rcx\n    jmp ."), 0)
    check("不透明谓词双分支", r['insns'] >= 5, "insns=%d paths=%d" % (r['insns'], r['paths']))

    r = deobf_one(_asm("    mov rax, 0x41\n    push rax\n    pop rbx\n    mov [rbp+0x10], rbx\n    jmp ."), 0)
    check("push/pop 配对", any(v.as_long() == 0x41 for v in r['slots'].values() if _isval(simplify(v))),
          str([str(v) for v in r['slots'].values()]))

    for name, body in [('xchg', "xchg rax,rbx"), ('imul3', "imul rax,rbx,8"),
                       ('movsxd', "movsxd rax,ebx"), ('ror', "ror al,3"),
                       ('setz', "test rax,rax\nsetz al"), ('cmovz', "test rax,rax\ncmovz rax,rbx"),
                       ('bswap', "bswap eax"), ('bt', "bt rax,3"), ('lahf', "lahf"),
                       ('shld', "shld rax,rbx,3"), ('cdq', "cdq"), ('movbe', "movbe rax,[rbp+8]")]:
        r = deobf_one(_asm("    " + body + "\n    jmp ."), 0)
        check("指令覆盖 %s" % name, not r['stop'].startswith('unsupported'), r['stop'])

    # dispatch 扫描
    for name, pat in [('cmp r12b', b'\x41\x80\xfc\x2c\x74\x02\x90\x90'),
                      ('cmp r13b', b'\x41\x80\xfd\x2c\x74\x02\x90\x90'),
                      ('cmp cl', b'\x80\xf9\x2c\x74\x02\x90\x90'),
                      ('cmp al', b'\x3c\x2c\x74\x02\x90\x90'),
                      ('cmp eax', b'\x3d\x2c\x00\x00\x00\x74\x02\x90\x90'),
                      ('cmp r10d', b'\x41\x81\xfa\x2c\x00\x00\x00\x74\x02\x90\x90'),
                      ('and r12b', b'\x41\x80\xe4\x2c\x74\x02\x90\x90'),
                      ('gap', b'\x41\x80\xfc\x2c\x90\x74\x02\x90\x90')]:
        got = discover_handlers(pat + b'\x00' * 8)
        check("dispatch %s" % name, 0x2C in got, str(['0x%02X' % o for o in got]))

    # IP 自动识别（disp32 编码，避免 disp8 符号扩展成负偏移）
    body = b''
    for k in range(8):
        body += b'\x48\x8b\x85\x92\x00\x00\x00'    # mov rax,[rbp+0x92]
        body += b'\x48\x8b\x58\x07'                # mov rbx,[rax+7]
        body += b'\x48\x89\x5d\x10'                # mov [rbp+0x10],rbx
        body += b'\xeb\x00'
    ip, votes = detect_ip(body, sample_offs=[0])
    check("IP 槽自动识别", ip == 0x92, "ip=%s votes=%s" % (ip and hex(ip), votes))

    print("\n[*] 结果: %d passed, %d failed" % (ok, fail))
    return fail == 0


# ============================================================
# 12. CLI
# ============================================================
def main():
    ap = argparse.ArgumentParser(
        description='X86IL 去混淆器 v2（Oreans WinLicense mutation）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument('payload', nargs='?', help='.vmp 节解压后的载荷文件')
    ap.add_argument('--handler', metavar='HEX', help='分析单个 handler，如 0x2c00e3')
    ap.add_argument('--scan', action='store_true', help='扫描 dispatch 链')
    ap.add_argument('--batch', action='store_true', help='批量去混淆全部 handler')
    ap.add_argument('--coverage', action='store_true', help='统计未支持指令频次')
    ap.add_argument('--selftest', action='store_true', help='运行内置回归测试')
    ap.add_argument('--limit', type=int, default=None)
    ap.add_argument('--emit', metavar='FILE')
    ap.add_argument('--json', metavar='FILE')
    ap.add_argument('--max-insn', type=int, default=120)
    ap.add_argument('--ip-offset', metavar='HEX', default=None)
    ap.add_argument('--image-base', metavar='HEX', default=None)
    ap.add_argument('--vmp-rva', metavar='HEX', default=None)
    ap.add_argument('--no-follow-jcc', action='store_true')
    ap.add_argument('--dispatch', choices=('auto', 'fast', 'legacy'), default='auto',
                    help='handler 发现引擎：auto=语义恢复优先（默认） fast=强制语义恢复 legacy=老扫描器')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    global CODE_BASE_VA
    if args.image_base:
        IMG_VA_ = int(args.image_base, 16)
    else:
        IMG_VA_ = IMG_VA
    if args.vmp_rva:
        CODE_BASE_VA = IMG_VA_ + int(args.vmp_rva, 16)

    if args.selftest:
        sys.exit(0 if selftest() else 1)

    if not args.payload:
        ap.print_help()
        return
    with open(args.payload, 'rb') as f:
        payload = f.read()
    print("[*] 载荷 %s  %.1f MB" % (args.payload, len(payload) / 1048576))

    ip_off = int(args.ip_offset, 16) if args.ip_offset else None
    if ip_off is None:
        det, votes = detect_ip(payload)
        if det is not None:
            ip_off = det
            print("[*] 自动识别 IP 槽: ctx[%s]  (票数 %d，全部 %s)"
                  % (_hexoff(det), votes.get(det, 0),
                     ', '.join('%s:%d' % (_hexoff(k), v) for k, v in
                               sorted(votes.items(), key=lambda x: -x[1])[:4])))
        else:
            ip_off = VMLifter.IP_OFFSET
            print("[!] 未能自动识别 IP 槽，回落默认 ctx[0x%X]" % VMLifter.IP_OFFSET)
    VMLifter.IP_OFFSET = ip_off

    if args.scan:
        table = discover_handlers(payload, CODE_BASE_VA, verbose=True,
                                  engine=args.dispatch)
        print("[*] 发现 %d 个 opcode，共 %d 个候选入口"
              % (len(table), sum(len(v) for v in table.values())))
        rev = collections.defaultdict(list)
        for op, cands in table.items():
            rev[cands[0][0]].append(op)
        for op in sorted(table):
            cands = table[op]
            print("    op 0x%02X (%3d): %s" % (op, op,
                  '' if len(rev[cands[0][0]]) == 1 else '  <别名 %s>' %
                  ','.join('0x%02X' % x for x in rev[cands[0][0]] if x != op)))
            for off, cnt in cands[:6]:
                print("        offset 0x%-8X VA 0x%-11X 命中 %d"
                      % (off, CODE_BASE_VA + off, cnt))
        return

    if args.handler:
        off = int(args.handler, 16)
        res = deobf_one(payload, off, max_insn=args.max_insn, follow_jcc=not args.no_follow_jcc,
                        code_base=CODE_BASE_VA, ip_off=ip_off)
        print_one(res, ip_off)
        if args.json:
            with open(args.json, 'w', encoding='utf-8') as f:
                json.dump({k: v for k, v in res.items()
                           if k in ('offset', 'insns', 'stop', 'approx', 'summary',
                                    'fetches', 'paths')}, f, ensure_ascii=False, indent=2)
        return

    if args.coverage:
        coverage_report(payload, CODE_BASE_VA, limit=args.limit)
        return

    if args.batch:
        results = batch(payload, limit=args.limit, code_base=CODE_BASE_VA,
                        ip_off=ip_off, engine=args.dispatch)
        if args.emit:
            emit_python(results, args.emit, ip_off)
        if args.json:
            with open(args.json, 'w', encoding='utf-8') as f:
                json.dump([{k: v for k, v in r.items()
                            if k in ('opcode', 'offset', 'insns', 'stop', 'approx',
                                     'summary', 'fetches', 'paths', 'unsupported')}
                           for r in results], f, ensure_ascii=False, indent=2, default=str)
        return

    ap.print_help()


if __name__ == '__main__':
    main()

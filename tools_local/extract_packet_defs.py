#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 vmp dump 提取每个 op 的派发器 packet 定义。
对给定 op→orig（来自 art23c 轨迹）：
  入口 jmp 链 → 主体 → 找 shl,3 派发器 → 回溯 next-op 的 u16 读（c1）
  → 收集读后到 shl 前对该寄存器的全部运算（解密链）
  → 找 movsxd i32 读（c2，rel）与 [rbp+0xBC] 写（IP 推进）。
输出 packet_defs.json。
"""
import re, json, sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

VBASE = 0x1419d4000
DUMP = open('/workspace/dgwork/out/vmp_unpacked_6201829.bin', 'rb').read()
END = VBASE + len(DUMP)
MD = Cs(CS_ARCH_X86, CS_MODE_64)


def disasm_block(va, maxn=600):
    off = va - VBASE
    out = []
    for i in MD.disasm(DUMP[off:off + maxn * 12], va):
        out.append((i.address, i.mnemonic, i.op_str, i.size))
        if len(out) >= maxn:
            break
    return out


def follow_chain(va):
    chain = [va]
    while True:
        if not (VBASE <= va < END):
            return chain, None
        off = va - VBASE
        i = next(MD.disasm(DUMP[off:off + 16], va), None)
        if i is None:
            return chain, None
        if i.mnemonic == 'jmp' and re.match(r'^0x[0-9a-f]+$', i.op_str):
            va = int(i.op_str, 16)
            if va in chain:
                return chain, None
            chain.append(va)
        else:
            return chain, va


def split2(s):
    a, _, b = s.partition(', ')
    return a.strip(), b.strip()


def regbase_of(op_str):
    """'word ptr [r11]' / '[r11 + 8]' -> (r11, disp)"""
    m = re.match(r'^(?:qword|dword|word|byte) ptr \[(\w+)(?: \+ (0x[0-9a-f]+|\d+))?\]$', op_str)
    if not m:
        m = re.match(r'^\[(\w+)(?: \+ (0x[0-9a-f]+|\d+))?\]$', op_str)
    if m:
        disp = int(m.group(2), 0) if m.group(2) else 0
        return m.group(1), disp
    return None, None


def extract_dispatcher(body):
    I = disasm_block(body)
    shl_idx = None
    for idx, (a, m, o, s) in enumerate(I):
        if m == 'shl' and o.endswith(', 3'):
            shl_idx = idx
            break
    if shl_idx is None:
        return None
    # 回溯找 movzx eX, word ptr [...]（next-op 读）
    read_at = None
    read_reg = None
    c1 = None
    for idx in range(shl_idx - 1, max(0, shl_idx - 30), -1):
        a, m, o, s = I[idx]
        if m in ('movzx', 'mov') and 'word ptr [' in o:
            dst, src = split2(o)
            base, disp = regbase_of(src)
            if base:
                # base 是否来自 [rbp+0xBC] 链：向前找
                ok = False
                for k in range(idx - 1, max(0, idx - 12), -1):
                    a2, m2, o2, s2 = I[k]
                    if m2 == 'mov' and o2.endswith(', qword ptr [rbp + 0xbc]'):
                        ok = True
                        break
                    if m2 == 'add' and split2(o2)[0] == base and split2(o2)[1] == 'rbp':
                        ok = True
                        break
                if ok:
                    read_at = idx
                    read_reg = dst
                    c1 = disp
                    break
    if read_at is None:
        return {'body': body, 'shl': I[shl_idx][0], 'c1': None, 'chain': [], 'c2': None}
    # 收集 read→shl 之间对 read_reg 的运算
    chain_ops = []
    reg = read_reg
    for idx in range(read_at + 1, shl_idx):
        a, m, o, s = I[idx]
        dst, src = split2(o)
        if dst == reg and m in ('xor', 'add', 'sub', 'and', 'or', 'shl', 'shr', 'imul'):
            if src.startswith('dword ptr [rbp') or src.startswith('word ptr [rbp') or src.startswith('qword ptr [rbp'):
                b2, d2 = regbase_of(src)
                chain_ops.append([m, 'ctx+%s' % hex(d2)])
            elif src == 'rbp':
                chain_ops.append([m, 'rbp'])
            else:
                try:
                    chain_ops.append([m, int(src, 0)])
                except ValueError:
                    chain_ops.append([m, src])
        elif dst == reg and m == 'mov' and src == reg:
            pass
        elif m == 'mov' and dst == reg and src.startswith('dword ptr [rbp'):
            b2, d2 = regbase_of(src)
            chain_ops.append(['mov', 'ctx+%s' % hex(d2)])
        elif m == 'imul' and dst == reg:
            chain_ops.append(['imul', src])
    # rel 读（movsxd dword [IP+c]）与 IP 写
    c2 = None
    for idx in range(shl_idx, min(shl_idx + 30, len(I))):
        a, m, o, s = I[idx]
        if m == 'movsxd':
            dst, src = split2(o)
            base, disp = regbase_of(src)
            if base:
                # 回溯 base 是否 = IP + disp
                for k in range(idx - 1, max(0, idx - 10), -1):
                    a2, m2, o2, s2 = I[k]
                    if m2 == 'add' and split2(o2)[0] == base:
                        extra = split2(o2)[1]
                        try:
                            disp += int(extra, 0)
                        except ValueError:
                            pass
                    if m2 == 'mov' and o2.endswith(', qword ptr [rbp + 0xbc]'):
                        c2 = disp
                        break
                if c2 is not None:
                    break
    return {'body': body, 'shl': I[shl_idx][0], 'c1': c1, 'chain': chain_ops, 'c2': c2}


def main():
    import collections
    tr = json.load(open('/workspace/dgwork/art23c/vm_trace.json'))
    t = tr['trace']
    op2orig = {}
    for e in t:
        op2orig.setdefault(e[3], e[5])
    defs = {}
    for op in sorted(op2orig):
        orig = op2orig[op]
        chain, body = follow_chain(orig)
        d = extract_dispatcher(body) if body else None
        if d:
            d['orig'] = orig
            d['entry_chain'] = [hex(x) for x in chain]
            defs[op] = d
            print('op %-4d orig=%#x body=%#x c1=%s c2=%s chain=%s'
                  % (op, orig, body, hex(d['c1']) if d['c1'] is not None else None,
                     hex(d['c2']) if d['c2'] is not None else None,
                     d['chain'][:6]))
        else:
            print('op %-4d orig=%#x body=%s 无派发器' % (op, orig, body))
    with open('/workspace/dgwork/out/sem/packet_defs.json', 'w') as f:
        json.dump({str(k): v for k, v in defs.items()}, f, indent=1)
    print('已写 packet_defs.json (%d ops)' % len(defs))


if __name__ == '__main__':
    main()

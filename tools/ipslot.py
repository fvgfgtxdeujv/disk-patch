# -*- coding: utf-8 -*-
"""
===============================================================
  ipslot.py —— VM 指令指针（IP 槽）自增惯用法恢复
===============================================================
DiskGenius 这份载荷的派发不是 cmp 链，而是每步处理末尾的：

    mov  rX, rbp            ; 或 lea rX, [rbp+imm]
    add  rX, <slot>         ; 计算 ctx + slot 的地址
    add  qword ptr [rX], rY ; ctx[slot] += <本步长度>   <- IP 推进
    jmp  rZ                 ; 寄存器间接跳到下一条

真实代码里这四条之间会插 junk 指令（实测 `and rdi,0x20` 就夹在中间），
所以不能按「连续四条」匹配，要用滑动窗口 + 寄存器一致性做状态机。

产出：
  - IP 槽偏移的分布（应当收敛到某个常数，这份载荷是 0x92）
  - 跳转寄存器分布
  - 每个站点的上下文（步长是从哪读进来的）

用法：
  python3 ipslot.py payload.bin
  python3 ipslot.py payload.bin --json ipslots.json
  python3 ipslot.py payload.bin --code-base 0x141D34000 --window 12
"""
import sys, os, re, json, argparse, collections

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

IMG_VA = 0x140000000
VMP_RVA = 0x1D34000
CODE_BASE_VA = IMG_VA + VMP_RVA

_W64 = set(['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp'] +
           ['r%d' % i for i in range(8, 16)])
_W64.add('eiz')      # 占位，避免误判


def _split2(s):
    a, sep, b = s.partition(', ')
    return (a, b) if sep else (None, None)


def _imm(s):
    if not s:
        return None
    t = s.strip()
    if not (t[0].isdigit() or t[0] in '+-'):
        return None
    try:
        return int(t, 0)
    except ValueError:
        return None


class Site:
    __slots__ = ('at', 'slot', 'ptr', 'step_reg', 'jmp_reg', 'seq', 'lensrc')

    def __init__(self, at, slot, ptr, step_reg, jmp_reg, seq):
        self.at = at
        self.slot = slot
        self.ptr = ptr
        self.step_reg = step_reg
        self.jmp_reg = jmp_reg
        self.seq = seq          # [(addr, mnemonic, op_str), ...] 站点附近的指令
        self.lensrc = None


def scan(payload, code_base=CODE_BASE_VA, window=12, verbose=False):
    """
    滑动窗口状态机。对每条 `jmp reg`，往前 window 条内找：
        add qword ptr [rX], rY     <- IP 推进
      且更前面有：
        add rX, imm  /  lea rX, [rbp+imm]   <- 槽地址
      且再前面有：
        mov rX, rbp
    """
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    md.skipdata = True

    win = collections.deque(maxlen=window * 3)
    sites = []
    n = 0
    for t in md.disasm_lite(payload, code_base):
        addr, size, mn, ostr = t
        win.append((addr, mn, ostr))
        n += 1
        if mn != 'jmp':
            continue
        jr = ostr.strip()
        if jr not in _W64:
            continue
        # 往前找 IP 推进
        k = len(win) - 2
        ip_idx = None
        ptr = step = None
        while k >= 0 and len(win) - 1 - k <= window:
            a2, m2, o2 = win[k]
            d2, s2 = _split2(o2)
            if m2 == 'add' and d2 and 'qword ptr [' in d2 and s2 and s2 in _W64:
                inner = d2[d2.index('[') + 1:d2.rindex(']')].strip()
                if inner in _W64:                 # 纯 [rX]，寄存器间接
                    ip_idx, ptr, step = k, inner, s2
                    break
            k -= 1
        if ip_idx is None:
            continue
        # 往前找槽地址计算
        slot = None
        k = ip_idx - 1
        while k >= 0 and ip_idx - k <= window:
            a2, m2, o2 = win[k]
            d2, s2 = _split2(o2)
            if d2 == ptr and s2 is not None:
                if m2 == 'add' and (imm := _imm(s2)) is not None:
                    slot = imm
                    break
                if m2 == 'lea' and 'rbp' in s2:
                    inner = s2[s2.index('[') + 1:s2.rindex(']')]
                    if 'rbp' in inner:
                        m = re.search(r'([+-]\s*0x[0-9a-fA-F]+)', inner)
                        slot = int(m.group(1).replace(' ', ''), 0) if m else None
                        if slot is not None:
                            break
            k -= 1
        if slot is None:
            continue
        # 再往前确认 ptr 来自 rbp
        base_ok = False
        k = ip_idx - 1
        while k >= 0 and ip_idx - k <= window:
            a2, m2, o2 = win[k]
            d2, s2 = _split2(o2)
            if m2 == 'mov' and d2 == ptr and s2 == 'rbp':
                base_ok = True
                break
            if m2 == 'lea' and d2 == ptr and s2 and 'rbp' in s2:
                base_ok = True
                break
            k -= 1
        if not base_ok:
            continue
        seq = list(win)[max(0, ip_idx - 2):]
        sites.append(Site(addr, slot, ptr, step, jr, seq))
        if verbose and len(sites) <= 5:
            print("[*] 站点 0x%X  slot=%s  ptr=%s  step=%s  jmp=%s"
                  % (addr, hex(slot), ptr, step, jr))
            for (a3, m3, o3) in list(win)[ip_idx - 2:]:
                print("      %08X  %-8s %s" % (a3, m3, o3))

    return {'sites': sites, 'insn': n,
            'skipped': 0}


def attach_len_source(payload, r, code_base=CODE_BASE_VA):
    """
    给每个站点找「步长是从哪来的」：step 寄存器在站点之前最近一次的写入形态。
    纯描述性统计，不做语义推演。
    """
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    md.skipdata = True
    sites = r['sites']
    hist = collections.Counter()
    if not sites:
        return hist

    by_addr = {}
    for s in sites:
        by_addr.setdefault(s.at, []).append(s)
    lo = min(by_addr) - 0x800
    hi = max(by_addr) + 0x10

    last_write = {}
    for t in md.disasm_lite(payload, code_base):
        addr, size, mn, ostr = t
        if addr > hi:
            break
        if addr < lo:
            if addr < lo - 0x2000:
                continue
        if addr in by_addr:
            for st in by_addr[addr]:
                st.lensrc = last_write.get(st.step_reg, '未知')
                hist[st.lensrc] += 1
        d, s2 = _split2(ostr)
        if d is None:
            d, s2 = ostr, None
        if mn in ('movsxd', 'mov', 'movzx', 'movsx', 'lea') and d in _W64 and s2:
            last_write[d] = '%s %s' % (mn, s2[:26])
    return hist


# ============================================================
# 表项派发分析：handler = table[opcode]
# ============================================================
def back_context(payload, addr, code_base=CODE_BASE_VA, back=120, maxinsn=36):
    """回溯解码：找一条指令序列，其结束地址正好是 addr（真实代码里 junk 会插队）"""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    best = None
    s0 = addr - code_base
    for s in range(max(1, s0 - back), s0):
        seq = []
        ok = False
        for i in md.disasm(payload[s:s0], code_base + s):
            seq.append((i.address, i.mnemonic, i.op_str))
            if i.address + i.size == addr:
                ok = True
                break
            if len(seq) > maxinsn:
                break
        if ok and (best is None or len(seq) >= len(best)):
            best = seq
    return best or []


def analyze_tables(payload, r, code_base=CODE_BASE_VA):
    """
    对每个 IP 槽站点，回看它的 jmp 寄存器是怎么来的。真实形态：

        and  r12, 0xffff        ; 16 位 opcode
        shl  r12, 3             ; opcode * 8
        add  r10, r12           ; table + opcode*8
        mov  r11, [r10]         ; handler = table[opcode]
        ...（读长度、推进 IP）...
        jmp  r11

    即：跳表用 mov + jmp reg 完成，而不是 jmp [mem]。
    """
    stat = collections.Counter()
    masks = collections.Counter()
    for st in r['sites']:
        ctx = back_context(payload, st.at, code_base)
        idx_mov = None
        for k, (a, m, o) in enumerate(ctx):
            d, s2 = _split2(o)
            if m == 'mov' and d == st.jmp_reg and s2 and s2.startswith('qword ptr ['):
                idx_mov = k
                break
        if idx_mov is None:
            stat['无表项读取'] += 1
            continue
        raw = ctx[idx_mov][2]
        ra = raw[raw.index('[') + 1:raw.rindex(']')].strip()
        scaled = False
        for j in range(idx_mov - 1, -1, -1):
            a2, m2, o2 = ctx[j]
            d2, s22 = _split2(o2)
            if d2 == ra and m2 == 'add' and s22:
                ri = s22
                for q in range(j - 1, -1, -1):
                    a3, m3, o3 = ctx[q]
                    d3, s33 = _split2(o3)
                    if d3 == ri and m3 == 'shl' and (s33 or '').strip() == '3':
                        scaled = True
                        break
                break
        if scaled:
            stat['表项 = base + idx*8'] += 1
            has_mask = any(m2 == 'and' and ', 0xffff' in (o2 or '') for _, m2, o2 in ctx)
            masks['16 位（and 0xffff）' if has_mask else '未见 16 位掩码'] += 1
        else:
            stat['表项读取但索引非 *8'] += 1
    return stat, masks


def report_tables(stat, masks):
    print("\n[站点派发形态]")
    tot = sum(stat.values()) or 1
    for k, v in stat.most_common():
        print("   %-28s %5d  %5.1f%%" % (k, v, 100.0 * v / tot))
    if masks:
        print("[opcode 宽度线索] %s" % dict(masks))


def report(r, hist=None, verbose=False):
    sites = r['sites']
    print("[*] 处理指令 %d 条，IP 槽站点 %d 个" % (r['insn'], len(sites)))
    if not sites:
        print("[!] 没找到 IP 槽自增惯用法")
        return

    slot = collections.Counter(s.slot for s in sites)
    jr = collections.Counter(s.jmp_reg for s in sites)
    ptr = collections.Counter(s.ptr for s in sites)
    step = collections.Counter(s.step_reg for s in sites)

    print("\n[IP 槽偏移分布]（应当收敛到一个常数）")
    allc = len(sites)
    for k, v in slot.most_common(8):
        print("   0x%-6X %5d  %5.1f%%" % (k & 0xFFFFFFFFFFFFFFFF, v, 100.0 * v / allc))

    print("\n[槽指针寄存器] %s" % dict(ptr.most_common(6)))
    print("[步长寄存器]   %s" % dict(step.most_common(6)))
    print("[跳转寄存器]   %s" % dict(jr.most_common(8)))

    if hist:
        print("\n[步长来源]（step 寄存器最近一次写入的形态）")
        for k, v in hist.most_common(8):
            print("   %-46s %d" % (k, v))

    if verbose:
        print("\n[样例站点]")
        for s in sites[:3]:
            print("   -- 0x%X  slot=0x%X  jmp=%s  step=%s" %
                  (s.at, s.slot, s.jmp_reg, s.step_reg))
            for (a, m, o) in s.seq:
                print("      %08X  %-8s %s" % (a, m, o))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('payload')
    ap.add_argument('--code-base', default=None)
    ap.add_argument('--window', type=int, default=12)
    ap.add_argument('--json', metavar='FILE')
    ap.add_argument('--verbose', '-v', action='store_true')
    a = ap.parse_args()

    cb = int(a.code_base, 16) if a.code_base else CODE_BASE_VA
    p = open(a.payload, 'rb').read()
    print("[*] 载荷 %s  %.1f MB  代码基址 0x%X"
          % (a.payload, len(p) / 1048576.0, cb))

    r = scan(p, cb, a.window, a.verbose)
    hist = attach_len_source(p, r, cb)
    report(r, hist, a.verbose)
    stat, masks = analyze_tables(p, r, cb)
    report_tables(stat, masks)

    if a.json:
        with open(a.json, 'w', encoding='utf-8') as f:
            json.dump({'code_base': cb, 'insn': r['insn'],
                       'sites': [{'at': '0x%X' % s.at, 'slot': s.slot,
                                  'ptr': s.ptr, 'step_reg': s.step_reg,
                                  'jmp_reg': s.jmp_reg, 'lensrc': s.lensrc}
                                 for s in r['sites']]},
                      f, ensure_ascii=False, indent=1)
        print("\n[+] 已生成 %s" % a.json)


if __name__ == '__main__':
    main()

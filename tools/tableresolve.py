# -*- coding: utf-8 -*-
"""
===============================================================
  tableresolve.py —— handler 表指针的静态定位 + 运行期取数清单
===============================================================
第六种派发形态是 `mov rD,[table+opcode*8]; jmp rD`，但 table 本身是运行期从
VM 上下文里读出来的（二级间接）。本工具把「table 到底存在哪个上下文槽」静态求出来：

    mov  r10, rbp
    add  r10, 4
    mov  r10, qword ptr [r10]     ; r10 = ctx[4]  <- 表指针
    add  r10, r12                 ; + opcode*8
    mov  r11, qword ptr [r10]     ; handler

顺带识别直接形态 `mov rA, qword ptr [rbp+K]`。

产出两类东西：
  1. 统计：表指针落在哪些 ctx 槽（可剔除已知 IP 槽）
  2. **运行期取数清单**：给出 ctx 槽偏移 + 派发点地址 + 索引寄存器，
     配合 `--emit-frida` / `--emit-x64dbg` 生成的脚本，在调试器里一次性
     把 table 指针 dump 出来，就能拼出完整的 opcode -> handler。

用法：
  python3 tableresolve.py payload.bin --ipslots ipslots.json
  python3 tableresolve.py payload.bin --ipslots ipslots.json --json tableres.json
  python3 tableresolve.py payload.bin --emit-frida dump.js --emit-x64dbg dump.txt
"""
import sys, os, re, json, argparse, collections

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

IMG_VA = 0x140000000
VMP_RVA = 0x1D34000
CODE_BASE_VA = IMG_VA + VMP_RVA

W64 = set(['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp'] +
          ['r%d' % i for i in range(8, 16)])


def _split2(s):
    a, sep, b = s.partition(', ')
    return (a, b) if sep else (a, None)


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



class InstrIndex:
    """按「结束地址」索引指令，带记忆化。反向走链用，避免每次重解整段。"""

    def __init__(self, payload, code_base=CODE_BASE_VA):
        self.p = payload
        self.cb = code_base
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = False
        self.cache = {}

    def ending_at(self, addr):
        if addr in self.cache:
            return self.cache[addr]
        r = None
        s0 = addr - self.cb
        if s0 > 8:
            for L in range(9, 1, -1):
                st = s0 - L
                for i in self.md.disasm(self.p[st:s0], self.cb + st):
                    if i.address == self.cb + st and i.address + i.size == addr:
                        r = (self.cb + st, i.mnemonic, i.op_str)
                    break
                if r is not None:
                    break
        self.cache[addr] = r
        return r

    def back(self, addr, n=60, max_scan=400):
        """往回走：解不出就退一个字节再试（真实代码 junk 多，硬断会丢链）"""
        seq = []
        cur = addr
        steps = 0
        while len(seq) < n and steps < max_scan and cur > self.cb + 8:
            r = self.ending_at(cur)
            if r is None:
                cur -= 1
                steps += 1
                continue
            seq.append(r)
            cur = r[0]
            steps += 1
        seq.reverse()
        return seq


def find_ctx_loads(payload, code_base=CODE_BASE_VA):
    """
    找「从上下文取指针」的两类惯用法，返回 [(指令地址, 寄存器, 槽偏移)]：
      A. mov rX,rbp ; add rX,imm ; mov rX,[rX]
      B. mov rX, qword ptr [rbp + imm]        （直接形态）
    """
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    md.skipdata = True
    out = []
    win = collections.deque(maxlen=8)
    for t in md.disasm_lite(payload, code_base):
        a, sz, m, o = t
        d, s = _split2(o)
        win.append((a, m, o, d, s))
        if m != 'mov' or not d or not s or '[' not in s:
            continue
        inner = s[s.index('[') + 1:s.rindex(']')].strip()
        # B. 直接 [rbp + imm]
        if inner.startswith('rbp') and '+' in inner:
            v = _imm(inner.split('+')[-1])
            if v is not None:
                out.append((a, d, v))
                continue
        # A. mov rX,[rX]，往前是 add rX,imm，再往前是 mov rX,rbp
        if inner != d:
            continue
        imm = None
        ok = False
        for (a2, m2, o2, d2, s2) in reversed(list(win)[:-1]):
            if d2 != d:
                continue
            if m2 == 'add' and s2 and _imm(s2) is not None and imm is None:
                imm = _imm(s2)
                continue
            if m2 == 'mov' and s2 == 'rbp':
                ok = True
            break
        if ok and imm is not None:
            out.append((a, d, imm))
    return out



def _hit(ctx, jr, byreg, window):
    """快速判断这组反向链能不能定到表指针槽位"""
    for j, (a, m, o) in enumerate(ctx):
        d, s = _split2(o)
        if m == 'mov' and d == jr and s and 'qword ptr [' in s:
            raw = s
            ra = raw[raw.index('[') + 1:raw.rindex(']')].strip()
            if ra not in W64:
                return False
            for (a2, slot) in byreg.get(ra, ()):
                if a2 < a and a - a2 <= window:
                    return True
            return False
    return False


def resolve(payload, dispatch, ctx_loads, code_base=CODE_BASE_VA,
            window=400, ip_slots=()):
    """
    对每个派发点，回看它的表项读取，再按寄存器把表指针对齐到最近的 ctx 装载。
    dispatch: [(at_va, jmp_reg)]
    返回 [(at, idx_reg, slot, ip_slot_collision)]
    """
    byreg = collections.defaultdict(list)
    for a, r, slot in ctx_loads:
        byreg[r].append((a, slot))
    for r in byreg:
        byreg[r].sort()

    idx = InstrIndex(payload, code_base)
    md2 = Cs(CS_ARCH_X86, CS_MODE_64)
    md2.detail = False

    def brute_ctx(addr, back=160, maxinsn=100):
        """穷举起点：取能精确落在 addr 上的最长序列（慢，只给兜底用）"""
        best = None
        s0 = addr - code_base
        for s in range(max(1, s0 - back), s0):
            seq = []
            ok = False
            for i in md2.disasm(payload[s:s0], code_base + s):
                seq.append((i.address, i.mnemonic, i.op_str))
                if i.address + i.size == addr:
                    ok = True
                    break
                if len(seq) > maxinsn:
                    break
            if ok and (best is None or len(seq) >= len(best)):
                best = seq
        return best or []

    def back_ctx(addr, back=window, maxinsn=140):
        return idx.back(addr, maxinsn)

    res = []
    for at, jr in dispatch:
        ctx = back_ctx(at)
        if not _hit(ctx, jr, byreg, window):
            ctx = brute_ctx(at) or ctx
        k = None
        for j, (a, m, o) in enumerate(ctx):
            d, s = _split2(o)
            if m == 'mov' and d == jr and s and 'qword ptr [' in s:
                k = j
                break
        if k is None:
            continue
        raw = ctx[k][2]
        ra = raw[raw.index('[') + 1:raw.rindex(']')].strip()
        if ra not in W64:
            continue
        cand = [(a, slot) for (a, slot) in byreg.get(ra, ())
                if a < ctx[k][0] and ctx[k][0] - a <= window]
        if not cand:
            continue
        a, slot = cand[-1]
        res.append((at, ra, slot, slot in ip_slots))
    return res


def report(res, dispatch_total, ip_slots):
    print("[*] 派发点 %d 个，表指针槽位可定位 %d 个（%.1f%%）"
          % (dispatch_total, len(res), 100.0 * len(res) / max(dispatch_total, 1)))
    if not res:
        return
    slots = collections.Counter(r[2] for r in res)
    collide = sum(1 for r in res if r[3])
    print("[*] 其中落在已知 IP 槽上的 %d 个（属误配，应剔除）" % collide)
    clean = collections.Counter({k: v for k, v in slots.items() if k not in ip_slots})
    print("\n[表指针落在哪个 ctx 槽]")
    for k, v in clean.most_common(10):
        print("   ctx+0x%-6X %5d  %5.1f%%" % (k, v, 100.0 * v / len(res)))
    print("\n[已知 IP 槽] %s"
          % (', '.join('ctx+0x%X' % x for x in sorted(ip_slots)) or '未提供'))


def emit_frida(path, res, code_base, ip_slots):
    slots = sorted({r[2] for r in res if not r[3]})
    lines = [
        '// 由 tableresolve.py 生成：把 VM 上下文里的 handler 表指针 dump 出来',
        '// ctx 基址寄存器按实测是 rbp（若版本不同请改 CTX）',
        'const CTX = "rbp";',
        'const SLOTS = [%s];' % ', '.join('0x%X' % s for s in slots),
        'const DISPATCH = [%s];' % ', '.join('0x%X' % r[0] for r in res[:64]),
        '',
        'function dumpTables() {',
        '    const ctx = this.context[CTX];',
        '    SLOTS.forEach(function (off) {',
        '        try {',
        '            const p = ctx.add(off).readPointer();',
        '            console.log("ctx+0x" + off.toString(16) + " -> table 0x" + p.toString(16));',
        '            for (let i = 0; i < 64; i++) {',
        '                const h = p.add(i * 8).readPointer();',
        '                if (h.compare(ptr("0x0")) <= 0) break;',
        '                console.log("  opcode 0x" + i.toString(16) + " -> handler 0x" + h.toString(16));',
        '            }',
        '        } catch (e) { console.log("slot 0x" + off.toString(16) + " 读取失败: " + e); }',
        '    });',
        '}',
        '',
        '// 用法：在任一派发点处调用 dumpTables.call(this)，或挂 Interceptor',
    ]
    open(path, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
    print("[+] 已生成 %s（%d 个槽位 / %d 个派发点）"
          % (path, len(slots), min(len(res), 64)))


def emit_x64dbg(path, res, code_base, ip_slots):
    slots = sorted({r[2] for r in res if not r[3]})
    lines = ['// x64dbg 脚本：dump VM 上下文里的 handler 表',
             '// 用法：在断点命中、rbp = VM 上下文基址时运行']
    for s in slots:
        lines.append('log "ctx+0x%X ->"' % s)
        lines.append('log "{p:qword(0x{rbp}+0x%X)}"' % s)
    lines.append('ret')
    open(path, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
    print("[+] 已生成 %s（%d 个槽位）" % (path, len(slots)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('payload')
    ap.add_argument('--code-base', default=None)
    ap.add_argument('--ipslots', metavar='JSON', help='ipslot.py 产出，用于剔除 IP 槽')
    ap.add_argument('--dispatch', metavar='JSON', help='x86il_dispatch --json 产出（可选）')
    ap.add_argument('--window', type=int, default=400)
    ap.add_argument('--json', metavar='FILE')
    ap.add_argument('--emit-frida', metavar='FILE')
    ap.add_argument('--emit-x64dbg', metavar='FILE')
    a = ap.parse_args()

    cb = int(a.code_base, 16) if a.code_base else CODE_BASE_VA
    p = open(a.payload, 'rb').read()
    print("[*] 载荷 %s  %.1f MB  代码基址 0x%X"
          % (a.payload, len(p) / 1048576.0, cb))

    ip_slots = set()
    dispatch = []
    if a.ipslots:
        js = json.load(open(a.ipslots, encoding='utf-8'))
        ip_slots = {1 for _ in ()} if False else set()
        # 从站点里反推 IP 槽：取出现次数最多的几个偏移
        cnt = collections.Counter()
        for s in js['sites']:
            cnt[s['slot']] += 1
        ip_slots = {k for k, v in cnt.items() if v >= 20}
        print("[*] 载入 IP 站点 %d 个，识别出 IP 槽 %s"
              % (len(js['sites']), ', '.join('0x%X' % x for x in sorted(ip_slots))))
        dispatch = [(int(s['at'], 16), s['jmp_reg']) for s in js['sites']]

    if a.dispatch:
        dj = json.load(open(a.dispatch, encoding='utf-8'))
        dd = [(int(d['at'], 16), d.get('dest') or d.get('idx')) for d in dj.get('dispatch_points', [])]
        if dd:
            dispatch = dd
            print("[*] 使用 x86il_dispatch 的派发点 %d 个" % len(dd))

    if not dispatch:
        print("[!] 没有派发点输入，请给 --ipslots 或 --dispatch")
        return

    loads = find_ctx_loads(p, cb)
    print("[*] 上下文指针装载惯用法 %d 处" % len(loads))
    res = resolve(p, dispatch, loads, cb, a.window, ip_slots)
    report(res, len(dispatch), ip_slots)

    if a.json:
        json.dump({'code_base': cb,
                   'resolved': [{'at': '0x%X' % r[0], 'table_reg': r[1],
                                 'slot': '0x%X' % r[2], 'ip_slot': r[3]} for r in res],
                   'unresolved': len(dispatch) - len(res)},
                  open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print("[+] 已生成 %s" % a.json)
    if a.emit_frida:
        emit_frida(a.emit_frida, res, cb, ip_slots)
    if a.emit_x64dbg:
        emit_x64dbg(a.emit_x64dbg, res, cb, ip_slots)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""opcode 指令布局提取：每个 opcode 读 packet 的哪些字段（IP+off, 宽度）+ 读写哪些 ctx 槽
带寄存器别名 + 指针基（rbp / IP）追踪。
用法: python3 opsem3.py            # 全部 661 个
      python3 opsem3.py 424 407    # 指定
输出: layouts.json / layouts.md
"""
import json, os, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM

IMG = os.environ.get("DG_IMG", "image_run.bin")
BASE = 0x140000000
TAB = 0x1421080ab
NENT = 661
JUNK = {0x8, 0x6d, 0xa4, 0x119, 0x11b, 0x121, 0x13b, 0x13f, 0x178}
META = {0xbc: "IP", 0xf5: "TBL"}
SZ = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}

img = open(IMG, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

ALIAS = {}
for base, names in {
    "rax": ["rax", "eax", "ax", "al", "ah"], "rbx": ["rbx", "ebx", "bx", "bl", "bh"],
    "rcx": ["rcx", "ecx", "cx", "cl", "ch"], "rdx": ["rdx", "edx", "dx", "dl", "dh"],
    "rsi": ["rsi", "esi", "si", "sil"], "rdi": ["rdi", "edi", "di", "dil"],
    "rbp": ["rbp", "ebp", "bp", "bpl"], "rsp": ["rsp", "esp", "sp", "spl"],
}.items():
    for n in names:
        ALIAS[n] = base
for i in range(8, 16):
    ALIAS[f"r{i}"] = f"r{i}"
    for suf in ("d", "w", "b"):
        ALIAS[f"r{i}{suf}"] = f"r{i}"


def c(name):
    return ALIAS.get(name, name)


def rd(va, n):
    o = va - BASE
    return img[o:o + n] if 0 <= o and o + n <= len(img) else None


def table():
    return list(struct.unpack("<%dQ" % NENT, rd(TAB, NENT * 8)))


def resolve(va, maxhop=12):
    cur = va
    for _ in range(maxhop):
        b = rd(cur, 8)
        if not b or len(b) < 8:
            return cur
        if b[0] == 0xE9:
            cur = cur + 5 + struct.unpack("<i", b[1:5])[0]; continue
        if b[0] == 0xEB:
            cur = cur + 2 + struct.unpack("<b", b[1:2])[0]; continue
        if b[0] == 0xFF and b[1] == 0x25:
            p = rd(cur + 6 + struct.unpack("<i", b[2:6])[0], 8)
            if p:
                cur = struct.unpack("<Q", p)[0]; continue
        return cur
    return cur


def mem_expr(state, op):
    """返回 ('rbp', off) / ('ip', off) / None"""
    if op.mem.index != 0:
        return None
    if not op.mem.base:
        return None
    b = c(md.reg_name(op.mem.base))
    v = state.get(b)
    if isinstance(v, tuple) and v[0] in ("rbp", "ip"):
        return (v[0], v[1] + op.mem.disp)
    return None


def analyze(op):
    T = table()
    entry = T[op]
    body = resolve(entry)
    code = rd(body, 4000) or b""
    insns = []
    for ins in md.disasm(code, body):
        insns.append(ins)
        if ins.mnemonic == "jmp" and ins.operands and ins.operands[0].type == X86_OP_REG and len(insns) > 3:
            break
        if len(insns) > 400:
            break

    st = {}
    fields, slots_r, slots_w, flow = [], [], [], []
    rel_off = None

    for ins in insns:
        m, ops = ins.mnemonic, ins.operands
        if m in ("mov", "movzx", "movsx", "movsxd", "movsxd") and len(ops) == 2:
            d, s = ops
            if d.type == X86_OP_REG:
                dr = c(md.reg_name(d.reg))
                if s.type == X86_OP_REG:
                    sr = c(md.reg_name(s.reg))
                    st[dr] = ("rbp", 0) if sr == "rbp" else st.get(sr, ("var", None))
                elif s.type == X86_OP_IMM:
                    st[dr] = ("imm", s.imm)
                elif s.type == X86_OP_MEM:
                    e = mem_expr(st, s)
                    if e and e[0] == "rbp":
                        off = e[1]
                        if off == 0xbc:
                            st[dr] = ("ip", 0)
                        elif off == 0xf5:
                            st[dr] = ("tbl", 0)
                        else:
                            st[dr] = ("mem", off, s.size)
                            if off not in JUNK:
                                slots_r.append((off, s.size))
                    elif e and e[0] == "ip":
                        st[dr] = ("ipval", e[1], s.size)
                        fields.append((e[1], s.size))
                    else:
                        st[dr] = ("var", None)
            elif d.type == X86_OP_MEM:
                e = mem_expr(st, d)
                if e and e[0] == "rbp" and e[1] not in JUNK:
                    src = "?"
                    if s.type == X86_OP_REG:
                        sv = st.get(c(md.reg_name(s.reg)))
                        if isinstance(sv, tuple) and sv[0] == "ipval":
                            src = f"{SZ.get(sv[2],'?')}@IP+{sv[1]:#x}"
                        elif isinstance(sv, tuple) and sv[0] == "mem":
                            src = f"[+{sv[1]:#x}]"
                        elif isinstance(sv, tuple) and sv[0] == "imm":
                            src = hex(sv[1] & 0xFFFFFFFF)
                        else:
                            src = c(md.reg_name(s.reg))
                    elif s.type == X86_OP_IMM:
                        src = hex(s.imm & 0xFFFFFFFFFFFFFFFF)
                    elif s.type == X86_OP_MEM:
                        e2 = mem_expr(st, s)
                        if e2 and e2[0] == "ip":
                            src = f"mem@IP+{e2[1]:#x}"
                        elif e2 and e2[0] == "rbp":
                            src = f"[+{e2[1]:#x}]"
                    slots_w.append((e[1], d.size, src))
        elif m in ("add", "sub") and len(ops) == 2 and ops[0].type == X86_OP_REG:
            dr = c(md.reg_name(ops[0].reg))
            v = st.get(dr)
            k = 1 if m == "add" else -1
            if isinstance(v, tuple) and v[0] in ("rbp", "ip") and ops[1].type == X86_OP_IMM:
                st[dr] = (v[0], v[1] + k * ops[1].imm)
            elif isinstance(v, tuple) and v[0] == "mem":
                st[dr] = ("var", None)
            elif isinstance(v, tuple) and v[0] == "ipval":
                st[dr] = ("var", None)
            else:
                st[dr] = ("var", None)
        elif m in ("add", "sub") and ops and ops[0].type == X86_OP_MEM:
            e = mem_expr(st, ops[0])
            if e and e[0] == "ip" and len(ops) > 1 and ops[1].type == X86_OP_REG:
                sv = st.get(c(md.reg_name(ops[1].reg)))
                if isinstance(sv, tuple) and sv[0] == "ipval" and sv[2] == 4:
                    rel_off = sv[1]
            elif e and e[0] == "rbp" and e[1] == 0xbc:
                # add qword ptr [ctx+0xBC], rX  → IP += rX（rX 是 ipval 时即 rel 字段）
                if len(ops) > 1 and ops[1].type == X86_OP_REG:
                    sv = st.get(c(md.reg_name(ops[1].reg)))
                    if isinstance(sv, tuple) and sv[0] == "ipval" and sv[2] == 4:
                        rel_off = sv[1]
            elif e and e[0] == "rbp" and e[1] not in JUNK:
                slots_w.append((e[1], ops[0].size, "="+m))
        elif m in ("cmp", "test") and ops and ops[0].type == X86_OP_MEM:
            e = mem_expr(st, ops[0])
            if e and e[0] == "rbp" and e[1] not in JUNK:
                slots_r.append((e[1], ops[0].size))
        else:
            for o in ops:
                if o.type == X86_OP_REG:
                    st[c(md.reg_name(o.reg))] = ("var", None)

    return {"op": op, "entry": entry, "body": body, "n": len(insns),
            "fields": sorted(set(fields)),
            "R": sorted(set(slots_r)), "W": sorted(set(slots_w)),
            "rel_off_hint": rel_off,
            "asm": "\n".join(f"{i.address:#x}: {i.mnemonic} {i.op_str}" for i in insns)}


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a.isdigit() or a.startswith("0x")]
    ops = [int(a, 0) for a in args] if args else list(range(NENT))
    out = {}
    for op in ops:
        r = analyze(op)
        out[op] = r
    json.dump({str(k): {kk: vv for kk, vv in v.items()} for k, v in out.items()},
              open("layouts.json", "w"), indent=1)
    # 统计
    from collections import Counter
    fc = Counter()
    for r in out.values():
        fc[tuple(r["fields"])] += 1
    print("字段布局分布 top10:")
    for k, v in fc.most_common(10):
        print("  ", k, "×", v)
    print("\n样例 424:", out[424]["fields"], "R", [(hex(a), b) for a, b in out[424]["R"]],
          "W", [(hex(a), b, s) for a, b, s in out[424]["W"]])

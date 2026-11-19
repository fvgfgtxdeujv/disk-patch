#!/usr/bin/env python3
"""opcode 语义提取 v2：带寄存器别名/指针混淆追踪
- 追踪 mov reg,rbp / add reg,imm / mov reg,[reg] / 内存槽读写
- 过滤混淆累加器槽，输出每个 op 的真实读/写槽与运算
用法: python3 opsem2.py 424 407 297 --asm
"""
import json, os, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM

IMG = os.environ.get("DG_IMG", "image_run.bin")
BASE = 0x140000000
TAB = 0x1421080ab
NENT = 661
VMP_LO, VMP_HI = 0x1419d4000, 0x142780000

JUNK = {0x8, 0x6d, 0xa4, 0x119, 0x11b, 0x121, 0x13b, 0x13f, 0x178}
META = {0xbc: "IP", 0xf5: "TBL"}
SZ = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}

img = open(IMG, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
md.reg_name_map = {}


def rd(va, n):
    o = va - BASE
    return img[o:o + n] if 0 <= o and o + n <= len(img) else None


def table():
    return list(struct.unpack("<%dQ" % NENT, rd(TAB, NENT * 8)))


def resolve(va, maxhop=12):
    cur = va
    for _ in range(maxhop):
        b = rd(cur, 8)
        if not b:
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


ALIAS = {}
for base, names in {
    "rax": ["rax", "eax", "ax", "al", "ah"], "rbx": ["rbx", "ebx", "bx", "bl", "bh"],
    "rcx": ["rcx", "ecx", "cx", "cl", "ch"], "rdx": ["rdx", "edx", "dx", "dl", "dh"],
    "rsi": ["rsi", "esi", "si", "sil"], "rdi": ["rdi", "edi", "di", "dil"],
    "rbp": ["rbp", "ebp", "bp", "bpl"], "rsp": ["rsp", "esp", "sp", "spl"],
}.items():
    for i, n in enumerate(names):
        ALIAS[n] = (base, [8, 4, 2, 1, 1][i])
for i in range(8, 16):
    n = f"r{i}"
    ALIAS[n] = (n, 8)
    ALIAS[f"r{i}d"] = (n, 4)
    ALIAS[f"r{i}w"] = (n, 2)
    ALIAS[f"r{i}b"] = (n, 1)


def canon(name):
    return ALIAS.get(name, (name, 8))[0]


def wsize(name):
    return ALIAS.get(name, (name, 8))[1]


def expr_of_mem(state, op, reg_name):
    """[base+index*scale+disp] 若 base/index 在 state 里是已知指针，给出表达式"""
    base = reg_name(op.mem.base) if op.mem.base else None
    idx = reg_name(op.mem.index) if op.mem.index else None
    disp = op.mem.disp
    parts = []
    if base:
        v = state.get(canon(base))
        if isinstance(v, tuple) and v[0] == "rbp":
            parts.append((v[0], v[1] + disp))
        else:
            return None
    if idx:
        v = state.get(canon(idx))
        if isinstance(v, tuple) and v[0] == "var":
            parts.append(("var_idx", None))
        else:
            return None
    if not base and not idx:
        return ("abs", disp)
    if len(parts) == 1:
        return parts[0]
    return None


def analyze(op, want_asm=False):
    T = table()
    entry = T[op]
    body = resolve(entry)
    code = rd(body, 4000)
    insns = []
    for ins in md.disasm(code, body):
        insns.append(ins)
        if ins.mnemonic == "jmp" and ins.operands and ins.operands[0].type == X86_OP_REG and len(insns) > 3:
            break
        if len(insns) > 500:
            break

    state = {}          # canon reg -> ('rbp', off) | ('var', off) | ('imm', v) | ('mem', off, sz)
    slots_r, slots_w, sem = [], [], []

    for ins in insns:
        m = ins.mnemonic
        ops = ins.operands
        # 1) 赋值类
        if m == "mov" and len(ops) == 2:
            d, s = ops
            if d.type == X86_OP_REG:
                dr = canon(reg_name(d.reg))
                if s.type == X86_OP_REG:
                    sr = canon(reg_name(s.reg))
                    if sr == "rbp":
                        state[dr] = ("rbp", 0)
                    elif sr in state:
                        state[dr] = state[sr]
                    else:
                        state[dr] = ("var", None)
                elif s.type == X86_OP_IMM:
                    state[dr] = ("imm", s.imm)
                elif s.type == X86_OP_MEM:
                    e = expr_of_mem(state, s, reg_name)
                    if e and e[0] == "rbp":
                        off = e[1]
                        state[dr] = ("mem", off, s.size)
                        if off not in JUNK:
                            tag = META.get(off, "")
                            slots_r.append((off, s.size, tag))
                    else:
                        state[dr] = ("var", None)
            elif d.type == X86_OP_MEM:
                e = expr_of_mem(state, d, reg_name)
                if e and e[0] == "rbp":
                    off = e[1]
                    src = ""
                    if s.type == X86_OP_REG:
                        sv = state.get(canon(reg_name(s.reg)))
                        if isinstance(sv, tuple) and sv[0] == "mem":
                            src = f"[+{sv[1]:#x}]"
                        elif isinstance(sv, tuple) and sv[0] == "imm":
                            src = hex(sv[1] & 0xFFFFFFFFFFFFFFFF)
                        else:
                            src = canon(reg_name(s.reg))
                    elif s.type == X86_OP_IMM:
                        src = hex(s.imm & 0xFFFFFFFFFFFFFFFF)
                    elif s.type == X86_OP_MEM:
                        e2 = expr_of_mem(state, s, reg_name)
                        src = f"[+{e2[1]:#x}]" if e2 and e2[0] == "rbp" else "mem"
                    if off not in JUNK:
                        slots_w.append((off, d.size, src))
                        sem.append(f"[+{off:#04x}]{SZ.get(d.size,'?')} = {src}")
        # 2) 地址运算
        elif m in ("add", "sub") and len(ops) == 2 and ops[0].type == X86_OP_REG:
            dr = canon(reg_name(ops[0].reg))
            v = state.get(dr)
            k = 1 if m == "add" else -1
            if isinstance(v, tuple) and v[0] == "rbp" and ops[1].type == X86_OP_IMM:
                state[dr] = ("rbp", v[1] + k * ops[1].imm)
            elif isinstance(v, tuple) and v[0] == "mem" and ops[1].type == X86_OP_IMM:
                state[dr] = ("mem", v[1] + k * ops[1].imm, v[2])  # 指针推进
            elif ops[1].type == X86_OP_IMM:
                state[dr] = ("var", None)
            else:
                state[dr] = ("var", None)
        # 3) 内存槽上的算术（真语义大多在这）
        elif m in ("add", "sub", "xor", "or", "and", "shl", "shr", "sar", "rol", "ror", "imul"):
            if ops and ops[0].type == X86_OP_MEM:
                e = expr_of_mem(state, ops[0], reg_name)
                if e and e[0] == "rbp":
                    off = e[1]
                    src = ""
                    if len(ops) > 1:
                        o1 = ops[1]
                        if o1.type == X86_OP_IMM:
                            src = hex(o1.imm & 0xFFFFFFFF)
                        elif o1.type == X86_OP_REG:
                            sv = state.get(canon(reg_name(o1.reg)))
                            if isinstance(sv, tuple) and sv[0] == "mem":
                                src = f"[+{sv[1]:#x}]"
                            elif isinstance(sv, tuple) and sv[0] == "imm":
                                src = hex(sv[1] & 0xFFFFFFFF)
                            else:
                                src = canon(reg_name(o1.reg))
                        elif o1.type == X86_OP_MEM:
                            e2 = expr_of_mem(state, o1, reg_name)
                            src = f"[+{e2[1]:#x}]" if e2 and e2[0] == "rbp" else "mem"
                    if off not in JUNK:
                        slots_w.append((off, ops[0].size, src))
                        slots_r.append((off, ops[0].size, ""))
                        sem.append(f"[+{off:#04x}]{SZ.get(ops[0].size,'?')} {m}= {src}")
        # 4) movzx/movsx 读槽
        elif m in ("movzx", "movsx", "movsxd", "movbe") and len(ops) == 2 and ops[0].type == X86_OP_REG:
            dr = canon(reg_name(ops[0].reg))
            s = ops[1]
            if s.type == X86_OP_MEM:
                e = expr_of_mem(state, s, reg_name)
                if e and e[0] == "rbp":
                    off = e[1]
                    state[dr] = ("mem", off, s.size)
                    if off not in JUNK:
                        slots_r.append((off, s.size, "zx"))
                else:
                    state[dr] = ("var", None)
        else:
            for o in ops:
                if o.type == X86_OP_REG:
                    state[canon(reg_name(o.reg))] = ("var", None)

    return {"op": op, "entry": entry, "body": body, "n": len(insns),
            "R": sorted({(o, s) for o, s, _ in slots_r}),
            "W": sorted({(o, s, src) for o, s, src in slots_w}),
            "sem": sem,
            "asm": "\n".join(f"{i.address:#x}: {i.mnemonic} {i.op_str}" for i in insns)}


def reg_name(rid):
    return md.reg_name(rid)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    show_asm = "--asm" in sys.argv
    ops = [int(a, 0) for a in args] or [424]
    out = {}
    for op in ops:
        r = analyze(op)
        out[op] = r
        print(f"### op {op}  body {r['body']:#x}  {r['n']} insns")
        print(f"  R: {[(hex(o),s) for o,s in r['R']]}")
        print(f"  W: {[(hex(o),s,src) for o,s,src in r['W']]}")
        for s in r["sem"][:40]:
            print("   ", s)
        if show_asm:
            print(r["asm"])
        print()
    json.dump({str(k): {kk: (vv if kk != 'asm' else vv) for kk, vv in v.items()} for k, v in out.items()},
              open("opsem2_out.json", "w"), indent=1)

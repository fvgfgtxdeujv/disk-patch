#!/usr/bin/env python3
"""opcode 语义差分提取（unicorn 沙箱）
思路：把 ctx 每个槽预置成可区分的哨兵值 → 跑 handler 到派发出口 → 比对 ctx diff。
跑 3 组不同种子，用「写入值对哪些输入槽敏感 + 算术关系拟合」判定语义。
用法: python3 lift.py 424 407 297
"""
import json, os, struct, sys
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UcError
from unicorn.x86_const import (UC_X86_REG_RBP, UC_X86_REG_RSP, UC_X86_REG_RAX,
                               UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
                               UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RIP)

IMG = os.environ.get("DG_IMG", "image_run.bin")
BASE = 0x140000000
TAB = 0x1421080ab
NENT = 661
CTX = 0x30000000
CTXSZ = 0x8000
BC = 0x40000000
FAKET = 0x41000000
STK = 0x50000000
STKSZ = 0x20000
IPSZ = 0x1000

img = open(IMG, "rb").read()
imglen = len(img)

OPS = [424, 407, 547, 297, 446, 545, 263, 90, 478, 409, 197, 430, 256, 649,
       508, 210, 101, 418, 80, 395, 399, 24, 180, 460, 414, 355, 632, 305]


def table():
    raw = img[TAB - BASE: TAB - BASE + NENT * 8]
    return list(struct.unpack("<%dQ" % NENT, raw))


def resolve(va, maxhop=12):
    cur = va
    for _ in range(maxhop):
        b = img[cur - BASE: cur - BASE + 8]
        if len(b) < 8:
            return cur
        if b[0] == 0xE9:
            cur = cur + 5 + struct.unpack("<i", b[1:5])[0]; continue
        if b[0] == 0xEB:
            cur = cur + 2 + struct.unpack("<b", b[1:2])[0]; continue
        if b[0] == 0xFF and b[1] == 0x25:
            o = cur + 6 + struct.unpack("<i", b[2:6])[0] - BASE
            if 0 <= o < imglen - 8:
                cur = struct.unpack("<Q", img[o:o + 8])[0]; continue
        return cur
    return cur


def build_ctx(seed):
    """每槽一个可区分哨兵：0x1000_0000_0000 + slot*0x10000 + seed"""
    buf = bytearray(CTXSZ)
    for off in range(0, CTXSZ, 8):
        v = (0x0001000000000000 | (off << 16) | seed) & 0xFFFFFFFFFFFFFFFF
        struct.pack_into("<Q", buf, off, v)
    return buf


def run(op, seed, maxinsn=3000):
    ent = resolve(table()[op])
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    # 只映射 handler 附近 2MB，省内存：以 handler 所在 2MB 对齐段
    uc.mem_map(BASE, (imglen + 0xFFFFF) & ~0xFFFFF)
    uc.mem_write(BASE, img)
    uc.mem_map(CTX, CTXSZ)
    uc.mem_map(BC, IPSZ)
    uc.mem_map(FAKET, 0x4000)
    uc.mem_map(STK, STKSZ)

    ctx = build_ctx(seed)
    ip = BC + 0x800
    struct.pack_into("<Q", ctx, 0xbc, ip)
    struct.pack_into("<Q", ctx, 0xf5, FAKET)
    struct.pack_into("<I", ctx, 0x178, (-0x7d4a62f1) & 0xFFFFFFFF)
    uc.mem_write(CTX, bytes(ctx))
    # 伪造一条下一条指令：op=0x1234, rel=+7
    uc.mem_write(ip, struct.pack("<Hi", 0x1234, 7) + bytes(26))

    uc.reg_write(UC_X86_REG_RBP, CTX)
    uc.reg_write(UC_X86_REG_RSP, STK + STKSZ - 0x100)
    uc.reg_write(UC_X86_REG_RIP, ent)

    insns = []
    uc.hook_add(UC_HOOK_CODE, lambda u, a, s, d: insns.append(a))

    err = None
    try:
        uc.emu_start(ent, 0, count=maxinsn)
    except UcError as e:
        err = str(e)

    return {"entry": ent, "insns": insns, "err": err,
            "ctx": bytes(uc.mem_read(CTX, CTXSZ)),
            "bc": bytes(uc.mem_read(BC, IPSZ)),
            "ip": struct.unpack("<Q", bytes(uc.mem_read(CTX + 0xbc, 8)))[0],
            "ctx0": bytes(ctx)}


def diff(c0, c1):
    """按 1 字节粒度找变化，再归并成 (最小偏移, 最长连续长度, 值)"""
    out = []
    i = 0
    n = len(c0)
    while i < n:
        if c0[i] != c1[i]:
            j = i
            while j < n and c0[j] != c1[j]:
                j += 1
            ln = j - i
            val = int.from_bytes(c1[i:j], "little")
            out.append((i, ln, val))
            i = j
        else:
            i += 1
    return out


def fmt(v):
    return f"{v:#018x}"


if __name__ == "__main__":
    ops = [int(a, 0) for a in sys.argv[1:]] or OPS
    res = {}
    for op in ops:
        r1 = run(op, 1)
        r2 = run(op, 2)
        d1 = diff(r1["ctx0"], r1["ctx"])
        d2 = diff(r2["ctx0"], r2["ctx"])
        w1 = {(o, l): b for o, l, b in d1}
        w2 = {(o, l): b for o, l, b in d2}
        print(f"### op {op} entry {r1['entry']:#x} insns={len(r1['insns'])} err={r1['err']}")
        print(f"    writes={len(w1)}")
        print(f"    执行路径前8: {[hex(x) for x in r1['insns'][:8]]}")
        for k in sorted(w1):
            o, l = k
            print(f"      +{o:#06x}/{l}B: {fmt(w1[k])} (s1) / {fmt(w2.get(k,0))} (s2)")
        print()
        res[op] = {"entry": r1["entry"], "n": len(r1["insns"]), "err": r1["err"],
                   "writes": {f"{hex(k[0])}/{k[1]}": [fmt(w1[k]), fmt(w2.get(k, 0))] for k in w1},
                   "path": [hex(x) for x in r1["insns"]], "ip_after": hex(r1["ip"])}
    json.dump({str(k): v for k, v in res.items()}, open("lift_out.json", "w"), indent=1)

#!/usr/bin/env python3
"""从运行期镜像里提 handler：读三张派发表 → 去重 handler 地址 → 反汇编 → 按字节序列聚类
用法: python3 extract_handlers.py
输出: handlers.json / handlers/*.asm / summary.md
"""
import json, os, struct, hashlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

IMG = os.environ.get("DG_IMG", "image_run.bin")
BASE = 0x140000000
OUT = os.environ.get("DG_OUT", "hx")
TABLES = [(0x1421080ab, 661), (0x141da2b42, 49), (0x141d8df04, 1096)]
VMP_LO, VMP_HI = 0x1419d4000, 0x142780000
MAX_INSN = 40

img = open(IMG, "rb").read()
print(f"image {len(img):#x} bytes  base {BASE:#x}  end {BASE+len(img):#x}")
print(f".vmp {VMP_LO:#x}-{VMP_HI:#x} {'OK' if VMP_LO>=BASE and VMP_HI<=BASE+len(img) else 'OUT OF RANGE'}")


def rd(va, n):
    off = va - BASE
    if off < 0 or off + n > len(img):
        return None
    return img[off:off + n]


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

os.makedirs(OUT, exist_ok=True)

tables = {}
all_handlers = {}
for tab_va, n in TABLES:
    raw = rd(tab_va, n * 8)
    if raw is None:
        print(f"table {tab_va:#x} unreadable"); continue
    ents = list(struct.unpack("<%dQ" % n, raw))
    tables[hex(tab_va)] = ents
    ok = sum(1 for e in ents if VMP_LO <= e < VMP_HI)
    print(f"table {tab_va:#x} n={n} in-vmp={ok} first4={[hex(x) for x in ents[:4]]}")
    for i, e in enumerate(ents):
        if VMP_LO <= e < VMP_HI:
            all_handlers.setdefault(e, []).append((tab_va, i))

print(f"unique handlers {len(all_handlers)}")

# 反汇编，按指令地址收集
recs = {}
clusters = {}
for hv in sorted(all_handlers):
    code = rd(hv, 400)
    if code is None:
        continue
    insns = []
    for ins in md.disasm(code, hv):
        insns.append(ins)
        if ins.mnemonic in ("ret", "jmp") or len(insns) >= MAX_INSN:
            break
    txt = "\n".join(f"{i.address:#x}: {i.mnemonic} {i.op_str}" for i in insns)
    # 去掉地址做指纹
    body = "\n".join(f"{i.mnemonic} {i.op_str}" for i in insns)
    h = hashlib.sha1(body.encode()).hexdigest()[:12]
    clusters.setdefault(h, []).append(hv)
    recs[hex(hv)] = {
        "addrs": [f"{t:#x}[{i}]" for t, i in all_handlers[hv]],
        "cluster": h,
        "n": len(insns),
        "asm": txt,
    }

print(f"clusters {len(clusters)}")
sizes = sorted((len(v), k) for k, v in clusters.items())
for sz, k in sizes[-8:]:
    print(f"  cluster {k} n={sz}")

json.dump({"tables": {k: [hex(x) for x in v] for k, v in tables.items()},
           "handlers": recs,
           "clusters": {k: [hex(x) for x in v] for k, v in clusters.items()}},
          open(os.path.join(OUT, "handlers.json"), "w"), indent=1)

# 每个 cluster 挑一个代表落盘
for k, v in clusters.items():
    rep = hex(v[0])
    open(os.path.join(OUT, f"cl_{k}.asm"), "w").write(recs[rep]["asm"] + "\n")

# 汇总
lines = ["# handler 聚类汇总", "", f"unique handlers {len(all_handlers)}, clusters {len(clusters)}", ""]
for k, v in sorted(clusters.items(), key=lambda kv: -len(kv[1])):
    lines.append(f"## {k}  ({len(v)} 个)  e.g. {hex(v[0])}")
    lines.append("```")
    lines.append(recs[hex(v[0])]["asm"][:1500])
    lines.append("```")
    lines.append("")
open(os.path.join(OUT, "summary.md"), "w").write("\n".join(lines))
print("out:", OUT)

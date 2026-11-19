#!/usr/bin/env python3
"""写一个带标记的假 key → 只读锁定 Options.ini（让程序删不掉）→ 起程序 → 扫内存找标记。

目的：定位程序对 key 的解析/变换结果。标记用高熵串，避免误命中。
"""
import os, subprocess, sys, time, glob

PREFIX = "/tmp/zaka-20261119/wine64"
DGDIR = "/tmp/zaka-20261119/disk-patch/dg/DiskGenius"
INI = os.path.join(DGDIR, "Options.ini")
OUT = "/tmp/zaka-20261119"

MARK = "ZAKAMARK7XQ9"
KEY = (f"appname=DiskGenius&license={MARK}A1&user={MARK}B2"
       f"&email={MARK}C3@x.com&verify={MARK}D4")

rows = {
    "appname": "DiskGenius",
    "user": f"{MARK}B2",
    "email": f"{MARK}C3@x.com",
    "regcode": "QK7X-M2PV-ZLHD-W8CT-RBNQ",
    "regver": "6.2.0.1829_x64_pro_eng",
    "VerifyDate": "20991231",
    "key": KEY,
}
lines = ["[license]"] + [f'{k} = "{v}"' for k, v in rows.items()] + [""]
data = "\r\n".join(lines) + "\r\n"

for p in (INI,):
    try: os.chmod(p, 0o666)
    except FileNotFoundError: pass
open(INI, "wb").write(b"\xff\xfe" + data.encode("utf-16-le"))
os.chmod(INI, 0o444)          # 让 DeleteFileW 失败
print("INI written+readonly:", os.path.getsize(INI))

env = dict(os.environ, WINEPREFIX=PREFIX, DISPLAY=":95")
xv = subprocess.Popen(["Xvfb", ":95", "-screen", "0", "1280x900x24"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)
proc = subprocess.Popen(["wine", "DiskGenius.exe"], cwd=DGDIR, env=env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def find_dg_pid():
    for d in glob.glob("/proc/[0-9]*"):
        try:
            maps = open(d + "/maps", "r", errors="ignore").read()
        except Exception:
            continue
        if "DiskGenius.exe" in maps and "wine" in maps:
            return int(d.split("/")[-1])
    return None

pid = None
for _ in range(60):
    pid = find_dg_pid()
    if pid: break
    time.sleep(1)
print("pid:", pid)
time.sleep(10)

def read_regions(pid):
    out = []
    for line in open(f"/proc/{pid}/maps"):
        parts = line.split()
        rng = parts[0].split("-")
        if "r" not in parts[1]:
            continue
        lo, hi = int(rng[0], 16), int(rng[1], 16)
        if hi - lo > 400 * 1024 * 1024:
            continue
        out.append((lo, hi, parts[-1] if len(parts) >= 6 else "", line.strip()))
    return out

hits = []
try:
    with open(f"/proc/{pid}/mem", "rb", 0) as mem:
        regions = read_regions(pid)
        print("regions:", len(regions))
        needles = {"ascii": MARK.encode(), "utf16": MARK.encode("utf-16-le")}
        for lo, hi, name, line in regions:
            size = min(hi - lo, 80 * 1024 * 1024)
            try:
                mem.seek(lo)
                buf = mem.read(size)
            except Exception:
                continue
            for kind, nd in needles.items():
                start = 0
                while True:
                    i = buf.find(nd, start)
                    if i < 0: break
                    ctx = buf[max(0, i-64): i+192]
                    hits.append({"kind": kind, "addr": lo + i, "region": line,
                                 "ctx_hex": ctx.hex(), "ctx_ascii":
                                 "".join(chr(c) if 32 <= c < 127 else "." for c in ctx)})
                    start = i + 1
                    if len(hits) > 400: break
                if len(hits) > 400: break
            if len(hits) > 400: break
except Exception as e:
    print("scan error:", e)

print("hits:", len(hits))
for h in hits[:12]:
    print(f"  [{h['kind']}] {hex(h['addr'])}  {h['region']}")
    print("    ", h["ctx_ascii"])

import json
json.dump(hits, open(os.path.join(OUT, "marker_hits.json"), "w"), indent=1)

proc.terminate()
time.sleep(1)
subprocess.run(["wineserver", "-k"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
xv.terminate()
os.chmod(INI, 0o666)
print("ini still there:", os.path.exists(INI), os.path.getsize(INI) if os.path.exists(INI) else 0)

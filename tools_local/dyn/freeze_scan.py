#!/usr/bin/env python3
"""冻结进程扫标记：写带 marker 的 key → 起程序 → attach(暂停) → 扫内存 → detach。

用法: freeze_scan.py <等待秒数>
"""
import os, subprocess, sys, time, glob, ctypes, json

WAIT = float(sys.argv[1]) if len(sys.argv) > 1 else 2.0
PREFIX = "/tmp/zaka-20261119/wine64"
DGDIR = "/tmp/zaka-20261119/disk-patch/dg/DiskGenius"
INI = os.path.join(DGDIR, "Options.ini")
OUT = "/tmp/zaka-20261119"
LOADER = "/usr/lib/wine/wine64"

MARK = "ZAKAMARK7XQ9"
KEY = (f"appname=DiskGenius&license={MARK}A1&user={MARK}B2"
       f"&email={MARK}C3@x.com&verify={MARK}D4")
rows = {
    "appname": "DiskGenius", "user": f"{MARK}B2", "email": f"{MARK}C3@x.com",
    "regcode": "QK7X-M2PV-ZLHD-W8CT-RBNQ", "regver": "6.2.0.1829_x64_pro_eng",
    "VerifyDate": "20991231", "key": KEY,
}
lines = ["[license]"] + [f'{k} = "{v}"' for k, v in rows.items()] + [""]
for p in (INI,):
    if os.path.exists(p):
        os.chmod(p, 0o666)
open(INI, "wb").write(b"\xff\xfe" + ("\r\n".join(lines) + "\r\n").encode("utf-16-le"))

env = dict(os.environ, WINEPREFIX=PREFIX, DISPLAY=":95")
xv = subprocess.Popen(["Xvfb", ":95", "-screen", "0", "1280x900x24"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)
proc = subprocess.Popen([LOADER, "DiskGenius.exe"], cwd=DGDIR, env=env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(WAIT)

libc = ctypes.CDLL("libc.so.6", use_errno=True)
PTRACE_ATTACH, PTRACE_DETACH = 16, 17
attached = False
try:
    if libc.ptrace(PTRACE_ATTACH, proc.pid, None, None) == 0:
        os.waitpid(proc.pid, 0)
        attached = True
except Exception as e:
    print("attach err", e)
print(f"wait={WAIT} pid={proc.pid} attached={attached}")

hits = []
if attached:
    regions = []
    for line in open(f"/proc/{proc.pid}/maps"):
        parts = line.split()
        if "r" not in parts[1]:
            continue
        lo, hi = (int(x, 16) for x in parts[0].split("-"))
        if hi - lo > 400 * 1024 * 1024:
            continue
        regions.append((lo, hi, line.strip()))
    needles = {"ascii": MARK.encode(), "utf16": MARK.encode("utf-16-le")}
    t0 = time.time()
    with open(f"/proc/{proc.pid}/mem", "rb", 0) as mem:
        for lo, hi, line in regions:
            try:
                mem.seek(lo)
                buf = mem.read(hi - lo)
            except Exception:
                continue
            for kind, nd in needles.items():
                i = buf.find(nd)
                while i >= 0 and len(hits) < 200:
                    ctx = buf[max(0, i - 96): i + 224]
                    hits.append({
                        "kind": kind, "addr": hex(lo + i), "region": line,
                        "ascii": "".join(chr(c) if 32 <= c < 127 else "." for c in ctx),
                        "hex": ctx.hex(),
                    })
                    i = buf.find(nd, i + 1)
    print(f"scan {time.time()-t0:.1f}s regions={len(regions)} hits={len(hits)}")
    libc.ptrace(PTRACE_DETACH, proc.pid, None, None)

for h in hits[:10]:
    print(f"  [{h['kind']}] {h['addr']} {h['region'][:70]}")
    print("    ", h["ascii"][:300])
json.dump(hits, open(f"{OUT}/hits_w{WAIT}.json", "w"), indent=1)

proc.terminate(); time.sleep(1)
subprocess.run(["wineserver", "-k"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
xv.terminate()

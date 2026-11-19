"""Linux/Wine 下的授权取证探针。

用途：DiskGenius 加壳后静态看不到授权代码，但它在 Wine 里能跑起来。本脚本把进程
作为自己的子进程启动（这样能过 ptrace_scope=1），等它起来后扫内存里与授权相关的
字符串，并把命中点周围的窗口落盘，方便离线分析。

用法：
    python -m pyauth.probe_wine --exe /path/to/DiskGenius.exe --wait 40 --out ./dumps
    python -m pyauth.probe_wine --exe ... --needle regcode --needle "mid="

前提：WINEPREFIX 指向一个 64 位前缀（win64），系统里有 /usr/lib/wine/wine64。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time

DEFAULT_NEEDLES = (
    b"regcode", b"regver", b"VerifyDate", b"LicenseInfo", b"OfflineReg.dat",
    b"Options.ini", b"appname", b"&check=", b"encryption=", b"skey", b"mid=",
    b"ShowLicense", b"Improveplan",
)

LOADER = "/usr/lib/wine/wine64"


def _launch(exe: str, wineprefix: str | None, display: str | None, cwd: str | None):
    env = dict(os.environ)
    if wineprefix:
        env["WINEPREFIX"] = wineprefix
    if display:
        env["DISPLAY"] = display
    loader = LOADER if os.path.exists(LOADER) else "wine"
    # 关键：必须由本进程直接拉起目标，才能读它的 /proc/<pid>/mem
    return subprocess.Popen([loader, os.path.basename(exe)], cwd=cwd or os.path.dirname(exe) or ".",
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def scan(pid: int, needles, outdir: str, window: int = 0x5000, max_per_needle: int = 6):
    hits = []
    mem = open("/proc/%d/mem" % pid, "rb", 0)
    regions = []
    for line in open("/proc/%d/maps" % pid):
        parts = line.split()
        if len(parts) < 2 or "r" not in parts[1]:
            continue
        lo, hi = (int(x, 16) for x in parts[0].split("-"))
        if hi - lo > 512 * 1024 * 1024:
            continue
        regions.append((lo, hi))

    os.makedirs(outdir, exist_ok=True)
    for lo, hi in regions:
        try:
            mem.seek(lo)
            data = mem.read(hi - lo)
        except OSError:
            continue
        for needle in needles:
            start, found = 0, 0
            while found < max_per_needle:
                idx = data.find(needle, start)
                if idx < 0:
                    break
                addr = lo + idx
                hits.append({"addr": hex(addr), "needle": needle.decode("latin1", "replace")})
                try:
                    mem.seek(max(0, addr - window // 2))
                    blob = mem.read(window)
                except OSError:
                    blob = b""
                name = "%x_%s.bin" % (addr, re.sub(r"[^A-Za-z0-9]", "_", needle.decode("latin1", "replace")))
                if blob:
                    with open(os.path.join(outdir, name), "wb") as fh:
                        fh.write(blob)
                found += 1
                start = idx + 1
    return hits


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pyauth.probe_wine")
    ap.add_argument("--exe", required=True, help="DiskGenius.exe 路径")
    ap.add_argument("--wineprefix", default=os.environ.get("WINEPREFIX"))
    ap.add_argument("--display", default=os.environ.get("DISPLAY", ":77"))
    ap.add_argument("--wait", type=float, default=40.0, help="启动后等多久再扫（壳解密需要时间）")
    ap.add_argument("--out", default="./dumps")
    ap.add_argument("--needle", action="append", default=None, help="自定义搜索串，可多次")
    ap.add_argument("--json", default=None, help="把命中清单写到这个 json")
    args = ap.parse_args(argv)

    needles = tuple(n.encode() for n in args.needle) if args.needle else DEFAULT_NEEDLES
    proc = _launch(os.path.abspath(args.exe), args.wineprefix, args.display, None)
    print("launched pid=%d, waiting %.0fs ..." % (proc.pid, args.wait))
    sys.stdout.flush()
    time.sleep(args.wait)
    if not os.path.exists("/proc/%d" % proc.pid):
        print("进程已退出，拿不到内存（检查 WINEPREFIX 是否 64 位）")
        return 2
    hits = scan(proc.pid, needles, args.out)
    print("hits=%d -> %s" % (len(hits), args.out))
    for h in hits[:40]:
        print("  %(addr)s  %(needle)r" % h)
    if args.json:
        json.dump(hits, open(args.json, "w"), ensure_ascii=False, indent=1)
    print("进程还活着（pid=%d），要继续分析就趁现在；结束时记得 kill %d" % (proc.pid, proc.pid))
    return 0


if __name__ == "__main__":
    sys.exit(main())

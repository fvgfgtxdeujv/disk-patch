#!/usr/bin/env python3
"""dump 运行期镜像：attach → 读 0x140000000 起 SizeOfImage → 落盘 → detach"""
import os, subprocess, sys, time, ctypes

PREFIX = "/tmp/zaka-20261119/wine64"
DGDIR = "/tmp/zaka-20261119/disk-patch/dg/DiskGenius"
INI = os.path.join(DGDIR, "Options.ini")
OUT = "/tmp/zaka-20261119"
LOADER = "/usr/lib/wine/wine64"

BASE = 0x140000000
SIZE = 0x2FF3000

# 带一个假 license，保证走授权路径
MARK = "ZAKAMARK7XQ9"
KEY = f"appname=DiskGenius&license={MARK}A1&user={MARK}B2&email={MARK}C3@x.com"
lines = ["[license]",
         'appname = "DiskGenius"', f'user = "{MARK}B2"', f'email = "{MARK}C3@x.com"',
         'regcode = "QK7X-M2PV-ZLHD-W8CT-RBNQ"', 'regver = "6.2.0.1829_x64_pro_eng"',
         'VerifyDate = "20991231"', f'key = "{KEY}"', ""]
if os.path.exists(INI): os.chmod(INI, 0o666)
open(INI, "wb").write(b"\xff\xfe" + ("\r\n".join(lines) + "\r\n").encode("utf-16-le"))

env = dict(os.environ, WINEPREFIX=PREFIX, DISPLAY=":95")
xv = subprocess.Popen(["Xvfb", ":95", "-screen", "0", "1280x900x24"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)
proc = subprocess.Popen([LOADER, "DiskGenius.exe"], cwd=DGDIR, env=env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(5)

libc = ctypes.CDLL("libc.so.6", use_errno=True)
if libc.ptrace(16, proc.pid, None, None) != 0:
    print("attach failed"); sys.exit(1)
os.waitpid(proc.pid, 0)
print("attached", proc.pid)

out = os.path.join(OUT, "image_run.bin")
with open(f"/proc/{proc.pid}/mem", "rb", 0) as mem, open(out, "wb") as f:
    got = 0
    for lo in range(0, SIZE, 0x100000):
        try:
            mem.seek(BASE + lo)
            b = mem.read(min(0x100000, SIZE - lo))
        except Exception:
            b = b"\x00" * min(0x100000, SIZE - lo)
        f.write(b)
        got += len(b)
print("dumped", hex(got), "->", out, os.path.getsize(out))

libc.ptrace(17, proc.pid, None, None)
proc.terminate(); time.sleep(1)
subprocess.run(["wineserver", "-k"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
xv.terminate()

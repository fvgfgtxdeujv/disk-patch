#!/usr/bin/env python3
"""把删除 Options.ini 的那次调用 patch 成 nop，看程序后续是否写注册表/改变状态。"""
import os, subprocess, time, ctypes, struct

PREFIX = "/tmp/zaka-20261119/wine64"
DGDIR = "/tmp/zaka-20261119/disk-patch/dg/DiskGenius"
INI = os.path.join(DGDIR, "Options.ini")
LOADER = "/usr/lib/wine/wine64"
KB = "/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/kernelbase.dll"
PATCH_AT = 0x14020b2d1
LO, HI = 0x140000000, 0x143000000

def export_rva(dll, name):
    d = open(dll, "rb").read()
    e = struct.unpack_from("<I", d, 0x3C)[0]; opt = e + 24
    magic = struct.unpack_from("<H", d, opt)[0]; dd = opt + (112 if magic == 0x20B else 96)
    exp = struct.unpack_from("<I", d, dd)[0]
    ns = struct.unpack_from("<H", d, e + 6)[0]; sh = e + 24 + struct.unpack_from("<H", d, e + 20)[0]
    secs = []
    for i in range(ns):
        o = sh + i * 40; vsz, va, rsz, ra = struct.unpack_from("<IIII", d, o + 8)
        secs.append((va, max(vsz, rsz), ra))
    def r2o(r):
        for va, sz, ra in secs:
            if va <= r < va + sz: return ra + (r - va)
    eo = r2o(exp); nn = struct.unpack_from("<I", d, eo + 24)[0]
    nr, orv, fr = (struct.unpack_from("<I", d, eo + x)[0] for x in (32, 36, 28))
    no, oo, fo = r2o(nr), r2o(orv), r2o(fr)
    for i in range(nn):
        nmo = r2o(struct.unpack_from("<I", d, no + i*4)[0])
        if d[nmo:d.index(b"\0", nmo)].decode(errors="ignore") == name:
            oi = struct.unpack_from("<H", d, oo + i*2)[0]
            return struct.unpack_from("<I", d, fo + oi*4)[0]

libc = ctypes.CDLL("libc.so.6", use_errno=True)
class Regs(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "r15","r14","r13","r12","rbp","rbx","r11","r10","r9","r8","rax","rcx","rdx",
        "rsi","rdi","orig_rax","rip","cs","eflags","rsp","ss","fs_base","gs_base","ds","es","fs","gs")]

def rd(pid, a, n):
    with open(f"/proc/{pid}/mem", "rb", 0) as m:
        m.seek(a); return m.read(n)
def wr(pid, a, b):
    with open(f"/proc/{pid}/mem", "r+b", 0) as m:
        m.seek(a); m.write(b)

key = "appname=DiskGenius&license=A&user=ZakaTest&email=zaka@example.com"
lines = ["[license]", 'appname = "DiskGenius"', 'user = "ZakaTest"',
         'email = "zaka@example.com"', 'regcode = "QK7X-M2PV-ZLHD-W8CT-RBNQ"',
         'regver = "6.2.0.1829_x64_pro_eng"', f'key = "{key}"', ""]
if os.path.exists(INI): os.chmod(INI, 0o666)
open(INI, "wb").write(b"\xff\xfe" + ("\r\n".join(lines) + "\r\n").encode("utf-16-le"))

env = dict(os.environ, WINEPREFIX=PREFIX, DISPLAY=":95")
xv = subprocess.Popen(["Xvfb", ":95", "-screen", "0", "1280x900x24"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)
proc = subprocess.Popen([LOADER, "DiskGenius.exe"], cwd=DGDIR, env=env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)
pid = proc.pid
libc.ptrace(16, pid, None, None); os.waitpid(pid, 0)

orig = rd(pid, PATCH_AT, 6)
print("原指令:", orig.hex())
wr(pid, PATCH_AT, b"\x90" * 6)
print("patched: True")
libc.ptrace(7, pid, None, None)  # PTRACE_CONT
time.sleep(6)
libc.ptrace(16, pid, None, None)
try: os.waitpid(pid, os.WNOHANG)
except Exception: pass
print("INI 还在:", os.path.exists(INI), os.path.getsize(INI) if os.path.exists(INI) else 0)
libc.ptrace(17, pid, None, None)
proc.terminate(); time.sleep(1)
subprocess.run(["wineserver", "-k"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
xv.terminate()
print("--- reg ---")
out = subprocess.run(["wine", "reg", "query", "HKCU\\Software\\Eassos\\DiskGenius", "/s"],
                     env=env, capture_output=True, text=True)
print("\n".join(l for l in out.stdout.splitlines() if l.strip()))

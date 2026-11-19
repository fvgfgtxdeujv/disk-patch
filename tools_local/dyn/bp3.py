#!/usr/bin/env python3
"""DeleteFileW 断点：抓删除 Options.ini 那一刻的完整候选调用链（读大栈窗口）"""
import os, subprocess, time, ctypes, struct

PREFIX = "/tmp/zaka-20261119/wine64"
DGDIR = "/tmp/zaka-20261119/disk-patch/dg/DiskGenius"
INI = os.path.join(DGDIR, "Options.ini")
LOADER = "/usr/lib/wine/wine64"
KB = "/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/kernelbase.dll"
LO, HI = 0x140000000, 0x143000000

def export_rva(dll, name):
    d = open(dll, "rb").read()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    opt = e + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    dd = opt + (112 if magic == 0x20B else 96)
    exp = struct.unpack_from("<I", d, dd)[0]
    ns = struct.unpack_from("<H", d, e + 6)[0]
    sh = e + 24 + struct.unpack_from("<H", d, e + 20)[0]
    secs = []
    for i in range(ns):
        o = sh + i * 40
        vsz, va, rsz, ra = struct.unpack_from("<IIII", d, o + 8)
        secs.append((va, max(vsz, rsz), ra))
    def r2o(r):
        for va, sz, ra in secs:
            if va <= r < va + sz: return ra + (r - va)
    eo = r2o(exp)
    nn = struct.unpack_from("<I", d, eo + 24)[0]
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

def rd(pid, addr, n):
    with open(f"/proc/{pid}/mem", "rb", 0) as m:
        m.seek(addr); return m.read(n)

def wr(pid, addr, data):
    with open(f"/proc/{pid}/mem", "r+b", 0) as m:
        m.seek(addr); m.write(data)

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
time.sleep(1.0)
if libc.ptrace(16, proc.pid, None, None) != 0:
    print("attach failed"); raise SystemExit
os.waitpid(proc.pid, 0)
pid = proc.pid

kb = None
for line in open(f"/proc/{pid}/maps"):
    if "kernelbase.dll" in line:
        kb = int(line.split("-")[0], 16); break
addr = kb + export_rva(KB, "DeleteFileW")
print("bp:", hex(addr))
orig = rd(pid, addr, 1)
wr(pid, addr, b"\xcc")

regs = Regs()
for _ in range(600):
    if libc.ptrace(7, pid, None, None) != 0: break
    _, st = os.waitpid(pid, 0)
    if os.WIFEXITED(st): break
    libc.ptrace(12, pid, None, ctypes.byref(regs))
    if abs(regs.rip - addr) <= 1:
        raw = rd(pid, regs.rcx, 400)
        nm = raw.decode("utf-16-le", errors="ignore").split("\0")[0]
        if "Options.ini" in nm:
            stack = rd(pid, regs.rsp, 0x3000)
            seen, chain = set(), []
            for off in range(0, len(stack) - 8, 8):
                v = int.from_bytes(stack[off:off+8], "little")
                if LO <= v < HI and v not in seen:
                    seen.add(v); chain.append(hex(v))
            print("DEL:", nm)
            print("chain:", chain[:24])
            break
wr(pid, addr, orig)
libc.ptrace(17, pid, None, None)
proc.terminate(); time.sleep(1)
subprocess.run(["wineserver", "-k"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
xv.terminate()

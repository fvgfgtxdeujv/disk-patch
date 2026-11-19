#!/usr/bin/env python3
"""用硬件执行断点（DR0）在删除封装入口下断，绕过 int3 反调试，抓精确调用者。"""
import os, subprocess, time, ctypes

PREFIX = "/tmp/zaka-20261119/wine64"
DGDIR = "/tmp/zaka-20261119/disk-patch/dg/DiskGenius"
INI = os.path.join(DGDIR, "Options.ini")
LOADER = "/usr/lib/wine/wine64"
FN = 0x14020b2a4
LO, HI = 0x140000000, 0x143000000
U_DEBUGREG = 848   # struct user->u_debugreg[0]

libc = ctypes.CDLL("libc.so.6", use_errno=True)
class Regs(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "r15","r14","r13","r12","rbp","rbx","r11","r10","r9","r8","rax","rcx","rdx",
        "rsi","rdi","orig_rax","rip","cs","eflags","rsp","ss","fs_base","gs_base","ds","es","fs","gs")]

def rd(pid, a, n):
    with open(f"/proc/{pid}/mem", "rb", 0) as m:
        m.seek(a); return m.read(n)

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
time.sleep(4.6)
pid = proc.pid
if libc.ptrace(16, pid, None, None) != 0:
    print("attach fail", ctypes.get_errno()); raise SystemExit
os.waitpid(pid, 0)
print("head:", rd(pid, FN, 8).hex())

def set_dr(idx, value):
    addr = ctypes.c_void_p(U_DEBUGREG + idx * 8)
    return libc.ptrace(6, pid, addr, ctypes.c_void_p(value))   # PTRACE_POKEUSER

ok1 = set_dr(0, FN)
ok2 = set_dr(7, 0x1)      # L0=1, RW0=00(执行), LEN0=00
print("DR0:", ok1, " DR7:", ok2)

regs = Regs()
hits = 0
for _ in range(4000):
    if libc.ptrace(7, pid, None, None) != 0:
        print("cont err", ctypes.get_errno()); break
    _, st = os.waitpid(pid, 0)
    if os.WIFEXITED(st):
        print("exited"); break
    sig = os.WSTOPSIG(st)
    libc.ptrace(12, pid, None, ctypes.byref(regs))
    if sig == 5 and abs(regs.rip - FN) <= 1:      # SIGTRAP
        hits += 1
        chain, rbp = [], regs.rbp
        for _d in range(8):
            if not (0x10000 < rbp < 0x7fffffffffff): break
            fr = rd(pid, rbp, 16)
            ret = int.from_bytes(fr[8:16], "little")
            prev = int.from_bytes(fr[0:8], "little")
            if not (LO <= ret < HI): break
            chain.append(hex(ret)); rbp = prev
        print(f"HIT#{hits} rcx={hex(regs.rcx)} chain={chain}")
        if hits >= 4: break
set_dr(0, 0); set_dr(7, 0)
libc.ptrace(17, pid, None, None)
proc.terminate(); time.sleep(1)
subprocess.run(["wineserver","-k"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
xv.terminate()

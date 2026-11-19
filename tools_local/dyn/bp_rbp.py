#!/usr/bin/env python3
"""在删除函数入口 0x14020b2a4 下断点，沿 RBP 链精确回溯调用者。"""
import os, subprocess, time, ctypes

PREFIX = "/tmp/zaka-20261119/wine64"
DGDIR = "/tmp/zaka-20261119/disk-patch/dg/DiskGenius"
INI = os.path.join(DGDIR, "Options.ini")
LOADER = "/usr/lib/wine/wine64"
FN = 0x14020b2a4
LO, HI = 0x140000000, 0x143000000

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
time.sleep(4.5)
pid = proc.pid
if libc.ptrace(16, pid, None, None) != 0:
    print("attach fail"); raise SystemExit
os.waitpid(pid, 0)

probe = rd(pid, FN, 8)
print("函数头:", probe.hex())
orig = rd(pid, FN, 1)
wr(pid, FN, b"\xcc")

regs = Regs()
hits = 0
for _ in range(2000):
    if libc.ptrace(7, pid, None, None) != 0: break
    _, st = os.waitpid(pid, 0)
    if os.WIFEXITED(st): print("exited"); break
    libc.ptrace(12, pid, None, ctypes.byref(regs))
    if abs(regs.rip - FN) <= 1:
        hits += 1
        chain = []
        rbp = regs.rbp
        for depth in range(8):
            try:
                if not (0x10000 < rbp < 0x7fffffffffff): break
                frame = rd(pid, rbp, 16)
                ret = int.from_bytes(frame[8:16], "little")
                prev = int.from_bytes(frame[0:8], "little")
                if not (LO <= ret < HI): break
                chain.append(hex(ret)); rbp = prev
            except Exception:
                break
        print(f"HIT#{hits} 参数rcx={hex(regs.rcx)} 链={chain}")
        if hits >= 6:
            break
wr(pid, FN, orig)
libc.ptrace(17, pid, None, None)
proc.terminate(); time.sleep(1)
subprocess.run(["wineserver","-k"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
xv.terminate()

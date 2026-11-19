#!/usr/bin/env python3
"""在 GetPrivateProfileStringW 下断点，抓读取 key 的位置和调用链。"""
import os, subprocess, time, ctypes, struct

PREFIX = "/tmp/zaka-20261119/wine64"
DGDIR = "/tmp/zaka-20261119/disk-patch/dg/DiskGenius"
INI = os.path.join(DGDIR, "Options.ini")
LOADER = "/usr/lib/wine/wine64"
KERNELBASE = "/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/kernel32.dll"
BASE_LO, BASE_HI = 0x140000000, 0x143000000

def export_rva(dll, name):
    d = open(dll, "rb").read()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    opt = e + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    dd = opt + (112 if magic == 0x20B else 96)
    exp_rva = struct.unpack_from("<I", d, dd)[0]
    nsec = struct.unpack_from("<H", d, e + 6)[0]
    sh = e + 24 + struct.unpack_from("<H", d, e + 20)[0]
    secs = []
    for i in range(nsec):
        o = sh + i * 40
        vsz, va, rsz, ra = struct.unpack_from("<IIII", d, o + 8)
        secs.append((va, max(vsz, rsz), ra))
    def r2o(r):
        for va, sz, ra in secs:
            if va <= r < va + sz: return ra + (r - va)
        return None
    eo = r2o(exp_rva)
    nn = struct.unpack_from("<I", d, eo + 24)[0]
    nrva, orva, frva = struct.unpack_from("<III", d, eo + 32)[0], struct.unpack_from("<I", d, eo + 36)[0], struct.unpack_from("<I", d, eo + 28)[0]
    no, oo, fo = r2o(nrva), r2o(orva), r2o(frva)
    for i in range(nn):
        nmo = r2o(struct.unpack_from("<I", d, no + i*4)[0])
        end = d.index(b"\0", nmo)
        if d[nmo:end].decode(errors="ignore") == name:
            oi = struct.unpack_from("<H", d, oo + i*2)[0]
            return struct.unpack_from("<I", d, fo + oi*4)[0]
    return None

libc = ctypes.CDLL("libc.so.6", use_errno=True)
class Regs(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "r15","r14","r13","r12","rbp","rbx","r11","r10","r9","r8","rax","rcx","rdx",
        "rsi","rdi","orig_rax","rip","cs","eflags","rsp","ss","fs_base","gs_base","ds","es","fs","gs")]

def wide(pid, p, n=260):
    try:
        fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
        raw = os.pread(fd, n*2, p); os.close(fd)
        return raw.decode("utf-16-le", errors="ignore").split("\0")[0]
    except Exception:
        return "?"

def main():
    key = "appname=DiskGenius&license=A&user=ZakaTest&email=zaka@example.com"
    lines = ["[license]", 'appname = "DiskGenius"', 'user = "ZakaTest"',
             'email = "zaka@example.com"', 'regcode = "QK7X-M2PV-ZLHD-W8CT-RBNQ"',
             'regver = "6.2.0.1829_x64_pro_eng"', f'key = "{key}"', ""]
    if os.path.exists(INI): os.chmod(INI, 0o666)
    open(INI,"wb").write(b"\xff\xfe" + ("\r\n".join(lines)+"\r\n").encode("utf-16-le"))

    env = dict(os.environ, WINEPREFIX=PREFIX, DISPLAY=":95")
    xv = subprocess.Popen(["Xvfb",":95","-screen","0","1280x900x24"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    proc = subprocess.Popen([LOADER,"DiskGenius.exe"], cwd=DGDIR, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    if libc.ptrace(16, proc.pid, None, None) != 0:
        print("attach failed"); return
    os.waitpid(proc.pid, 0)

    kb = None
    for line in open(f"/proc/{proc.pid}/maps"):
        if "kernel32.dll" in line:
            kb = int(line.split("-")[0], 16); break
    print("kernelbase:", hex(kb))
    for api in ("GetPrivateProfileStringW","GetPrivateProfileIntW","WritePrivateProfileStringW"):
        rva = export_rva(KERNELBASE, api)
        print(f"  {api}: {hex(rva) if rva else None}")
    rva = export_rva(KERNELBASE, "GetPrivateProfileStringW")
    addr = kb + rva

    def memfd(flags=os.O_RDONLY): return os.open(f"/proc/{proc.pid}/mem", flags)
    fd = memfd(os.O_RDWR)
    orig = os.pread(fd, 1, addr)
    os.pwrite(fd, b"\xcc", addr); os.close(fd)

    regs = Regs(); hits = 0
    for _ in range(3000):
        if libc.ptrace(7, proc.pid, None, None) != 0: break
        pid, st = os.waitpid(proc.pid, 0)
        if os.WIFEXITED(st): print("exited"); break
        libc.ptrace(12, proc.pid, None, ctypes.byref(regs))
        if abs(regs.rip - addr) <= 1:
            app = wide(proc.pid, regs.rcx); keyn = wide(proc.pid, regs.rdx)
            if keyn and keyn.lower() in ("key","license","regcode","verifydate","user","email","regver","appname"):
                stack = os.pread(memfd(), 0x300, regs.rsp)
                cands = []
                for off in range(0, len(stack)-8, 8):
                    v = int.from_bytes(stack[off:off+8],"little")
                    if BASE_LO <= v < BASE_HI:
                        cands.append(hex(v))
                print(f"HIT [{app}] [{keyn}]  rsp={hex(regs.rsp)}")
                print("   stack:", cands[:10])
                hits += 1
                if hits >= 8: break
    fd = memfd(os.O_RDWR); os.pwrite(fd, orig, addr); os.close(fd)
    libc.ptrace(17, proc.pid, None, None)
    proc.terminate(); time.sleep(1)
    subprocess.run(["wineserver","-k"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    xv.terminate()

main()

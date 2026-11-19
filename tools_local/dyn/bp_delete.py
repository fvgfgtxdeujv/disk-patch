#!/usr/bin/env python3
"""在 kernelbase!DeleteFileW 下断点，抓调用者返回地址（定位“判定失败→删除”的分支）。"""
import os, subprocess, sys, time, ctypes, struct, glob

PREFIX = "/tmp/zaka-20261119/wine64"
DGDIR = "/tmp/zaka-20261119/disk-patch/dg/DiskGenius"
INI = os.path.join(DGDIR, "Options.ini")
LOADER = "/usr/lib/wine/wine64"
KERNELBASE = "/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/kernelbase.dll"
BASE_LO, BASE_HI = 0x140000000, 0x143000000

# ---- PE 导出解析（纯手工，不依赖 pefile）----
def export_rva(dll, name):
    d = open(dll, "rb").read()
    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    dd = opt + (112 if magic == 0x20B else 96)
    exp_rva, exp_sz = struct.unpack_from("<II", d, dd)
    secs = struct.unpack_from("<H", d, e_lfanew + 6)[0]
    sh = e_lfanew + 24 + struct.unpack_from("<H", d, e_lfanew + 20)[0]
    sections = []
    for i in range(secs):
        off = sh + i * 40
        vsz, va, rsz, ra = struct.unpack_from("<IIII", d, off + 8)
        sections.append((va, vsz, ra, rsz))
    def r2o(rva):
        for va, vsz, ra, rsz in sections:
            if va <= rva < va + max(vsz, rsz):
                return ra + (rva - va)
        return None
    eo = r2o(exp_rva)
    nnames = struct.unpack_from("<I", d, eo + 24)[0]
    names_rva, ords_rva = struct.unpack_from("<II", d, eo + 32)
    funcs_rva = struct.unpack_from("<I", d, eo + 28)[0]
    no, oo = r2o(names_rva), r2o(ords_rva)
    fo = r2o(funcs_rva)
    for i in range(nnames):
        nr = struct.unpack_from("<I", d, no + i * 4)[0]
        nm_off = r2o(nr)
        end = d.index(b"\0", nm_off)
        if d[nm_off:end] == name.encode():
            oi = struct.unpack_from("<H", d, oo + i * 2)[0]
            frva = struct.unpack_from("<I", d, fo + oi * 4)[0]
            return frva
    return None

libc = ctypes.CDLL("libc.so.6", use_errno=True)
PTRACE_ATTACH, PTRACE_DETACH, PTRACE_CONT, PTRACE_PEEKDATA, PTRACE_POKEDATA = 16, 17, 7, 2, 5
PTRACE_GETREGS = 12

class user_regs_struct(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "r15","r14","r13","r12","rbp","rbx","r11","r10","r9","r8","rax","rcx","rdx",
        "rsi","rdi","orig_rax","rip","cs","eflags","rsp","ss","fs_base","gs_base",
        "ds","es","fs","gs")]

def maps(pid):
    out = []
    for line in open(f"/proc/{pid}/maps"):
        p = line.split()
        lo, hi = (int(x, 16) for x in p[0].split("-"))
        path = p[-1] if len(p) >= 6 else ""
        out.append((lo, hi, path))
    return out

def main():
    # 准备一个“会被删”的 key（d3 组合稳定触发）
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
    time.sleep(1.2)

    if libc.ptrace(PTRACE_ATTACH, proc.pid, None, None) != 0:
        print("attach failed"); return
    os.waitpid(proc.pid, 0)
    print("attached", proc.pid)

    # 找 kernelbase 映射
    kb = None
    for lo, hi, path in maps(proc.pid):
        if "kernelbase.dll" in path:
            kb = lo; break
    print("kernelbase base:", hex(kb) if kb else None)
    if not kb:
        libc.ptrace(PTRACE_DETACH, proc.pid, None, None); return

    rva = export_rva(KERNELBASE, "DeleteFileW")
    print("DeleteFileW rva:", hex(rva) if rva else None)
    if not rva: return
    addr = kb + rva
    print("breakpoint at", hex(addr))

    def rd(a, n=8):
        return int.from_bytes(os.pread(os.open(f"/proc/{proc.pid}/mem", os.O_RDWR), n, a), "little")
    def wr(a, b):
        fd = os.open(f"/proc/{proc.pid}/mem", os.O_RDWR)
        os.pwrite(fd, b, a); os.close(fd)

    orig = os.pread(os.open(f"/proc/{proc.pid}/mem", os.O_RDONLY), 1, addr)
    wr(addr, b"\xcc")

    hits = []
    regs = user_regs_struct()
    for round_ in range(400):
        if libc.ptrace(PTRACE_CONT, proc.pid, None, None) != 0: break
        pid, status = os.waitpid(proc.pid, 0)
        if os.WIFEXITED(status): print("exited"); break
        libc.ptrace(PTRACE_GETREGS, proc.pid, None, ctypes.byref(regs))
        if regs.rip == addr + 1 or regs.rip == addr:
            # 抓到断点：读栈找 exe 范围内的返回地址
            stack = os.pread(os.open(f"/proc/{proc.pid}/mem", os.O_RDONLY), 0x400, regs.rsp)
            cands = []
            for off in range(0, len(stack) - 8, 8):
                v = int.from_bytes(stack[off:off+8], "little")
                if BASE_LO <= v < BASE_HI:
                    cands.append((off, hex(v)))
            print("HIT rip=", hex(regs.rip), "rcx=", hex(regs.rcx), "rdx=", hex(regs.rdx))
            print("  stack cands:", cands[:8])
            hits.append(cands)
            break
    wr(addr, orig)
    os.close(os.open(f"/proc/{proc.pid}/mem", os.O_RDWR)) if False else None
    libc.ptrace(PTRACE_DETACH, proc.pid, None, None)
    proc.terminate(); time.sleep(1)
    subprocess.run(["wineserver", "-k"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    xv.terminate()

main()

#!/usr/bin/env python3
"""vmp_tracer.py —— DiskGenius (Themida) 派发器指令级探针（本机 Wine）

原理：改派发表（数据）→ 全部指向一段记录桩 → 桩记录 [ctx+0xBC] 与 [IP] 8 字节
→ 查影子表拿回真 handler → jmp rsi。不修改任何指令字节，语义等价。

用法：
    python3 tools/vmp_tracer.py --wait 4 --table 0x1421080ab --count 661 --seconds 6
    python3 tools/vmp_tracer.py --table 0x141d8df04 --count 1096   # 注意：这张表 hook 会崩

输出 vm_trace_local.txt：每行 "<IP hex> <8 bytes hex>"

前提：Wine 9.0、Xvfb、目标程序在 --exe-dir 下、ptrace 可用。
"""
import argparse, ctypes, os, shutil, struct, subprocess, sys, time

VMP_LO, VMP_HI = 0x1419D4000, 0x142780000   # .vmp 段（RWX），本版本固定
LOADER = "/usr/lib/wine/wine64"


def attach_helpers():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.ptrace.restype = ctypes.c_long          # 关键：默认 c_int 会截断 64 位地址
    libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
    return libc


def peek(libc, pid, addr):
    v = libc.ptrace(2, pid, ctypes.c_void_p(addr), None)
    return None if v == -1 else v & 0xFFFFFFFFFFFFFFFF


def poke(libc, pid, addr, val):
    return libc.ptrace(5, pid, ctypes.c_void_p(addr), ctypes.c_void_p(val & 0xFFFFFFFFFFFFFFFF))


def rd(pid, addr, n):
    with open("/proc/%d/mem" % pid, "rb", 0) as f:
        f.seek(addr)
        return f.read(n)


def wr(pid, addr, data):
    with open("/proc/%d/mem" % pid, "r+b", 0) as f:
        f.seek(addr)
        f.write(data)


def make_stub(shadow, buf, cnt):
    S = b"\x9c"                          # pushfq
    S += b"\x50\x51\x52\x53"             # push rax rcx rdx rbx
    S += b"\x41\x52\x41\x53"             # push r10 r11
    S += bytes.fromhex("488b85bc000000")  # mov rax,[rbp+0xBC]   <- VM IP 槽
    S += b"\x48\xba" + struct.pack("<Q", buf)
    S += b"\x48\xb9" + struct.pack("<Q", cnt)
    S += bytes.fromhex("4c8b11")          # mov r10,[rcx]
    S += b"\x4d\x89\xd3"                  # mov r11,r10
    S += b"\x49\xc1\xe3\x04"              # shl r11,4
    S += bytes.fromhex("488b18")          # mov rbx,[rax]
    S += bytes.fromhex("4a89041a")        # mov [rdx+r11],rax
    S += bytes.fromhex("4a895c1a08")      # mov [rdx+r11+8],rbx
    S += bytes.fromhex("49ffc2")          # inc r10
    S += bytes.fromhex("4981e2ff010000")  # and r10,0x1ff
    S += bytes.fromhex("4c8911")          # mov [rcx],r10
    S += b"\x49\xba" + struct.pack("<Q", shadow)
    S += bytes.fromhex("4f8b343a")        # mov rsi,[r10+r15]
    S += b"\x41\x5b\x41\x5a"              # pop r11 r10
    S += b"\x5b\x5a\x59\x58"              # pop rbx rdx rcx rax
    S += b"\x9d"                          # popfq
    S += b"\xff\xe6"                      # jmp rsi
    return S


def find_zone(pid, need=0x3400):
    if VMP_HI - VMP_LO > 0x2000000:
        raise SystemExit("段范围异常")
    blob = rd(pid, VMP_LO, VMP_HI - VMP_LO)
    run = start = 0
    for i, b in enumerate(blob):
        if b == 0:
            if run == 0:
                start = i
            run += 1
            if run >= need:
                return VMP_LO + start
        else:
            run = 0
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prefix", default=os.path.expanduser("~/wine64"))
    ap.add_argument("--exe-dir", default="dg/DiskGenius")
    ap.add_argument("--exe", default="DiskGenius.exe")
    ap.add_argument("--display", default=":98")
    ap.add_argument("--wait", type=float, default=4.0, help="启动后多少秒 attach")
    ap.add_argument("--table", default="0x1421080ab")
    ap.add_argument("--count", type=int, default=661)
    ap.add_argument("--seconds", type=float, default=6.0, help="hook 后观察多久")
    ap.add_argument("--out", default="vm_trace_local.txt")
    a = ap.parse_args()

    TBL = int(a.table, 16)
    libc = attach_helpers()
    exe_dir = os.path.abspath(a.exe_dir)
    if not os.path.exists(os.path.join(exe_dir, a.exe)):
        raise SystemExit("找不到 %s" % os.path.join(exe_dir, a.exe))

    env = dict(os.environ, WINEPREFIX=os.path.abspath(a.prefix), DISPLAY=a.display)
    xvfb = None
    if a.display and shutil.which("Xvfb"):
        xvfb = subprocess.Popen(["Xvfb", a.display, "-screen", "0", "1280x900x24"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)

    proc = subprocess.Popen([LOADER, a.exe], cwd=exe_dir, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(a.wait)
    if libc.ptrace(16, proc.pid, None, None) != 0:
        raise SystemExit("attach 失败（检查 ptrace 权限）")
    os.waitpid(proc.pid, 0)
    print("[+] attached", proc.pid, flush=True)

    origs = [peek(libc, proc.pid, TBL + i * 8) for i in range(a.count)]
    live = [x for x in origs if x]
    print("[+] table %#x  count=%d  有效项=%d  T[0]=%#x" % (TBL, a.count, len(live), origs[0] or 0), flush=True)

    zone = find_zone(proc.pid)
    if not zone:
        print("[-] .vmp 里找不到足够大的零洞", flush=True)
        proc.kill()
        return
    STUB, CNT, SHADOW, BUF = zone, zone + 0x100, zone + 0x200, zone + 0x1800
    print("[+] zone=%#x" % zone, flush=True)

    wr(proc.pid, CNT, struct.pack("<Q", 0))
    wr(proc.pid, SHADOW, b"".join(struct.pack("<Q", h or 0) for h in origs))
    stub = make_stub(SHADOW, BUF, CNT)
    wr(proc.pid, STUB, stub)
    for i in range(a.count):
        if origs[i]:
            poke(libc, proc.pid, TBL + i * 8, STUB)
    print("[+] stub 已装 (%d 字节)，表已全部指向它" % len(stub), flush=True)

    libc.ptrace(7, proc.pid, None, None)   # CONT
    time.sleep(a.seconds)

    n = peek(libc, proc.pid, CNT)
    if n is None:
        print("[-] 进程已退出", flush=True)
        n = 0
    n = min(n, 0x1ff)
    print("[+] recorded =", n, flush=True)

    recs = []
    if n:
        raw = rd(proc.pid, BUF, n * 16)
        recs = [struct.unpack_from("<QQ", raw, i) for i in range(0, len(raw) - 15, 16)]
    with open(a.out, "w") as f:
        for ip, by in recs:
            line = "%#x %s" % (ip, struct.pack("<Q", by).hex())
            print("    " + line, flush=True)
            f.write(line + "\n")

    # 还原表
    for i in range(a.count):
        if origs[i]:
            poke(libc, proc.pid, TBL + i * 8, origs[i])
    libc.ptrace(17, proc.pid, None, None)   # DETACH
    try:
        proc.kill()
    except Exception:
        pass
    subprocess.run(["wineserver", "-k"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if xvfb:
        xvfb.terminate()
    print("[+] trace ->", a.out, flush=True)


if __name__ == "__main__":
    main()

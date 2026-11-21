# -*- coding: utf-8 -*-
"""运行期断点探针：对比伪造 key 下 VM 消息投递 / 请求对象 / 发送点 的差异。
需管理员运行（目标 manifest 要求 elevation，且要写 HKLM）。
"""
import argparse, ctypes, json, os, struct, sys, time, threading, winreg
from ctypes import wintypes as wt

BASE_IMG = 0x140000000
RVA_BPS = {
    0x140199e71: 'vmcall_0x479',   # call [0x140630538] 前
    0x1403f3f94: 'run_request',
    0x14058d684: 'send',
    0x1400d8045: 'md5_reg_payload',
}
LIMIT = 40

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
class STARTUPINFOW(ctypes.Structure):
    _fields_ = [('cb', wt.DWORD), ('lpReserved', wt.LPWSTR), ('lpDesktop', wt.LPWSTR),
                ('lpTitle', wt.LPWSTR), ('dwX', wt.DWORD), ('dwY', wt.DWORD),
                ('dwXSize', wt.DWORD), ('dwYSize', wt.DWORD),
                ('dwXCountChars', wt.DWORD), ('dwYCountChars', wt.DWORD),
                ('dwFillAttribute', wt.DWORD), ('dwFlags', wt.DWORD),
                ('wShowWindow', wt.WORD), ('cbReserved2', wt.WORD),
                ('lpReserved2', ctypes.c_void_p), ('hStdInput', wt.HANDLE),
                ('hStdOutput', wt.HANDLE), ('hStdError', wt.HANDLE)]
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [('hProcess', wt.HANDLE), ('hThread', wt.HANDLE),
                ('dwProcessId', wt.DWORD), ('dwThreadId', wt.DWORD)]
class THREADENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', wt.DWORD), ('cntUsage', wt.DWORD), ('th32ThreadID', wt.DWORD),
                ('th32OwnerProcessID', wt.DWORD), ('tpBasePri', wt.LONG),
                ('tpDeltaPri', wt.LONG), ('dwFlags', wt.DWORD)]

k32.CreateProcessW.argtypes = [wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
                               wt.BOOL, wt.DWORD, ctypes.c_void_p, wt.LPCWSTR,
                               ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)]
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.POINTER(ctypes.c_size_t)]
k32.WaitForDebugEvent.argtypes = [ctypes.c_void_p, wt.DWORD]
k32.ContinueDebugEvent.argtypes = [wt.DWORD, wt.DWORD, wt.DWORD]
k32.GetThreadContext.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.SetThreadContext.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]; k32.OpenThread.restype = wt.HANDLE
k32.SuspendThread.argtypes = [wt.HANDLE]; k32.ResumeThread.argtypes = [wt.HANDLE]
k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]; k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.Thread32First.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.Thread32Next.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.DebugBreakProcess.argtypes = [wt.HANDLE]
k32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.FlushInstructionCache.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t]

class DBG(ctypes.Structure):
    _fields_ = [('code', wt.DWORD), ('pid', wt.DWORD), ('tid', wt.DWORD), ('pad', wt.DWORD),
                ('u', ctypes.c_byte * 168)]

def rd(h, addr, n):
    b = ctypes.create_string_buffer(n); got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), b, n, ctypes.byref(got)):
        return None
    return b.raw[:got.value]

def wr(h, addr, data):
    buf = ctypes.create_string_buffer(data, len(data))
    got = ctypes.c_size_t(0)
    return bool(k32.WriteProcessMemory(h, ctypes.c_void_p(addr), ctypes.cast(buf, ctypes.c_void_p),
                                       len(data), ctypes.byref(got)))

def u64(v): return struct.unpack('<Q', v)[0]
def u64m(buf, off): return struct.unpack_from('<Q', buf, off)[0]

def wide(h, addr, n=400):
    raw = rd(h, addr, n * 2)
    if not raw: return None
    s = raw.decode('utf-16-le', 'replace').split('\x00')[0]
    return s if s and all(0x20 <= ord(c) <= 0x7e for c in s) else (s if s else None)

def reg_set_license(data):
    for sub in ('Reg', 'CReg'):
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r'SOFTWARE\Eassos\DiskGenius\%s' % sub, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, 'license', 0, winreg.REG_BINARY, data); k.Close()
        except OSError as e:
            print('reg set fail', sub, e)

def reg_backup():
    bak = {}
    for sub in ('Reg', 'CReg'):
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r'SOFTWARE\Eassos\DiskGenius\%s' % sub, 0, winreg.KEY_READ)
            try:
                v, t = winreg.QueryValueEx(k, 'license')
            except OSError:
                v, t = None, None
            bak[sub] = (v, t); k.Close()
        except OSError:
            bak[sub] = (None, None)
    return bak

def reg_restore(bak):
    for sub, (v, t) in bak.items():
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r'SOFTWARE\Eassos\DiskGenius\%s' % sub, 0, winreg.KEY_SET_VALUE)
            if v is None:
                try: winreg.DeleteValue(k, 'license')
                except OSError: pass
            else:
                winreg.SetValueEx(k, 'license', 0, t, v)
            k.Close()
        except OSError as e:
            print('reg restore fail', sub, e)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--key', default=None, help='写入的 key 文本；省略=空')
    ap.add_argument('--seconds', type=int, default=30)
    ap.add_argument('--out', default=None)
    a = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    exe = os.path.join(root, 'out', 'runtime', 'DiskGenius', 'DiskGenius.exe')
    game = os.path.dirname(exe)
    out = a.out or os.path.join(root, 'out', '_dg_dbg_%s.jsonl' % (a.key or 'empty'))
    f = open(out, 'w', encoding='utf-8')
    def log(o):
        o['t'] = round(time.time() - T0, 3)
        f.write(json.dumps(o, ensure_ascii=False) + '\n'); f.flush()

    bak = reg_backup()
    reg_set_license(b'' if a.key is None else a.key.encode('utf-16-le'))

    si = STARTUPINFOW(); si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer('"%s"' % exe)
    ok = k32.CreateProcessW(exe, cmd, None, None, False,
                            0x00000002 | 0x00000010, None, game, ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        print('CreateProcess fail', ctypes.get_last_error()); reg_restore(bak); return 1
    h, pid, tid0 = pi.hProcess, pi.dwProcessId, pi.dwThreadId
    # 抹掉调试标记，降低 VMP 反调试触发概率
    try:
        ntdll = ctypes.WinDLL('ntdll')
        ntdll.NtQueryInformationProcess.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                    ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        pbi = ctypes.create_string_buffer(48)
        ret = ctypes.c_ulong(0)
        ntdll.NtQueryInformationProcess(h, 0, pbi, 48, ctypes.byref(ret))
        peb = u64(pbi.raw[8:16])
        if peb:
            wr(h, peb + 2, b'\x00'); wr(h, peb + 0xBC, b'\x00\x00\x00\x00')
    except Exception as e:
        print('peb patch skip', e)
    T0 = time.time()
    log({'ev': 'start', 'pid': pid, 'key': a.key})

    base = None; bps = {}; orig = {}; armed = False; hits = {}
    pending = {}
    ctxbuf = ctypes.create_string_buffer(0x500)

    def getctx(tidh):
        ctypes.memset(ctxbuf, 0, 0x500)
        struct.pack_into('<I', ctxbuf, 0x30, 0x0010000B)
        if not k32.GetThreadContext(tidh, ctypes.byref(ctxbuf)):
            return None
        return ctxbuf

    def arm():
        nonlocal armed
        good = 0
        for va, name in RVA_BPS.items():
            addr = base + (va - BASE_IMG)
            b = rd(h, addr, 16)
            if not b or (va in EXPECT and b != EXPECT[va]):
                log({'ev': 'arm_skip', 'bp': name, 'addr': hex(addr),
                     'got': b.hex() if b else None}); continue
            orig[name] = b[:1]
            if wr(h, addr, b'\xcc'):
                good += 1
        k32.FlushInstructionCache(h, None, 0)
        armed = True
        log({'ev': 'armed', 'count': good, 'base': hex(base)})

    def suspend_all():
        snap = k32.CreateToolhelp32Snapshot(0x00000004, 0)
        hs = []
        if snap and int(snap) != -1:
            te = THREADENTRY32(); te.dwSize = ctypes.sizeof(te)
            if k32.Thread32First(snap, ctypes.byref(te)):
                while True:
                    if te.th32OwnerProcessID == pid:
                        th = k32.OpenThread(0x0002 | 0x0008, False, te.th32ThreadID)
                        if th:
                            k32.SuspendThread(th); hs.append(th)
                    if not k32.Thread32Next(snap, ctypes.byref(te)): break
            k32.CloseHandle(snap)
        return hs

    def resume_all(hs):
        for th in hs:
            k32.ResumeThread(th); k32.CloseHandle(th)

    # 运行期代码是加密的：轮询到目标处字节与运行期 dump 一致后，再打断点
    EXPECT = {}
    try:
        dump = open(os.path.join(root, 'out', 'moddump_140000000.bin'), 'rb').read()
        for va in RVA_BPS:
            EXPECT[va] = dump[va - BASE_IMG: va - BASE_IMG + 16]
    except OSError:
        pass
    log({'ev': 'expect', 'count': len(EXPECT)})
    base_evt = threading.Event()

    def watchdog():
        while not base_evt.wait(0.05):
            if time.time() > T0 + 25:
                return
        dl = time.time() + 20
        logged = False
        while time.time() < dl:
            if base:
                for va, ex in EXPECT.items():
                    got = rd(h, base + (va - BASE_IMG), 16)
                    if not logged:
                        logged = True
                        log({'ev': 'poll', 'bp': RVA_BPS[va],
                             'got': got.hex() if got else None, 'exp': ex.hex()})
                    if got and got == ex:
                        log({'ev': 'decrypted', 'bp': RVA_BPS[va], 'at': round(time.time() - T0, 3)})
                        k32.DebugBreakProcess(h)
                        return
            time.sleep(0.015)
    threading.Thread(target=watchdog, daemon=True).start()

    end = time.time() + a.seconds
    dbg = DBG()
    while time.time() < end:
        if not k32.WaitForDebugEvent(ctypes.byref(dbg), 500):
            continue
        code, ep, et = dbg.code, dbg.pid, dbg.tid
        cont = 0x00010002
        try:
            if code == 3:  # CREATE_PROCESS
                base = u64m(dbg.u, 24)
                h2 = u64m(dbg.u, 0)
                if int(h2) not in (0, -1): k32.CloseHandle(ctypes.c_void_p(h2))
                log({'ev': 'create', 'base': hex(base)})
                base_evt.set()
            elif code == 6:  # LOAD_DLL
                pass
            elif code == 1:  # EXCEPTION
                ecode = struct.unpack_from('<I', dbg.u, 0)[0]
                eaddr = u64m(dbg.u, 16)
                if ecode == 0x80000003:  # breakpoint
                    name = None
                    if armed:
                        for va, nm in RVA_BPS.items():
                            if eaddr == base + (va - BASE_IMG) + 1:
                                name = nm; break
                    if name:
                        hits[name] = hits.get(name, 0) + 1
                        th = k32.OpenThread(0x0002 | 0x0008, False, et)
                        cx = getctx(th) if th else None
                        rec = {'ev': 'bp', 'bp': name, 'n': hits[name]}
                        if cx:
                            g = lambda off, fmt='<Q': struct.unpack_from(fmt, cx, off)[0]
                            rec['rcx'] = hex(g(0x80)); rec['rdx'] = hex(g(0x88))
                            rec['r8'] = hex(g(0xB8)); rec['r9'] = hex(g(0xC0))
                            rec['rip'] = hex(g(0xF8)); rec['rsi'] = hex(g(0xA8))
                            if name == 'send':
                                rec['url'] = wide(h, g(0xB8))
                                rec['resp'] = wide(h, g(0x88))
                            if name == 'md5_reg_payload':
                                rec['buf_r8'] = wide(h, g(0xB8))
                        if hits[name] <= LIMIT: log(rec)
                        if cx or not th:
                            # 恢复原字节 + 单步
                            va = [v for v, n2 in RVA_BPS.items() if n2 == name][0]
                            addr = base + (va - BASE_IMG)
                            if name in orig: wr(h, addr, orig[name])
                            if cx:
                                struct.pack_into('<Q', cx, 0xF8, addr)
                                flags = struct.unpack_from('<I', cx, 0x44)[0] | 0x100
                                struct.pack_into('<I', cx, 0x44, flags)
                                k32.SetThreadContext(th, ctypes.byref(cx))
                            pending[et] = name
                        if th: k32.CloseHandle(th)
                        cont = 0x00010002
                    else:
                        if not armed:
                            hs = suspend_all(); arm(); resume_all(hs)
                        cont = 0x00010002
                elif ecode == 0x80000004:  # single step
                    nm = pending.pop(et, None)
                    if nm:
                        va = [v for v, n2 in RVA_BPS.items() if n2 == nm][0]
                        wr(h, base + (va - BASE_IMG), b'\xcc')
                        th = k32.OpenThread(0x0002 | 0x0008, False, et)
                        if th:
                            cx = getctx(th)
                            if cx:
                                struct.pack_into('<I', cx, 0x44,
                                                 struct.unpack_from('<I', cx, 0x44)[0] & ~0x100)
                                k32.SetThreadContext(th, ctypes.byref(cx))
                            k32.CloseHandle(th)
                    cont = 0x00010002
                else:
                    cont = 0x00010002
        finally:
            k32.ContinueDebugEvent(ep, et, cont)

    try:
        k32.TerminateProcess(h, 0)
    except Exception:
        pass
    reg_restore(bak)
    log({'ev': 'end', 'hits': hits})
    print('hits', hits)
    return 0

if __name__ == '__main__':
    sys.exit(main())

# -*- coding: utf-8 -*-
"""轻量采样：只读取 0x141AD7F00 附近 64 字节，看 key 对 VMP 状态的影响。"""
import argparse, ctypes, os, subprocess, sys, time, winreg
from ctypes import wintypes as wt
k32 = ctypes.WinDLL('kernel32')
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]; k32.OpenProcess.restype = wt.HANDLE
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.CloseHandle.argtypes = [wt.HANDLE]

def setlic(v):
    for sub in ('Reg', 'CReg'):
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Eassos\DiskGenius\%s' % sub, 0,
                           winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, 'license', 0, winreg.REG_BINARY, v); k.Close()

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--key', default=None)
    a = ap.parse_args()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    exe = os.path.join(root, 'out', 'runtime', 'DiskGenius', 'DiskGenius.exe')
    setlic(b'' if a.key is None else a.key.encode('utf-16-le'))
    p = subprocess.Popen([exe], cwd=os.path.dirname(exe))
    try:
        time.sleep(10)
        h = k32.OpenProcess(0x0010, False, p.pid)
        buf = ctypes.create_string_buffer(64); cs = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(h, ctypes.c_void_p(0x141AD7F00), buf, 64, ctypes.byref(cs))
        k32.CloseHandle(h)
        print('%-8s %s' % (a.key or 'empty', buf.raw[:64].hex() if ok else 'READFAIL'))
    finally:
        p.terminate()
    return 0
if __name__ == '__main__':
    sys.exit(main())

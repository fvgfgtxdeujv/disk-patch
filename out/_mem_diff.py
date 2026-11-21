# -*- coding: utf-8 -*-
"""无调试器差分：启动 DiskGenius，采样 TCP 连接，12s 后整模块内存落盘。
对比不同 license key 下的内存差异（含 VMP 解密页与全局状态）。
需管理员运行。
"""
import argparse, ctypes, json, os, struct, subprocess, sys, time, winreg
from ctypes import wintypes as wt

BASE_IMG = 0x140000000
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

class ME32(ctypes.Structure):
    _fields_ = [('dwSize', wt.DWORD), ('th32ModuleID', wt.DWORD), ('th32ProcessID', wt.DWORD),
                ('GlblcntUsage', wt.DWORD), ('ProccntUsage', wt.DWORD),
                ('modBaseAddr', ctypes.POINTER(ctypes.c_byte)), ('modBaseSize', wt.DWORD),
                ('hModule', wt.HMODULE), ('szModule', wt.WCHAR * 256),
                ('szExePath', wt.WCHAR * 260)]

k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]; k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.Module32First.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.Module32Next.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]; k32.OpenProcess.restype = wt.HANDLE
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.CloseHandle.argtypes = [wt.HANDLE]
psapi.EnumProcessModulesEx.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                                       ctypes.POINTER(wt.DWORD), wt.DWORD]
psapi.GetModuleFileNameExW.argtypes = [wt.HANDLE, wt.HMODULE, wt.LPWSTR, wt.DWORD]
psapi.GetModuleInformation.argtypes = [wt.HANDLE, wt.HMODULE, ctypes.c_void_p, wt.DWORD]

def reg_set(data):
    for sub in ('Reg', 'CReg'):
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Eassos\DiskGenius\%s' % sub,
                           0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, 'license', 0, winreg.REG_BINARY, data); k.Close()

def reg_bak():
    d = {}
    for sub in ('Reg', 'CReg'):
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Eassos\DiskGenius\%s' % sub,
                           0, winreg.KEY_READ)
        try: d[sub] = winreg.QueryValueEx(k, 'license')
        except OSError: d[sub] = (None, None)
        k.Close()
    return d

def reg_restore(d):
    for sub, (v, t) in d.items():
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Eassos\DiskGenius\%s' % sub,
                           0, winreg.KEY_SET_VALUE)
        if v is None:
            try: winreg.DeleteValue(k, 'license')
            except OSError: pass
        else: winreg.SetValueEx(k, 'license', 0, t, v)
        k.Close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--key', default=None)
    ap.add_argument('--seconds', type=int, default=12)
    ap.add_argument('--tag', default=None)
    a = ap.parse_args()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    exe = os.path.join(root, 'out', 'runtime', 'DiskGenius', 'DiskGenius.exe')
    tag = a.tag or (a.key or 'empty')
    out = os.path.join(root, 'out', 'memdump_%s.bin' % tag)
    meta = os.path.join(root, 'out', 'memdump_%s.json' % tag)

    bak = reg_bak(); reg_set(b'' if a.key is None else a.key.encode('utf-16-le'))
    p = subprocess.Popen([exe], cwd=os.path.dirname(exe))
    t0 = time.time()
    conns = set()
    try:
        while time.time() - t0 < a.seconds:
            try:
                o = subprocess.run(['netstat', '-ano', '-p', 'tcp'], capture_output=True, text=True,
                                   timeout=3).stdout
                for ln in o.splitlines():
                    if ln.split() and ln.split()[-1] == str(p.pid):
                        parts = ln.split()
                        if len(parts) >= 3: conns.add(parts[1] + ' -> ' + parts[2])
            except Exception:
                pass
            time.sleep(0.25)
        # 模块定位（psapi）
        h = k32.OpenProcess(0x0010 | 0x0400 | 0x0020, False, p.pid)
        base, size, name = 0, 0, ''
        if h:
            mods = (wt.HMODULE * 1024)()
            need = wt.DWORD(0)
            if psapi.EnumProcessModulesEx(h, ctypes.byref(mods), ctypes.sizeof(mods),
                                          ctypes.byref(need), 3):
                for i in range(min(need.value // ctypes.sizeof(wt.HMODULE), 1024)):
                    nm = ctypes.create_unicode_buffer(512)
                    psapi.GetModuleFileNameExW(h, mods[i], nm, 512)
                    if nm.value.lower().endswith('diskgenius.exe'):
                        class MI(ctypes.Structure):
                            _fields_ = [('lpBaseOfDll', ctypes.c_void_p), ('SizeOfImage', wt.DWORD),
                                        ('EntryPoint', ctypes.c_void_p)]
                        mi = MI()
                        if psapi.GetModuleInformation(h, mods[i], ctypes.byref(mi), ctypes.sizeof(mi)):
                            base = mi.lpBaseOfDll
                            size = mi.SizeOfImage
                            name = nm.value
                        break
        d = {'key': a.key, 'pid': p.pid, 'base': base, 'size': size, 'conns': sorted(conns)}
        dnsc = subprocess.run(['ipconfig', '/displaydns'], capture_output=True, text=True,
                              errors='ignore', timeout=15).stdout
        d['dns_eassos'] = sorted({ln.strip() for ln in dnsc.splitlines() if 'eassos' in ln.lower()})
        print(json.dumps(d, ensure_ascii=False))
        if base and size and h:
            buf = bytearray(size)
            cs = ctypes.c_size_t(0)
            blob = ctypes.create_string_buffer(0x1000)
            got_pages = 0
            for off in range(0, size, 0x1000):
                ok = k32.ReadProcessMemory(h, ctypes.c_void_p(base + off), blob, 0x1000, ctypes.byref(cs))
                if ok and cs.value:
                    buf[off:off + cs.value] = blob.raw[:cs.value]
                    got_pages += 1
            k32.CloseHandle(h)
            urls = []
            needle = 'https://internal.eassos.com'.encode('utf-16-le')
            pos = 0
            while True:
                i = buf.find(needle, pos)
                if i < 0: break
                pos = i + 2
                seg = bytes(buf[i:i + 4000])
                try:
                    s = seg.decode('utf-16-le', 'ignore').split('\x00')[0]
                except Exception:
                    s = ''
                if s: urls.append([hex(base + i), s[:800]])
            d['live_urls'] = urls
            open(out, 'wb').write(bytes(buf))
            d['pages'] = got_pages
            json.dump(d, open(meta, 'w', encoding='utf-8'), ensure_ascii=False)
            print('wrote', out, size, got_pages, 'urls', len(urls))
            for a2, s in urls:
                print(a2, s[:300])
    finally:
        try: p.terminate()
        except Exception: pass
    reg_restore(bak)
    return 0

if __name__ == '__main__':
    sys.exit(main())

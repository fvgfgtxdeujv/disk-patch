import ctypes, ctypes.wintypes as wt, subprocess, time, os, sys

exe = r'out\runtime\DiskGenius\DiskGenius.exe'
out = r'out\moddump_140000000.bin'
_log = open(r'out\_moddump.log', 'w', encoding='utf-8', buffering=1)
sys.stdout = _log
sys.stderr = _log
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03

k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenProcess.restype = wt.HANDLE
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
psapi.EnumProcessModulesEx.argtypes = [wt.HANDLE, ctypes.POINTER(wt.HMODULE), wt.DWORD,
                                       ctypes.POINTER(wt.DWORD), wt.DWORD]
psapi.GetModuleBaseNameW.argtypes = [wt.HANDLE, wt.HMODULE, wt.LPWSTR, wt.DWORD]
psapi.GetModuleInformation.argtypes = [wt.HANDLE, wt.HMODULE, ctypes.c_void_p, wt.DWORD]

p = subprocess.Popen([exe], cwd=os.path.dirname(exe))
print('pid', p.pid, flush=True)
time.sleep(12)
h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, p.pid)
if not h:
    print('OpenProcess failed', ctypes.get_last_error()); sys.exit(1)
mods = (wt.HMODULE * 1024)()
need = wt.DWORD()
if not psapi.EnumProcessModulesEx(h, mods, ctypes.sizeof(mods), ctypes.byref(need), LIST_MODULES_ALL):
    print('EnumProcessModulesEx failed', ctypes.get_last_error()); sys.exit(1)
print('modules', need.value // ctypes.sizeof(wt.HMODULE), flush=True)

class MODINFO(ctypes.Structure):
    _fields_ = [('lpBaseOfDll', ctypes.c_void_p), ('SizeOfImage', wt.DWORD), ('EntryPoint', ctypes.c_void_p)]

base = None
for i in range(need.value // ctypes.sizeof(wt.HMODULE)):
    buf = ctypes.create_unicode_buffer(1024)
    psapi.GetModuleBaseNameW(h, mods[i], buf, 1024)
    if buf.value.lower() == 'diskgenius.exe':
        mi = MODINFO()
        psapi.GetModuleInformation(h, mods[i], ctypes.byref(mi), ctypes.sizeof(mi))
        base, size = mi.lpBaseOfDll, mi.SizeOfImage
        print('found', buf.value, hex(base), hex(size), flush=True)
        break
if base is None:
    print('module not found'); sys.exit(1)

with open(out, 'wb') as f:
    ok = bad = 0
    for off in range(0, size, 0x1000):
        b = ctypes.create_string_buffer(0x1000)
        n = ctypes.c_size_t()
        if k32.ReadProcessMemory(h, ctypes.c_void_p(base + off), b, 0x1000, ctypes.byref(n)):
            f.write(b.raw); ok += 1
        else:
            f.write(b'\x00' * 0x1000); bad += 1
print('pages ok', ok, 'bad', bad, flush=True)
p.terminate()
print('saved', out, os.path.getsize(out), flush=True)
blob = open(out, 'rb').read()
for n in ('[license]', 'Options.ini', 'appname=', 'regver'):
    u = n.encode('utf-16-le')
    i = blob.find(u)
    print('str', n, hex(base + i) if i >= 0 else None, flush=True)

import os, sys, time, json, ctypes, ctypes.wintypes as wt, subprocess, winreg

HERE = r'c:\Users\tfvtd\Desktop\项目\disk-patch'
GAME = os.path.join(HERE, 'out', 'runtime', 'DiskGenius')
EXE = os.path.join(GAME, 'DiskGenius.exe')
INI = os.path.join(GAME, 'Options.ini')
LOG = open(os.path.join(HERE, 'out', '_gate_probe.log'), 'w', encoding='utf-8', buffering=1)

u32 = ctypes.WinDLL('user32', use_last_error=True)
u32.EnumWindows.argtypes = [ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM), wt.LPARAM]
u32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
u32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
u32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
u32.IsWindowVisible.argtypes = [wt.HWND]

def windows_of(pid):
    out = []
    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def cb(hwnd, lparam):
        p = wt.DWORD()
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if p.value == pid:
            t = ctypes.create_unicode_buffer(512)
            u32.GetWindowTextW(hwnd, t, 512)
            c = ctypes.create_unicode_buffer(256)
            u32.GetClassNameW(hwnd, c, 256)
            out.append({'hwnd': int(hwnd), 'title': t.value, 'cls': c.value,
                        'visible': bool(u32.IsWindowVisible(hwnd))})
        return True
    u32.EnumWindows(cb, 0)
    return out

def ini_bytes(key):
    lines = ['[LicenseInfo]', 'Show = "6.2.0.1829"']
    if key is not None:
        lines += ['', '[license]', 'appname = "DiskGenius"', 'user = "Zaka"',
                  'email = "zaka@example.com"', 'regcode = ""',
                  'regver = "6.2.0.1829_x64_pro_eng"', 'key = "%s"' % key]
    return b'\xff\xfe' + ('\r\n'.join(lines) + '\r\n\r\n').encode('utf-16-le')

def reg_dump(root, path):
    out = {}
    try:
        k = winreg.OpenKey(root, path, 0, winreg.KEY_READ)
    except OSError:
        return out
    n = 0
    while True:
        try:
            name, val, typ = winreg.EnumValue(k, n)
        except OSError:
            break
        out[name] = '%r(type=%d)' % (val, typ)
        n += 1
    for i in range(20):
        try:
            sub = winreg.EnumKey(k, i)
        except OSError:
            break
        out.update(reg_dump(root, path + '\\' + sub))
    return out

def kill():
    subprocess.run(['taskkill', '/F', '/IM', 'DiskGenius.exe'], capture_output=True)

CASES = [
    ('baseline_nokey', None),
    ('k_aTEST', 'aTEST'),
    ('k_0TEST', '0TEST'),
    ('k_1TEST', '1TEST'),
    ('k_2TEST', '2TEST'),
    ('k_9TEST', '9TEST'),
]

orig = open(INI, 'rb').read() if os.path.exists(INI) else None
res = []
try:
    for name, key in CASES:
        kill()
        try:
            os.remove(INI)
        except OSError:
            pass
        open(INI, 'wb').write(ini_bytes(key))
        time.sleep(0.4)
        p = subprocess.Popen([EXE], cwd=GAME)
        time.sleep(9)
        wins = windows_of(p.pid)
        alive = p.poll() is None
        kept = os.path.exists(INI)
        before = open(INI, 'rb').read() if kept else b''
        reg = reg_dump(winreg.HKEY_CURRENT_USER, r'Software\Eassos\DiskGenius')
        p.terminate()
        try:
            p.wait(6)
        except Exception:
            p.kill()
        time.sleep(0.6)
        kept2 = os.path.exists(INI)
        after = open(INI, 'rb').read() if kept2 else b''
        rec = {'case': name, 'key': key, 'alive': alive, 'kept': kept2,
               'same': after == ini_bytes(key), 'size': len(after),
               'wins': wins, 'hkcu': reg}
        res.append(rec)
        print(json.dumps(rec, ensure_ascii=False), flush=True)
finally:
    kill()
    if orig is not None:
        open(INI, 'wb').write(orig)
    json.dump(res, open(os.path.join(HERE, 'out', 'gate_probe.json'), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    print('DONE', flush=True)

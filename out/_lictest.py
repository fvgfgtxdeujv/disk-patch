import os, sys, time, json, hashlib, winreg, subprocess

HERE = r'c:\Users\tfvtd\Desktop\项目\disk-patch'
GAME = os.path.join(HERE, 'out', 'runtime', 'DiskGenius')
EXE = os.path.join(GAME, 'DiskGenius.exe')
INI = os.path.join(GAME, 'Options.ini')
LOG = open(os.path.join(HERE, 'out', '_lictest.log'), 'w', encoding='utf-8', buffering=1)
sys.stdout = sys.stderr = LOG

def xor0e(s):
    return ''.join(chr(ord(c) ^ 0x0E) for c in s)

def ini_bytes(key=None):
    lines = ['[LicenseInfo]', 'Show = "6.2.0.1829"']
    if key is not None:
        lines += ['', '[license]', 'appname = "DiskGenius"', 'user = ""',
                  'email = "license@eassos.com"', 'regcode = ""',
                  'regver = "6.2.0.1829_x64_pro_eng"', 'key = "%s"' % key]
    return b'\xff\xfe' + ('\r\n'.join(lines) + '\r\n\r\n').encode('utf-16-le')

P = ('ver=6.2.0.1829_x64_pro_eng&code=QK7X-M2PV-ZLHD-W8CT-RBNQ'
     '&name=ZakaTest&email=zaka@example.com&mid=0000000000000000&applang=Eng')
H = hashlib.md5(P.encode()).hexdigest().upper()
CK = b'\xff\xfe' + ('\r\n'.join([
    '[LicenseInfo]', 'Show = "6.2.0.1829"', '', '[license]',
    'appname = "DiskGenius"', 'user = ""', 'email = "license@eassos.com"',
    'regcode = ""', 'regver = "6.2.0.1829_x64_pro_eng"', 'key = ""']) + '\r\n').encode('utf-16-le')

CASES = [
    ('control_nokey', None),
    ('fake_sample', 'appname=DiskGenius&license=SIG&user=ZakaTest&email=zaka@example.com'),
    ('plain_check', 'appname=DiskGenius&%s&check=%s' % (P, H)),
    ('enc_check', 'appname=DiskGenius&encryption=' + xor0e(P + '&check=' + H)),
    ('skey_dummy', 'appname=DiskGenius&%s&skey=%%00%%01%%02%%03%%04%%05%%06%%07' % P),
]

def reg_dump():
    out = {}
    def walk(root, path):
        try:
            k = winreg.OpenKey(root, path)
        except OSError:
            return
        n = 0
        while True:
            try:
                name, val, typ = winreg.EnumValue(k, n)
            except OSError:
                break
            out[path + '\\' + name] = str(val)
            n += 1
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(k, i)
            except OSError:
                break
            walk(root, path + '\\' + sub)
            i += 1
    walk(winreg.HKEY_CURRENT_USER, r'Software\Eassos\DiskGenius')
    return out

def kill():
    subprocess.run(['taskkill', '/F', '/IM', 'DiskGenius.exe'],
                   capture_output=True)

orig = open(INI, 'rb').read() if os.path.exists(INI) else None
results = []
try:
    for name, key in CASES:
        kill()
        open(INI, 'wb').write(ini_bytes(key))
        time.sleep(0.3)
        p = subprocess.Popen([EXE], cwd=GAME)
        time.sleep(11)
        alive = p.poll() is None
        kept = os.path.exists(INI)
        after = open(INI, 'rb').read() if kept else b''
        reg = reg_dump()
        p.terminate()
        try:
            p.wait(5)
        except Exception:
            p.kill()
        rec = {'case': name, 'key_len': len(key) if key else 0, 'alive': alive,
               'kept': kept, 'size_after': len(after),
               'same_bytes': after == ini_bytes(key),
               'reg': reg}
        results.append(rec)
        print(json.dumps(rec, ensure_ascii=False), flush=True)
        time.sleep(0.5)
finally:
    kill()
    if orig is not None:
        open(INI, 'wb').write(orig)
    json.dump(results, open(os.path.join(HERE, 'out', 'lictest.json'), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    print('DONE', flush=True)

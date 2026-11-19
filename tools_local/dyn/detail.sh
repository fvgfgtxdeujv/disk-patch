#!/bin/bash
set -u
TAG="$1"
export WINEPREFIX=/tmp/zaka-20261119/wine64 DISPLAY=:95
OUT=/tmp/zaka-20261119
DGDIR=/tmp/zaka-20261119/disk-patch/dg/DiskGenius
INI="$DGDIR/Options.ini"
cd "$DGDIR" || exit 1
rm -f "$INI"; wine reg delete "HKCU\Software\Eassos" /f >/dev/null 2>&1
python3 - "$TAG" "$INI" <<'PY'
import sys
tag, ini = sys.argv[1], sys.argv[2]
base = {"appname":"DiskGenius","user":"ZakaTest","email":"zaka@example.com",
        "regcode":"QK7X-M2PV-ZLHD-W8CT-RBNQ","regver":"6.2.0.1829_x64_pro_eng"}
V = {"empty_sec": None, "no_key": base,
     "with_date": dict(base, VerifyDate="20991231")}
rows = V[tag]
lines = ['[license]'] + (['%s = "%s"'%(k,v) for k,v in rows.items()] if rows else []) + ['']
open(ini,'wb').write(b'\xff\xfe'+('\r\n'.join(lines)+'\r\n').encode('utf-16-le'))
print("写前:", len(open(ini,'rb').read()), "字节")
PY
Xvfb :95 -screen 0 1280x900x24 >$OUT/xvfb.log 2>&1 & XPID=$!
sleep 2
wine DiskGenius.exe >$OUT/d_$TAG.log 2>&1 & WPID=$!
for i in $(seq 1 40); do W=$(xdotool search --name "DiskGenius V6" 2>/dev/null|head -1); [ -n "$W" ] && break; sleep 1; done
sleep 10
wineserver -k 2>/dev/null; kill $XPID 2>/dev/null
echo "=== INI 现状 ==="
ls -la "$INI" 2>/dev/null && iconv -f UTF-16 -t UTF-8 "$INI" 2>/dev/null | cat -A | head -20
echo "=== 注册表 ==="
wine reg query "HKCU\Software\Eassos\DiskGenius\Reg" /s 2>/dev/null | grep -v "err\|Font"

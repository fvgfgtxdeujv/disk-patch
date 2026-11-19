#!/bin/bash
set -u
export WINEPREFIX=/tmp/zaka-20261119/wine64 DISPLAY=:95
OUT=/tmp/zaka-20261119
DGDIR=/tmp/zaka-20261119/disk-patch/dg/DiskGenius
INI="$DGDIR/Options.ini"
cd "$DGDIR" || exit 1
rm -f "$INI"
python3 - "$INI" <<'PY'
import sys
ini=sys.argv[1]
lic={"appname":"DiskGenius","user":"ZakaTest","email":"zaka@example.com",
     "regcode":"QK7X-M2PV-ZLHD-W8CT-RBNQ","regver":"6.2.0.1829_x64_pro_eng",
     "key":"appname=DiskGenius&license=SIG&user=ZakaTest&email=zaka@example.com"}
lines=['[license]']+['%s = "%s"'%(k,v) for k,v in lic.items()]+['']
open(ini,'wb').write(b'\xff\xfe'+('\r\n'.join(lines)+'\r\n').encode('utf-16-le'))
PY
Xvfb :95 -screen 0 1280x900x24 >$OUT/xvfb.log 2>&1 & XPID=$!
sleep 2
strace -f -k -e trace=unlink,openat -o $OUT/ktrace.txt wine DiskGenius.exe >$OUT/k.log 2>&1 & SPID=$!
for i in $(seq 1 45); do W=$(xdotool search --name "DiskGenius V6" 2>/dev/null|head -1); [ -n "$W" ] && break; sleep 1; done
sleep 14
kill $SPID 2>/dev/null; sleep 1
wineserver -k 2>/dev/null; kill $XPID 2>/dev/null
echo "=== unlink Options.ini 及其栈 ==="
grep -n -A 30 "unlink.*Options.ini" $OUT/ktrace.txt | head -45

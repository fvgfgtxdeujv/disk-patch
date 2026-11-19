#!/bin/bash
set -u
export WINEPREFIX=/tmp/zaka-20261119/wine64 DISPLAY=:95
OUT=/tmp/zaka-20261119
DGDIR=/tmp/zaka-20261119/disk-patch/dg/DiskGenius
INI="$DGDIR/Options.ini"
cd "$DGDIR" || exit 1
rm -f "$INI"; wine reg delete "HKCU\Software\Eassos" /f >/dev/null 2>&1
python3 - "$INI" <<'PY'
import sys
ini=sys.argv[1]
lic={"appname":"DiskGenius","user":"ZakaTest","email":"zaka@example.com",
     "regcode":"QK7X-M2PV-ZLHD-W8CT-RBNQ","regver":"6.2.0.1829_x64_pro_eng",
     "key":"appname=DiskGenius&license=SIG&user=ZakaTest&email=zaka@example.com"}
lines=['[license]']+['%s = "%s"'%(k,v) for k,v in lic.items()]+['']
open(ini,'wb').write(b'\xff\xfe'+('\r\n'.join(lines)+'\r\n').encode('utf-16-le'))
print("ini", len(open(ini,'rb').read()))
PY
Xvfb :95 -screen 0 1280x900x24 >$OUT/xvfb.log 2>&1 &
XPID=$!; sleep 2
strace -f -y -e trace=openat,unlink,unlinkat,connect,socket -o $OUT/trace.txt wine DiskGenius.exe >$OUT/st.log 2>&1 &
SPID=$!
for i in $(seq 1 45); do W=$(xdotool search --name "DiskGenius V6" 2>/dev/null|head -1); [ -n "$W" ] && break; sleep 1; done
sleep 14
kill $SPID 2>/dev/null; sleep 1
wineserver -k 2>/dev/null
kill $XPID 2>/dev/null
echo "=== INI/Options 相关 ==="
grep -i "Options.ini" $OUT/trace.txt | head -20
echo "=== unlink ==="
grep -i "unlink" $OUT/trace.txt | head -10
echo "=== 网络 ==="
grep -E "connect\(|socket\(" $OUT/trace.txt | grep -v "ENOENT\|AF_UNIX\|AF_NETLINK" | head -20
echo "=== ini 还在? ==="
ls -la "$INI" 2>&1

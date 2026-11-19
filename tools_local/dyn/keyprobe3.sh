#!/bin/bash
set -u
export WINEPREFIX=/tmp/zaka-20261119/wine64 DISPLAY=:95
OUT=/tmp/zaka-20261119
DGDIR=/tmp/zaka-20261119/disk-patch/dg/DiskGenius
INI="$DGDIR/Options.ini"
cd "$DGDIR" || exit 1
probe () {
  TAG="$1"; KEYSTR="$2"
  rm -f "$INI"
  python3 - "$INI" "$KEYSTR" <<'PY'
import sys
ini, key = sys.argv[1], sys.argv[2]
lines = ['[license]', 'appname = "DiskGenius"', 'user = "ZakaTest"',
         'email = "zaka@example.com"', 'regcode = "QK7X-M2PV-ZLHD-W8CT-RBNQ"',
         'regver = "6.2.0.1829_x64_pro_eng"', f'key = "{key}"', '']
open(ini,'wb').write(b'\xff\xfe'+('\r\n'.join(lines)+'\r\n').encode('utf-16-le'))
PY
  Xvfb :95 -screen 0 1280x900x24 >$OUT/xvfb.log 2>&1 & XPID=$!
  sleep 2
  wine DiskGenius.exe >$OUT/kp_$TAG.log 2>&1 & WPID=$!
  for i in $(seq 1 40); do W=$(xdotool search --name "DiskGenius V6" 2>/dev/null|head -1); [ -n "$W" ] && break; sleep 1; done
  sleep 9
  wineserver -k 2>/dev/null; kill $XPID 2>/dev/null
  if [ -f "$INI" ]; then ST="保留"; else ST="删除"; fi
  echo "[$TAG] $ST  <$KEYSTR>"
}
probe d1 "appname=DiskGenius&license=SIG&user=ZakaTest&email=C"
probe d2 "appname=DiskGenius&license=SIG&user=B&email=zaka@example.com"
probe d3 "appname=DiskGenius&license=A&user=ZakaTest&email=zaka@example.com"
probe d4 "appname=DiskGenius&license=SIG&user=ZakaTest&email=zaka@example.com"

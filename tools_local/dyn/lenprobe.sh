#!/bin/bash
set -u
export WINEPREFIX=/tmp/zaka-20261119/wine64 DISPLAY=:95
OUT=/tmp/zaka-20261119
DGDIR=/tmp/zaka-20261119/disk-patch/dg/DiskGenius
INI="$DGDIR/Options.ini"
cd "$DGDIR" || exit 1
probe () {
  TAG="$1"; LIC="$2"
  rm -f "$INI"
  python3 - "$INI" "$LIC" <<'PY'
import sys
ini, lic = sys.argv[1], sys.argv[2]
lines = ['[license]', 'appname = "DiskGenius"', 'user = "ZakaTest"',
         'email = "zaka@example.com"', 'regcode = "QK7X-M2PV-ZLHD-W8CT-RBNQ"',
         'regver = "6.2.0.1829_x64_pro_eng"',
         f'key = "appname=DiskGenius&license={lic}&user=ZakaTest&email=zaka@example.com"', '']
open(ini,'wb').write(b'\xff\xfe'+('\r\n'.join(lines)+'\r\n').encode('utf-16-le'))
PY
  Xvfb :95 -screen 0 1280x900x24 >$OUT/xvfb.log 2>&1 & XPID=$!
  sleep 2
  wine DiskGenius.exe >$OUT/lp_$TAG.log 2>&1 & WPID=$!
  for i in $(seq 1 40); do W=$(xdotool search --name "DiskGenius V6" 2>/dev/null|head -1); [ -n "$W" ] && break; sleep 1; done
  sleep 8
  wineserver -k 2>/dev/null; kill $XPID 2>/dev/null
  [ -f "$INI" ] && echo "[$TAG] 保留 (len=${#LIC})" || echo "[$TAG] 删除 (len=${#LIC})"
}
probe l1   "A"
probe l16  "AAAAAAAAAAAAAAAA"
probe l32  "$(printf 'A%.0s' {1..32})"
probe l64  "$(printf 'A%.0s' {1..64})"
probe l128 "$(printf 'A%.0s' {1..128})"
probe l256 "$(printf 'A%.0s' {1..256})"
probe l344 "$(printf 'A%.0s' {1..344})"

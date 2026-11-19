#!/bin/bash
set -u
export WINEPREFIX=/tmp/zaka-20261119/wine64 DISPLAY=:95
OUT=/tmp/zaka-20261119
DGDIR=/tmp/zaka-20261119/disk-patch/dg/DiskGenius
INI="$DGDIR/Options.ini"
cd "$DGDIR" || exit 1

run_variant() {
  TAG="$1"
  rm -f "$INI"
  python3 - "$TAG" "$INI" <<'PY'
import sys
tag, ini = sys.argv[1], sys.argv[2]
base = {"appname":"DiskGenius","user":"ZakaTest","email":"zaka@example.com",
        "regcode":"QK7X-M2PV-ZLHD-W8CT-RBNQ","regver":"6.2.0.1829_x64_pro_eng"}
full_key = ("ver=6.2.0.1829_x64_pro_eng&code=QK7X-M2PV-ZLHD-W8CT-RBNQ&name=ZakaTest"
            "&email=zaka@example.com&mid=ABCDEF&appname=DiskGenius&applang=eng")
V = {
 "empty_sec":  ['[license]'],
 "appname":    {'appname':'DiskGenius'},
 "no_key":     dict(base),
 "with_date":  dict(base, VerifyDate="20991231"),
 "fullreq":    dict(base, VerifyDate="20991231", key=full_key),
 "keyonly":    {'key': full_key},
}
rows = V[tag]
lines = ['[license]']
if isinstance(rows, dict):
    lines += ['%s = "%s"' % (k, v) for k, v in rows.items()]
lines += ['']
open(ini,'wb').write(b'\xff\xfe' + ('\r\n'.join(lines)+'\r\n').encode('utf-16-le'))
PY
  Xvfb :95 -screen 0 1280x900x24 >$OUT/xvfb.log 2>&1 & XPID=$!
  sleep 2
  wine DiskGenius.exe >$OUT/v_$TAG.log 2>&1 & WPID=$!
  for i in $(seq 1 40); do W=$(xdotool search --name "DiskGenius V6" 2>/dev/null|head -1); [ -n "$W" ] && break; sleep 1; done
  sleep 10
  wineserver -k 2>/dev/null; kill $XPID 2>/dev/null
  if [ -f "$INI" ]; then echo "$TAG: INI 保留 ($(stat -c %s $INI) 字节)"; else echo "$TAG: INI 被删"; fi
  if wine reg query "HKCU\Software\Eassos\DiskGenius\Reg" /v license >/dev/null 2>&1; then echo "   -> 注册表出现 license 值!"; fi
  wine reg delete "HKCU\Software\Eassos" /f >/dev/null 2>&1
}

for t in empty_sec appname no_key with_date fullreq keyonly; do run_variant "$t"; done

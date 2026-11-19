#!/bin/bash
set -u
MODE="${1:-regsz}"
export WINEPREFIX=/tmp/zaka-20261119/wine64 DISPLAY=:95
OUT=/tmp/zaka-20261119
DGDIR=/tmp/zaka-20261119/disk-patch/dg/DiskGenius
INI="$DGDIR/Options.ini"
cd "$DGDIR" || exit 1
rm -f "$INI"; wine reg delete "HKCU\Software\Eassos" /f >/dev/null 2>&1
case "$MODE" in
  regsz)
    wine reg add "HKCU\Software\Eassos\DiskGenius\Reg" /v license /t REG_SZ /d "appname=DiskGenius&license=SIG&user=ZakaTest&email=zaka@example.com" /f >/dev/null 2>&1 ;;
  regmulti)
    wine reg add "HKCU\Software\Eassos\DiskGenius\Reg" /v license /t REG_MULTI_SZ /d "appname=DiskGenius" /f >/dev/null 2>&1 ;;
  inilic)
    python3 - "$INI" <<'PY'
import sys
ini=sys.argv[1]
lic={"appname":"DiskGenius","user":"ZakaTest","email":"zaka@example.com",
     "regcode":"QK7X-M2PV-ZLHD-W8CT-RBNQ","regver":"6.2.0.1829_x64_pro_eng",
     "key":"appname=DiskGenius&license=SIG&user=ZakaTest&email=zaka@example.com"}
lines=['[license]']+['%s = "%s"'%(k,v) for k,v in lic.items()]+['']
open(ini,'wb').write(b'\xff\xfe'+('\r\n'.join(lines)+'\r\n').encode('utf-16-le'))
PY
    ;;
esac
Xvfb :95 -screen 0 1280x900x24 >$OUT/xvfb.log 2>&1 & XPID=$!
sleep 2
WINEDEBUG=+reg wine DiskGenius.exe >$OUT/reg_$MODE.log 2>&1 & WPID=$!
for i in $(seq 1 45); do W=$(xdotool search --name "DiskGenius V6" 2>/dev/null|head -1); [ -n "$W" ] && break; sleep 1; done
sleep 14
wineserver -k 2>/dev/null
kill $XPID 2>/dev/null
echo "=== 与 Eassos/license 相关的 reg 操作 ==="
grep -iE "eassos|license|Improveplan|ShowLicense" $OUT/reg_$MODE.log | sed 's/^[0-9a-f]*://' | head -40
echo "=== 计数 ==="
grep -icE "eassos" $OUT/reg_$MODE.log

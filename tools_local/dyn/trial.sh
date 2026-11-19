#!/bin/bash
# 实验：写不同形态的授权数据 → 启动 → 看程序是否把授权写进 Reg\license
# 用法: trial.sh <标签> <模式>
#   none    不写任何授权（基线）
#   inilic  Options.ini 写 [license] 段（key = 伪造响应）
#   regsz   注册表 license 值，REG_SZ，UTF-16 kv 串
#   regbin  注册表 license 值，REG_BINARY，UTF-16 kv 串
set -u
TAG="$1"; MODE="$2"
export WINEPREFIX=/tmp/zaka-20261119/wine64
export DISPLAY=:95
OUT=/tmp/zaka-20261119
DGDIR=/tmp/zaka-20261119/disk-patch/dg/DiskGenius
INI="$DGDIR/Options.ini"

cd "$DGDIR" || exit 1

# 清理旧授权
rm -f "$INI"
wine reg delete "HKCU\Software\Eassos" /f >/dev/null 2>&1

python3 - "$MODE" "$INI" <<'PY'
import sys, os
mode, ini = sys.argv[1], sys.argv[2]
lic = {
 "appname": "DiskGenius",
 "user": "ZakaTest",
 "email": "zaka@example.com",
 "regcode": "QK7X-M2PV-ZLHD-W8CT-RBNQ",
 "regver": "6.2.0.1829_x64_pro_eng",
 "key": "appname=DiskGenius&license=SIG&user=ZakaTest&email=zaka@example.com",
}
if mode in ("inilic", "none"):
    lines = ['[LicenseInfo]', 'Show = "6.2.0.1829"', '']
    if mode == "inilic":
        lines = ['[license]'] + ['%s = "%s"' % (k, v) for k, v in lic.items()] + ['']
    data = '\r\n'.join(lines) + '\r\n'
    with open(ini, 'wb') as f:
        f.write(b'\xff\xfe' + data.encode('utf-16-le'))
    print("INI written:", mode, os.path.getsize(ini))
PY

case "$MODE" in
  regsz)
    wine reg add "HKCU\Software\Eassos\DiskGenius\Reg" /v license /t REG_SZ /d "appname=DiskGenius&license=SIG&user=ZakaTest&email=zaka@example.com" /f >/dev/null 2>&1
    ;;
  regbin)
    python3 - <<'PY'
open('/tmp/zaka-20261119/lic.bin','wb').write("appname=DiskGenius&license=SIG&user=ZakaTest&email=zaka@example.com".encode('utf-16-le'))
PY
    wine reg add "HKCU\Software\Eassos\DiskGenius\Reg" /v license /t REG_BINARY /d "$(xxd -p /tmp/zaka-20261119/lic.bin | tr -d '\n')" /f >/dev/null 2>&1
    ;;
esac

Xvfb :95 -screen 0 1280x900x24 >$OUT/xvfb.log 2>&1 &
XPID=$!
sleep 2
wine DiskGenius.exe >$OUT/trial_$TAG.log 2>&1 &
WPID=$!
for i in $(seq 1 45); do
  W=$(xdotool search --name "DiskGenius V6" 2>/dev/null | head -1)
  [ -n "$W" ] && break
  sleep 1
done
sleep 12
xdotool key --window "$W" Escape 2>/dev/null
sleep 8
import -window root $OUT/trial_$TAG.png 2>/dev/null

# 启动后注册表快照
wine reg query "HKCU\Software\Eassos\DiskGenius" /s > $OUT/reg_after_$TAG.txt 2>/dev/null

kill $WPID 2>/dev/null; sleep 2
wineserver -k 2>/dev/null
kill $XPID 2>/dev/null

echo "=== reg after ($TAG/$MODE) ==="
grep -v "err:\|Fontconfig\|winediag" $OUT/reg_after_$TAG.txt | head -20
echo "=== ini after ==="
ls -la "$INI" 2>/dev/null
echo DONE

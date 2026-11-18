#!/usr/bin/env bash
# 把 DiskGenius 安装包拉进 vendor/ 并校验 SHA256（Linux/macOS 用）
set -euo pipefail
cd "$(dirname "$0")"
get() { grep -E "^$1=" pin.txt | head -1 | cut -d= -f2-; }
NAME=$(get filename); URL=$(get url); SHA=$(get sha256)
if [ -f "$NAME" ]; then
  if [ "$(sha256sum "$NAME" | cut -d' ' -f1)" = "$SHA" ]; then
    echo "已存在且校验通过: $NAME"; exit 0
  fi
  echo "已存在但哈希不符，重新下载"
fi
echo "下载 $URL"
curl -L --retry 3 -o "$NAME" "$URL"
ACT=$(sha256sum "$NAME" | cut -d' ' -f1)
echo "SHA256 = $ACT"
[ "$ACT" = "$SHA" ] || { echo "!! 哈希不符"; exit 1; }
echo "OK -> $NAME"

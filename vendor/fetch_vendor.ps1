# 把 DiskGenius 安装包拉进 vendor/ 并校验 SHA256。
# 用法（仓库根目录）：powershell -ExecutionPolicy Bypass -File vendor\fetch_vendor.ps1
$ErrorActionPreference = 'Stop'
$pin = @{}
Get-Content "$PSScriptRoot\pin.txt" | ForEach-Object {
    if ($_ -match '^(\w+)=(.*)$') { $pin[$matches[1]] = $matches[2] }
}
$out = Join-Path $PSScriptRoot $pin['filename']
if (Test-Path $out) {
    $h = (Get-FileHash $out -Algorithm SHA256).Hash.ToLower()
    if ($h -eq $pin['sha256']) { Write-Host "已存在且校验通过: $out"; exit 0 }
    Write-Host "已存在但哈希不符，重新下载"
}
Write-Host "下载 $($pin['url'])"
Invoke-WebRequest -Uri $pin['url'] -OutFile $out -UseBasicParsing -TimeoutSec 600
$h = (Get-FileHash $out -Algorithm SHA256).Hash.ToLower()
Write-Host "SHA256 = $h"
if ($h -ne $pin['sha256']) { Write-Host "!! 哈希不符，可能版本已更新"; exit 1 }
Write-Host "OK -> $out"

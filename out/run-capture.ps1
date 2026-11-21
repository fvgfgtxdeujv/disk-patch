$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$root = 'c:\Users\tfvtd\Desktop\项目\disk-patch'
Set-Location -LiteralPath $root
$out = Join-Path $root 'out\fullctx-win6'
New-Item -ItemType Directory -Force -Path $out | Out-Null

Start-Job -ScriptBlock {
    Start-Sleep -Seconds 4
    $ws = New-Object -ComObject WScript.Shell
    for ($i = 0; $i -lt 6; $i++) {
        if ($ws.AppActivate('DiskGenius')) { $ws.SendKeys('{F5}') }
        Start-Sleep -Seconds 2
    }
} | Out-Null

& python (Join-Path $root 'winactions\dump_runtime.py') `
    --exe (Join-Path $root 'out\runtime\DiskGenius\DiskGenius.exe') `
    --trace-vm fullctx --trace-seconds 16 `
    --out (Join-Path $out 'vm_trace.json') *>> (Join-Path $out 'run-admin.log')

Get-Content (Join-Path $out 'run-admin.log') -Tail 6 | Out-File (Join-Path $out 'tail.txt')

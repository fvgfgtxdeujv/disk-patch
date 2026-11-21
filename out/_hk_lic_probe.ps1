#Requires -RunAsAdministrator
# HKLM 二进制 license 接受/拒绝实验（需以管理员身份运行）
#
# 背景：
#   安装态下 DiskGenius 的配置存储不是 exe 同目录 Options.ini，而是
#   HKLM\SOFTWARE\Eassos\DiskGenius\Reg（原生 RegOpenKey 根 0x80000002，失败回退 HKCU 0x80000001）。
#   [license] key 对应 Reg 下的 REG_BINARY 值 `license`。
#   本脚本把候选 key（UTF-16LE / ASCII）写进该值，启动程序观察窗口标题、注册表与 ini 变化，
#   结束后完整还原。
#
# 用法：右键“以管理员身份运行 PowerShell”，执行
#   powershell -NoProfile -ExecutionPolicy Bypass -File out\_hk_lic_probe.ps1

$ErrorActionPreference = 'Stop'
$root = 'C:\Users\tfvtd\Desktop\项目\disk-patch'
$game = Join-Path $root 'out\runtime\DiskGenius'
$exe  = Join-Path $game 'DiskGenius.exe'
$ini  = Join-Path $game 'Options.ini'
$log  = Join-Path $root 'out\_hk_lic_probe.log'
$json = Join-Path $root 'out\hk_lic_probe.json'
$regPath = 'SOFTWARE\Eassos\DiskGenius'

function Log($s) { $s | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $s }

function Get-RegBin([string]$sub, [string]$name) {
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$regPath\$sub")
        if ($null -eq $k) { return $null }
        return ,$k.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    } catch { return $null }
}
function Set-RegBin([string]$sub, [string]$name, [byte[]]$data, [int]$type = 3) {
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$regPath\$sub", $true)
    if ($null -eq $k) { throw "missing key $sub" }
    $k.SetValue($name, $data, [Microsoft.Win32.RegistryValueKind]$type)
    $k.Close()
}
function Snapshot {
    $r = [ordered]@{}
    foreach ($sub in 'Reg','CReg') {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$regPath\$sub")
        if ($null -eq $k) { $r[$sub] = '<missing>'; continue }
        $d = [ordered]@{}
        foreach ($n in $k.GetValueNames()) {
            $v = $k.GetValue($n)
            if ($v -is [byte[]]) { $d[$n] = "bin[$($v.Length)]:" + (($v | ForEach-Object { '{0:x2}' -f $_ }) -join '') }
            else { $d[$n] = "$v" }
        }
        $r[$sub] = $d; $k.Close()
    }
    $hkcu = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($regPath)
    $h = [ordered]@{}
    if ($null -ne $hkcu) {
        foreach ($n in $hkcu.GetValueNames()) { $h[$n] = "$($hkcu.GetValue($n))" }
        $hkcu.Close()
    }
    $r['HKCU'] = $h
    $r['iniSize'] = if (Test-Path $ini) { (Get-Item $ini).Length } else { -1 }
    $r['iniSha']  = if (Test-Path $ini) { (Get-FileHash $ini -Algorithm SHA256).Hash.Substring(0,16) } else { '' }
    return $r
}

function WindowTitles([int]$procId) {
    Add-Type -Namespace DG -Name W -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int n);
[DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int n);
'@ -ErrorAction SilentlyContinue
    $list = New-Object System.Collections.ArrayList
    $cb = [DG.W+EnumWindowsProc]{
        param($h, $l)
        $p = 0
        [DG.W]::GetWindowThreadProcessId($h, [ref]$p) | Out-Null
        if ($p -eq $procId) {
            $sb = New-Object System.Text.StringBuilder 512
            [DG.W]::GetWindowText($h, $sb, 512) | Out-Null
            $cb2 = New-Object System.Text.StringBuilder 256
            [DG.W]::GetClassName($h, $cb2, 256) | Out-Null
            [void]$list.Add([ordered]@{ title = $sb.ToString(); cls = $cb2.ToString() })
        }
        return $true
    }
    [DG.W]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
    return $list
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '需要管理员权限：请右键以管理员身份运行。' -ForegroundColor Red
    exit 1
}

"start $(Get-Date -Format o)" | Out-File -FilePath $log -Encoding utf8
Log "active=$(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"

$bak = @{}
foreach ($sub in 'Reg','CReg') {
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$regPath\$sub")
    if ($null -eq $k) { continue }
    foreach ($n in $k.GetValueNames()) {
        $bak["$sub\$n"] = @{ name = $n; sub = $sub; kind = $k.GetValueKind($n); value = $k.GetValue($n) }
    }
    $k.Close()
}
$iniBak = if (Test-Path $ini) { [IO.File]::ReadAllBytes($ini) } else { $null }

function Utf16($s) { return [Text.Encoding]::Unicode.GetBytes($s) }
function Ascii($s) { return [Text.Encoding]::ASCII.GetBytes($s) }

$P = 'ver=6.2.0.1829_x64_pro_eng&code=QK7X-M2PV-ZLHD-W8CT-RBNQ&name=ZakaTest&email=zaka@example.com&mid=0000000000000000&applang=Eng'
$cases = [ordered]@{
    'baseline_empty'   = @()
    'u16_1TEST'        = (Utf16 '1TEST')
    'u16_9TEST'        = (Utf16 '9TEST')
    'u16_0TEST'        = (Utf16 '0TEST')
    'u16_2TEST'        = (Utf16 '2TEST')
    'u16_1TEST_nul'    = (Utf16 "1TEST`0")
    'a_1TEST'          = (Ascii '1TEST')
    'u16_1_payload'    = (Utf16 "1appname=DiskGenius&$P")
    'u16_1_lic'        = (Utf16 '1appname=DiskGenius&license=SIG&user=Boss&email=boss@example.com')
}

$results = @()
try {
    foreach ($name in $cases.Keys) {
        Get-Process DiskGenius -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Milliseconds 400
        $data = [byte[]]$cases[$name]
        foreach ($sub in 'Reg','CReg') {
            try { Set-RegBin $sub 'license' $data 3 } catch { Log "set $sub failed: $_" }
        }
        Start-Sleep -Milliseconds 300
        $snapBefore = Snapshot
        $p = Start-Process -FilePath $exe -WorkingDirectory $game -PassThru
        Start-Sleep -Seconds 12
        $alive = -not $p.HasExited
        $wins = @()
        try { $wins = WindowTitles $p.Id } catch { }
        $snapAfter = Snapshot
        if ($alive) { $p.Kill() }
        Start-Sleep -Milliseconds 500
        $snapEnd = Snapshot
        $rec = [ordered]@{
            case = $name; bytes = $data.Length; alive = $alive
            windows = $wins
            changed = ($snapBefore.iniSha -ne $snapAfter.iniSha) -or ($snapBefore.iniSha -ne $snapEnd.iniSha)
            before = $snapBefore; after = $snapAfter; end = $snapEnd
        }
        $results += $rec
        Log ("CASE {0} bytes={1} alive={2} titles=[{3}] iniChanged={4} Reg_license={5} ShowLicense={6} Improveplan={7}" -f `
            $name, $data.Length, $alive, (($wins | ForEach-Object { $_.title }) -join ' | '), $rec.changed, `
            ($snapEnd['Reg']['license']), ($snapEnd['Reg']['ShowLicense']), ($snapEnd['Reg']['Improveplan']))
    }
} finally {
    Get-Process DiskGenius -ErrorAction SilentlyContinue | Stop-Process -Force
    foreach ($key in $bak.Keys) {
        $b = $bak[$key]
        try {
            $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$regPath\$($b.sub)", $true)
            if ($null -ne $k) {
                if ($null -eq $b.value) { $k.DeleteValue($b.name, $false) } else { $k.SetValue($b.name, $b.value, $b.kind) }
                $k.Close()
            }
        } catch { Log "restore $key failed: $_" }
    }
    if ($null -ne $iniBak) { [IO.File]::WriteAllBytes($ini, $iniBak) }
    $results | ConvertTo-Json -Depth 8 | Out-File -FilePath $json -Encoding utf8
    Log 'RESTORED'
}
Log 'DONE'

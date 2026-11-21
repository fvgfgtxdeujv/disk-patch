#Requires -RunAsAdministrator
# 用菜单/按钮文本判断 key 是否被接受（需管理员）
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$game = Join-Path $root 'out\runtime\DiskGenius'
$exe  = Join-Path $game 'DiskGenius.exe'
$log  = Join-Path $root 'out\_hk_menu_probe.log'
$regPath = 'SOFTWARE\Eassos\DiskGenius'

function Log($s) { $s | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $s }

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class M {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern IntPtr GetMenu(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetMenuItemCount(IntPtr m);
  [DllImport("user32.dll")] public static extern IntPtr GetSubMenu(IntPtr m, int pos);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetMenuString(IntPtr m, uint id, StringBuilder s, int n, uint flags);
  [DllImport("user32.dll")] public static extern uint GetMenuItemID(IntPtr m, int pos);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
}
'@

function Txt([IntPtr]$h) { $sb = New-Object System.Text.StringBuilder 1024; [void][M]::GetWindowText($h, $sb, 1024); $sb.ToString() }
function Cls([IntPtr]$h) { $sb = New-Object System.Text.StringBuilder 256; [void][M]::GetClassName($h, $sb, 256); $sb.ToString() }

function DumpMenu([IntPtr]$m, [string]$indent) {
    $n = [M]::GetMenuItemCount($m)
    for ($i = 0; $i -lt $n; $i++) {
        $sb = New-Object System.Text.StringBuilder 512
        [void][M]::GetMenuString($m, [uint32]$i, $sb, 512, 0x400)  # MF_BYPOSITION
        $id = [M]::GetMenuItemID($m, $i)
        Log ("{0}{1} [id=0x{2:x}]" -f $indent, $sb.ToString().Replace('&',''), $id)
        $sub = [M]::GetSubMenu($m, $i)
        if ($sub -ne [IntPtr]::Zero) { DumpMenu $sub ($indent + '    ') }
    }
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'need admin'; exit 1
}
"start $(Get-Date -Format o)" | Out-File -FilePath $log -Encoding utf8

$bak = @{}
foreach ($sub in 'Reg','CReg') {
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$regPath\$sub", $true)
    if ($null -eq $k) { continue }
    $bak[$sub] = @{ kind = $k.GetValueKind('license'); value = $k.GetValue('license') }
    $k.Close()
}

$cases = [ordered]@{
    'empty'  = $null
    'u16_1'  = '1TEST'
    'u16_9'  = '9TEST'
    'u16_a'  = 'aTEST'
}
try {
    foreach ($name in $cases.Keys) {
        Get-Process DiskGenius -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Milliseconds 400
        $v = $cases[$name]
        foreach ($sub in 'Reg','CReg') {
            $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$regPath\$sub", $true)
            if ($null -eq $k) { continue }
            if ($null -eq $v) { $k.SetValue('license', [byte[]]@(), 'Binary') }
            else { $k.SetValue('license', [Text.Encoding]::Unicode.GetBytes($v), 'Binary') }
            $k.Close()
        }
        $p = Start-Process -FilePath $exe -WorkingDirectory $game -PassThru
        Start-Sleep -Seconds 10
        $script:main = [IntPtr]::Zero
        $cb = [M+EnumProc]{
            param($h, $l)
            $q = 0; [void][M]::GetWindowThreadProcessId($h, [ref]$q)
            if ($q -eq $p.Id) {
                $sb = New-Object System.Text.StringBuilder 512
                [void][M]::GetWindowText($h, $sb, 512)
                if ($sb.ToString() -like 'DiskGenius*') { $script:main = $h }
            }
            return $true
        }
        [void][M]::EnumWindows($cb, [IntPtr]::Zero)
        $main = $script:main
        Log "===== CASE $name main=$main title=$(if($main -ne [IntPtr]::Zero){Txt $main})"
        if ($main -ne [IntPtr]::Zero) {
            $m = [M]::GetMenu($main)
            if ($m -ne [IntPtr]::Zero) { DumpMenu $m '' } else { Log '(no menu)' }
            $cb2 = [M+EnumProc]{
                param($ch, $l2)
                $t = Txt $ch; $c = Cls $ch
                if ($t -and ([M]::IsWindowVisible($ch))) { Log ("   BTN cls={0} text={1}" -f $c, $t) }
                return $true
            }
            [void][M]::EnumChildWindows($main, $cb2, [IntPtr]::Zero)
        }
        if (-not $p.HasExited) { $p.Kill() }
        Start-Sleep -Milliseconds 400
    }
} finally {
    Get-Process DiskGenius -ErrorAction SilentlyContinue | Stop-Process -Force
    foreach ($sub in $bak.Keys) {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$regPath\$sub", $true)
        if ($null -ne $k) {
            if ($null -eq $bak[$sub].value) { $k.DeleteValue('license', $false) } else { $k.SetValue('license', $bak[$sub].value, $bak[$sub].kind) }
            $k.Close()
        }
    }
    Log 'RESTORED'
}
Log 'DONE'

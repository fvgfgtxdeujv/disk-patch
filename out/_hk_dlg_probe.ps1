#Requires -RunAsAdministrator
# 抓取 “Error Message” 对话框正文 + 截图（需管理员）
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$game = Join-Path $root 'out\runtime\DiskGenius'
$exe  = Join-Path $game 'DiskGenius.exe'
$log  = Join-Path $root 'out\_hk_dlg_probe.log'
$regPath = 'SOFTWARE\Eassos\DiskGenius'

function Log($s) { $s | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $s }

Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class W {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
'@

function Txt([IntPtr]$h) { $sb = New-Object System.Text.StringBuilder 1024; [void][W]::GetWindowText($h, $sb, 1024); $sb.ToString() }
function Cls([IntPtr]$h) { $sb = New-Object System.Text.StringBuilder 256; [void][W]::GetClassName($h, $sb, 256); $sb.ToString() }

function Shoot([IntPtr]$h, [string]$path) {
    $r = New-Object W+RECT
    if (-not [W]::GetWindowRect($h, [ref]$r)) { return $false }
    $w = $r.Right - $r.Left; $ht = $r.Bottom - $r.Top
    if ($w -le 0 -or $ht -le 0) { return $false }
    $bmp = New-Object System.Drawing.Bitmap $w, $ht
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    [void][W]::PrintWindow($h, $hdc, 2)
    $g.ReleaseHdc($hdc); $g.Dispose()
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
    return $true
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
    $k.SetValue('license', [Text.Encoding]::Unicode.GetBytes('1TEST'), 'Binary')
    $k.Close()
}

$p = Start-Process -FilePath $exe -WorkingDirectory $game -PassThru
Start-Sleep -Seconds 9
$targets = New-Object System.Collections.ArrayList
$cb = [W+EnumProc]{
    param($h, $l)
    $q = 0; [void][W]::GetWindowThreadProcessId($h, [ref]$q)
    if ($q -eq $p.Id) { [void]$targets.Add($h) }
    return $true
}
[void][W]::EnumWindows($cb, [IntPtr]::Zero)
Log "top windows: $($targets.Count)"
$n = 0
foreach ($h in $targets) {
    $t = Txt $h; $c = Cls $h
    Log ("TOP [{0}] cls={1} vis={2} title={3}" -f $h, $c, [W]::IsWindowVisible($h), $t)
    $kids = New-Object System.Collections.ArrayList
    $cb2 = [W+EnumProc]{
        param($ch, $l2)
        Log ("   CHILD cls={0} vis={1} text={2}" -f (Cls $ch), [W]::IsWindowVisible($ch), (Txt $ch))
        return $true
    }
    [void][W]::EnumChildWindows($h, $cb2, [IntPtr]::Zero)
    if ($t) {
        $n++
        $safe = ($t -replace '[^\w\u4e00-\u9fa5]+', '_')
        $png = Join-Path $root ("out\_dlg_{0}_{1}.png" -f $n, $safe)
        if (Shoot $h $png) { Log "SHOT $png" }
    }
}
if (-not $p.HasExited) { $p.Kill() }
Start-Sleep -Milliseconds 500
foreach ($sub in $bak.Keys) {
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$regPath\$sub", $true)
    if ($null -ne $k) {
        if ($null -eq $bak[$sub].value) { $k.DeleteValue('license', $false) } else { $k.SetValue('license', $bak[$sub].value, $bak[$sub].kind) }
        $k.Close()
    }
}
Log 'RESTORED'
Log 'DONE'

#Requires -RunAsAdministrator
# 打开 Help->About 对话框，抓取正文与截图（需管理员）
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$game = Join-Path $root 'out\runtime\DiskGenius'
$exe  = Join-Path $game 'DiskGenius.exe'
$log  = Join-Path $root 'out\_hk_about_probe.log'
$regPath = 'SOFTWARE\Eassos\DiskGenius'
function Log($s) { $s | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $s }

Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class A {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern IntPtr PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
'@
function Txt([IntPtr]$h) { $sb = New-Object System.Text.StringBuilder 2048; [void][A]::GetWindowText($h, $sb, 2048); $sb.ToString() }
function Cls([IntPtr]$h) { $sb = New-Object System.Text.StringBuilder 256; [void][A]::GetClassName($h, $sb, 256); $sb.ToString() }
function Shoot([IntPtr]$h, [string]$path) {
    $r = New-Object A+RECT
    if (-not [A]::GetWindowRect($h, [ref]$r)) { return $false }
    $w = $r.Right - $r.Left; $ht = $r.Bottom - $r.Top
    if ($w -le 0 -or $ht -le 0) { return $false }
    $bmp = New-Object System.Drawing.Bitmap $w, $ht
    $g = [System.Drawing.Graphics]::FromImage($bmp); $hdc = $g.GetHdc()
    [void][A]::PrintWindow($h, $hdc, 2); $g.ReleaseHdc($hdc); $g.Dispose()
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose(); return $true
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host 'need admin'; exit 1 }
"start $(Get-Date -Format o)" | Out-File -FilePath $log -Encoding utf8
$bak = @{}
foreach ($sub in 'Reg','CReg') {
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$regPath\$sub", $true)
    if ($null -eq $k) { continue }
    $bak[$sub] = @{ kind = $k.GetValueKind('license'); value = $k.GetValue('license') }; $k.Close()
}
$cases = [ordered]@{ 'empty' = $null; 'u16_1' = '1TEST'; 'u16_9' = '9TEST'; 'u16_1payload' = '1appname=DiskGenius&license=SIG&user=Boss&email=boss@example.com' }
try {
  foreach ($name in $cases.Keys) {
    Get-Process DiskGenius -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Milliseconds 400
    $v = $cases[$name]
    foreach ($sub in 'Reg','CReg') {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$regPath\$sub", $true)
        if ($null -eq $k) { continue }
        if ($null -eq $v) { $k.SetValue('license', [byte[]]@(), 'Binary') } else { $k.SetValue('license', [Text.Encoding]::Unicode.GetBytes($v), 'Binary') }
        $k.Close()
    }
    $p = Start-Process -FilePath $exe -WorkingDirectory $game -PassThru
    Start-Sleep -Seconds 10
    $script:main = [IntPtr]::Zero
    $cb = [A+EnumProc]{ param($h,$l) $q=0; [void][A]::GetWindowThreadProcessId($h,[ref]$q); if($q -eq $p.Id){ $t=Txt $h; if($t -like 'DiskGenius*'){ $script:main=$h } }; return $true }
    [void][A]::EnumWindows($cb, [IntPtr]::Zero)
    Log "===== CASE $name main=$($script:main) title=$(Txt $script:main)"
    if ($script:main -ne [IntPtr]::Zero) {
        [void][A]::PostMessage($script:main, 0x111, [IntPtr]0xa5, [IntPtr]::Zero)
        Start-Sleep -Seconds 2
    }
    $wins = New-Object System.Collections.ArrayList
    $cb3 = [A+EnumProc]{ param($h,$l) $q=0; [void][A]::GetWindowThreadProcessId($h,[ref]$q); if($q -eq $p.Id){ [void]$wins.Add($h) }; return $true }
    [void][A]::EnumWindows($cb3, [IntPtr]::Zero)
    $i = 0
    foreach ($h in $wins) {
        $t = Txt $h
        if ($t -and [A]::IsWindowVisible($h)) {
            Log "TOP $t (cls=$(Cls $h))"
            $cb4 = [A+EnumProc]{ param($ch,$l2) if([A]::IsWindowVisible($ch)){ Log ("   CHILD text={0}" -f (Txt $ch)) }; return $true }
            [void][A]::EnumChildWindows($h, $cb4, [IntPtr]::Zero)
            if ($t -match 'About') { $i++; $safe = ($t -replace '[^\w]+','_'); $png = Join-Path $root ("out\_about_{0}_{1}.png" -f $name, $i); if (Shoot $h $png) { Log "SHOT $png" } }
        }
    }
    if (-not $p.HasExited) { $p.Kill() }
    Start-Sleep -Milliseconds 400
  }
} finally {
  Get-Process DiskGenius -ErrorAction SilentlyContinue | Stop-Process -Force
  foreach ($sub in $bak.Keys) { $k=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$regPath\$sub",$true); if($null -ne $k){ if($null -eq $bak[$sub].value){ $k.DeleteValue('license',$false) } else { $k.SetValue('license',$bak[$sub].value,$bak[$sub].kind) }; $k.Close() } }
  Log 'RESTORED'
}
Log 'DONE'

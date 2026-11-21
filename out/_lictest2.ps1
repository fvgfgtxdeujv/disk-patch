param([string]$root)
$ErrorActionPreference = 'Continue'
$game = Join-Path $root 'out\runtime\DiskGenius'
$exe = Join-Path $game 'DiskGenius.exe'
$ini = Join-Path $game 'Options.ini'
$log = Join-Path $root 'out\_lictest2.log'
"start $(Get-Date -Format o)" | Out-File -FilePath $log -Encoding utf8

function Ini-Bytes([string]$key) {
    $lines = @('[LicenseInfo]', 'Show = "6.2.0.1829"', '', '[license]',
        'appname = "DiskGenius"', 'user = ""', 'email = "license@eassos.com"',
        'regcode = ""', 'regver = "6.2.0.1829_x64_pro_eng"', "key = `"$key`"")
    return [Text.Encoding]::Unicode.GetPreamble() + [Text.Encoding]::Unicode.GetBytes(($lines -join "`r`n") + "`r`n")
}

function Reg-Dump {
    $p = 'HKCU:\Software\Eassos\DiskGenius'
    if (-not (Test-Path $p)) { return '<none>' }
    return (Get-ChildItem $p -Recurse | ForEach-Object { $_.Name; Get-ItemProperty $_.PSPath | Format-List | Out-String }) -join "`n"
}

$P = 'ver=6.2.0.1829_x64_pro_eng&code=QK7X-M2PV-ZLHD-W8CT-RBNQ&name=ZakaTest&email=zaka@example.com&mid=0000000000000000&applang=Eng'
$md5 = [Security.Cryptography.MD5]::Create()
$H = ([BitConverter]::ToString($md5.ComputeHash([Text.Encoding]::ASCII.GetBytes($P)))).Replace('-','')
$xor = -join ($P.ToCharArray() | ForEach-Object { [char]([int]$_ -bxor 14) })
$xorH = -join (($P + '&check=' + $H).ToCharArray() | ForEach-Object { [char]([int]$_ -bxor 14) })

$cases = [ordered]@{
  'fake_sample' = 'appname=DiskGenius&license=SIG&user=ZakaTest&email=zaka@example.com'
  'plain_check' = "appname=DiskGenius&$P&check=$H"
  'enc_check'   = "appname=DiskGenius&encryption=$xorH"
}
$bak = [IO.File]::ReadAllBytes($ini)

try {
    foreach ($name in $cases.Keys) {
        Get-Process DiskGenius -ErrorAction SilentlyContinue | Stop-Process -Force
        [IO.File]::WriteAllBytes($ini, (Ini-Bytes $cases[$name]))
        Start-Sleep -Milliseconds 300
        $p = Start-Process -FilePath $exe -WorkingDirectory $game -PassThru
        Start-Job -ScriptBlock {
            param($name)
            Start-Sleep -Seconds 3
            $ws = New-Object -ComObject WScript.Shell
            for ($i = 0; $i -lt 12; $i++) {
                if ($ws.AppActivate('DiskGenius')) { $ws.SendKeys('{F5}') }
                Start-Sleep -Seconds 2
            }
        } -ArgumentList $name | Out-Null
        foreach ($t in 8, 16, 26) {
            $elapsed = $t
            Start-Sleep -Seconds ($elapsed - [int]((Get-Date) - $p.StartTime).TotalSeconds)
            $exists = Test-Path $ini
            $size = 0
            if ($exists) { $size = (Get-Item $ini).Length }
            "$name t=$t exists=$exists size=$size" | Out-File -FilePath $log -Append -Encoding utf8
        }
        "reg=$((Reg-Dump))" | Out-File -FilePath $log -Append -Encoding utf8
        Get-Process DiskGenius -ErrorAction SilentlyContinue | Stop-Process -Force
        Get-Job | Remove-Job -Force
        Start-Sleep -Milliseconds 500
    }
} finally {
    Get-Process DiskGenius -ErrorAction SilentlyContinue | Stop-Process -Force
    [IO.File]::WriteAllBytes($ini, $bak)
    "restored" | Out-File -FilePath $log -Append -Encoding utf8
}
"DONE" | Out-File -FilePath $log -Append -Encoding utf8

$root = Split-Path -Parent $PSScriptRoot
$py = (Get-Command python).Source
$env:PYTHONIOENCODING = 'utf-8'
$log = Join-Path $root 'out\_onebyte.log'
"start" | Out-File -Encoding utf8 $log
foreach ($k in @('empty','1','9','a','t','1TEST','9TEST','tTEST')) {
    $a1 = @((Join-Path $root 'out\_onebyte_probe.py'))
    if ($k -ne 'empty') { $a1 += @('--key', $k) }
    & $py @a1 2>&1 | Out-File -Append -Encoding utf8 $log
}
"done" | Out-File -Append -Encoding utf8 $log

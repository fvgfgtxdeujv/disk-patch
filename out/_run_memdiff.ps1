$root = Split-Path -Parent $PSScriptRoot
$py = (Get-Command python).Source
$env:PYTHONIOENCODING = 'utf-8'
$log = Join-Path $root 'out\_run_memdiff.log'
"start $(Get-Date -Format o)" | Out-File -Encoding utf8 $log
foreach ($k in @('empty','1TEST','aTEST')) {
    $args1 = @((Join-Path $root 'out\_mem_diff.py'), '--seconds', '12', '--tag', $k)
    if ($k -ne 'empty') { $args1 += @('--key', $k) }
    "=== $k" | Out-File -Append -Encoding utf8 $log
    & $py @args1 2>&1 | Out-File -Append -Encoding utf8 $log
}
"done" | Out-File -Append -Encoding utf8 $log

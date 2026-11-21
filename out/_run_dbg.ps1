$root = Split-Path -Parent $PSScriptRoot
$py = (Get-Command python).Source
$env:PYTHONIOENCODING = 'utf-8'
$log = Join-Path $root 'out\_run_dbg.log'
"start $(Get-Date -Format o) py=$py" | Out-File -Encoding utf8 $log
foreach ($k in @('1TEST','9TEST','aTEST')) {
    "=== key=$k" | Out-File -Append -Encoding utf8 $log
    & $py (Join-Path $root 'out\_dg_dbg.py') --key $k --seconds 30 2>&1 | Out-File -Append -Encoding utf8 $log
    "exit=$LASTEXITCODE" | Out-File -Append -Encoding utf8 $log
}
"done" | Out-File -Append -Encoding utf8 $log

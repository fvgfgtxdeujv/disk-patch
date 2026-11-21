$root = Split-Path -Parent $PSScriptRoot
$py = (Get-Command python).Source
$env:PYTHONIOENCODING = 'utf-8'
$log = Join-Path $root 'out\_run_mitm.log'
& $py (Join-Path $root 'out\_hosts_mitm.py') --key 1TEST --seconds 16 2>&1 | Out-File -Encoding utf8 $log
"exit=$LASTEXITCODE" | Out-File -Append -Encoding utf8 $log

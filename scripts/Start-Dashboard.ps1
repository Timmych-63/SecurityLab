param([string]$State = (Join-Path $env:TEMP 'SecurityLab_S72_DemoState'), [int]$Port = 8765)
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    if (-not (Test-Path '.\dashboard\dist\index.html')) { throw 'Dashboard build missing. Extract the complete S8.1 update.' }
    Write-Host "Open http://127.0.0.1:$Port in your browser. State: $State"
    py -3 -m securitylab.dashboard --state "$State" --port $Port
    if ($LASTEXITCODE -ne 0) { throw "Dashboard exited with code $LASTEXITCODE" }
} finally { Pop-Location }

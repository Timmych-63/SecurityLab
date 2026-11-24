param([string]$State = (Join-Path $env:TEMP 'SecurityLab_S72_DemoState'), [int]$Port = 8765)
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    # S11.5: dashboard\dist.local (if present) wins over the git-tracked dashboard\dist.
    # UI updates delivered as a patch can live outside Git without dirtying the working tree.
    $dist = '.\dashboard\dist'
    if (Test-Path '.\dashboard\dist.local\index.html') { $dist = '.\dashboard\dist.local' }
    if (-not (Test-Path (Join-Path $dist 'index.html'))) { throw 'Dashboard build missing. Extract the complete S8.1 update.' }
    Write-Host "Open http://127.0.0.1:$Port in your browser. State: $State"
    Write-Host "UI folder: $dist"
    py -3 -m securitylab.dashboard --state "$State" --port $Port --dist "$dist"
    if ($LASTEXITCODE -ne 0) { throw "Dashboard exited with code $LASTEXITCODE" }
} finally { Pop-Location }

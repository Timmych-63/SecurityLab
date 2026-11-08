$ErrorActionPreference = "Stop"
Push-Location (Join-Path $PSScriptRoot "..")
try {
    py -3 -m securitylab demo
    if ($LASTEXITCODE -ne 0) { throw "Demo failed: $LASTEXITCODE" }
} finally { Pop-Location }

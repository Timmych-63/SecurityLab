$ErrorActionPreference = "Stop"
Push-Location (Join-Path $PSScriptRoot "..")
try {
    py -3 -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw "Tests failed: $LASTEXITCODE" }
    py -3 -m securitylab doctor
    if ($LASTEXITCODE -ne 0) { throw "Doctor failed: $LASTEXITCODE" }
} finally { Pop-Location }

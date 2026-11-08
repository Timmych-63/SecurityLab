$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE. Stop here and send the output." }
}
Write-Host 'S4: building the isolated Hermes environment (first build may take several minutes).'
Invoke-Checked 'docker' @('compose', '-f', 'compose.ai.yaml', '--profile', 'build', 'build', 'hermes')
Write-Host 'Downloading the local model (~2.7 GB); already downloaded layers are reused.'
Invoke-Checked 'docker' @('compose', '-f', 'compose.ai.yaml', '--profile', 'setup', 'run', '--rm', 'model-pull')
Invoke-Checked 'docker' @('compose', '-f', 'compose.ai.yaml', 'up', '-d', 'model')
Write-Host 'Waiting for the local model server...'
$Ready = $false
for ($Attempt = 0; $Attempt -lt 30; $Attempt++) {
    & docker compose -f compose.ai.yaml exec -T model ollama list
    if ($LASTEXITCODE -eq 0) { $Ready = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $Ready) { throw 'Model server did not become ready.' }
Invoke-Checked 'py' @('-3', '-m', 'securitylab', 'ai-smoke')
Write-Host 'Running Red, then Blue, then independent S3 checks.'
Invoke-Checked 'py' @('-3', '-m', 'securitylab', 'ai-demo')

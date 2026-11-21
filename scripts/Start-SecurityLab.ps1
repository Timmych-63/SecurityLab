# S11.3: start after reboot - Docker engine -> model service -> ollama readiness -> dashboard.
# Replaces the manual sequence "Docker Desktop -> compose up model -> wait for
# ollama list -> Start-Dashboard.ps1". Safe to re-run at any time: every step is
# idempotent and the dashboard is only started last.
param([string]$State = (Join-Path $env:TEMP 'SecurityLab_S72_DemoState'), [int]$Port = 8765)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Push-Location $projectRoot
try {
    # Native stderr under $ErrorActionPreference='Stop' turns into
    # NativeCommandError in Windows PowerShell 5.1 the moment streams are
    # redirected; every docker invocation therefore runs with 'Continue'
    # inside Invoke-Docker and is judged by $LASTEXITCODE.
    function Invoke-Docker {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $output = & docker @args 2>&1
            $code = $LASTEXITCODE
            $text = ($output | ForEach-Object { "$_" }) -join "`r`n"
            return @{ Code = $code; Output = $text }
        } finally { $ErrorActionPreference = $prev }
    }

    Write-Host '[1/4] Проверка Docker engine...'
    $engine = Invoke-Docker info
    if ($engine.Code -ne 0) {
        $candidates = @(
            (Join-Path $env:LOCALAPPDATA 'Docker\Docker Desktop.exe'),
            (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe')
        ) | Where-Object { $_ -and (Test-Path $_) }
        if ($candidates.Count -gt 0) {
            Write-Host 'Docker engine не отвечает; запускаю Docker Desktop...'
            Start-Process @($candidates)[0]
        } else {
            throw 'Docker engine недоступен, Docker Desktop.exe не найден в стандартных путях; запустите Docker Desktop вручную и повторите.'
        }
        $deadline = (Get-Date).AddMinutes(5)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 5
            $engine = Invoke-Docker info
            if ($engine.Code -eq 0) { break }
        }
        if ($engine.Code -ne 0) { throw 'Docker engine не ответил за 5 минут; откройте Docker Desktop и дождитесь статуса running.' }
    }
    Write-Host '[1/4] Docker engine готов.'

    Write-Host '[2/4] Подъём сервиса model (compose.ai.yaml)...'
    $up = Invoke-Docker compose -f compose.ai.yaml up -d model
    if ($up.Code -ne 0) { throw ('compose up model завершился с ошибкой: ' + $up.Output.Substring(0, [Math]::Min(800, $up.Output.Length))) }
    Write-Host '[2/4] Сервис model запущен (restart: unless-stopped поднимет его и после перезагрузки).'

    Write-Host '[3/4] Ожидание готовности ollama (серверу нужно несколько секунд)...'
    $deadline = (Get-Date).AddMinutes(3)
    $modelReady = $false
    while ((Get-Date) -lt $deadline) {
        $list = Invoke-Docker compose -f compose.ai.yaml exec -T model ollama list
        if ($list.Code -eq 0 -and $list.Output.Trim()) { $modelReady = $true; break }
        Start-Sleep -Seconds 5
    }
    if (-not $modelReady) {
        throw 'ollama list не ответил за 3 минуты; проверьте контейнер: docker compose -f compose.ai.yaml logs model'
    }
    Write-Host '[3/4] Модель-сервер отвечает:'
    Write-Host $list.Output.Trim()

    if (-not (Test-Path '.\dashboard\dist\index.html')) { throw 'Dashboard build missing. Extract the complete S8.1 update.' }
    Write-Host ('[4/4] Запуск дашборда (http://127.0.0.1:' + $Port + ', state: ' + $State + ').')
    & powershell -ExecutionPolicy Bypass -File .\scripts\Start-Dashboard.ps1 -State $State -Port $Port
} finally { Pop-Location }


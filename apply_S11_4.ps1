# S11.4 apply script. Unpacks update/ (all S11.3 edits plus the run #7 crash fix),
# verifies edit markers, backs up replaced
# files, rebuilds the Hermes image with COPY-layer CACHED control and runs ai-smoke.
#
# PowerShell 5.1 note (live build hotfix): docker build writes progress to stderr;
# with $ErrorActionPreference='Stop' any redirected stderr line becomes
# NativeCommandError and can abort the script before steps [5/6]/[6/6]. Every
# native call therefore runs with 'Continue' inside Invoke-Native and is judged
# by $LASTEXITCODE, never by exception flow.
param([string]$ZipPath = '')
$ErrorActionPreference = 'Stop'

function Invoke-Native {
    param([string]$FilePath, [string[]]$Arguments = @())
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $FilePath @Arguments 2>&1
        $code = $LASTEXITCODE
        $text = ($output | ForEach-Object { "$_" }) -join "`r`n"
        return @{ Code = $code; Output = $text }
    } finally { $ErrorActionPreference = $prev }
}

function Fail($msg) {
    Write-Host ''
    Write-Host ('ПРИМЕНЕНИЕ ОСТАНОВЛЕНО: ' + $msg) -ForegroundColor Red
    exit 2
}

$cwd = (Get-Location).Path
if (Test-Path (Join-Path $cwd 'securitylab')) {
    $projectRoot = $cwd
} elseif (Test-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'securitylab')) {
    $projectRoot = Split-Path $PSScriptRoot -Parent
} else {
    Fail 'запустите скрипт из корня проекта SecurityLab (папка, где лежит каталог securitylab)'
}
$markers = [ordered]@{
    'securitylab/research_contract.py' = @('probe_suggestions', 'SUGGESTED NEXT PROBES')
    'securitylab/research_cycle.py'    = @('observed_stage', "proposal.get('action')")
    'securitylab/dashboard_dto.py'     = @('observedStage')
    'scripts/Start-SecurityLab.ps1'    = @('ollama list')
    'compose.ai.yaml'                  = @('unless-stopped')
    'ai.example.toml'                  = @('frequency_penalty')
    'examples/research/authznotes.md'  = @('AuthzNotes')
    'README_S11_3_RU.md'               = @('S11.3')
    'README_S11_4_RU.md'               = @('S11.4')
}

Write-Host '[1/6] Архив обновления.'
if (-not $ZipPath) {
    foreach ($candidate in @((Join-Path $PSScriptRoot 'SecurityLab_S11_4_update.zip'),
                             (Join-Path $projectRoot 'SecurityLab_S11_4_update.zip'))) {
        if (Test-Path $candidate) { $ZipPath = $candidate; break }
    }
}
if (-not $ZipPath -or -not (Test-Path $ZipPath)) {
    Fail ('архив не найден; положите SecurityLab_S11_4_update.zip рядом со скриптом или укажите -ZipPath')
}
$zipItem = Get-Item $ZipPath
if ($zipItem.Length -lt 10000) { Fail 'архив подозрительно мал (<10 КБ); вероятно, повреждён или докачан не полностью' }
if ($zipItem.Length -gt 100MB) { Fail 'архив больше 100 МБ; проверьте, тот ли это файл' }
Write-Host ('      ' + $zipItem.FullName + ' (' + [Math]::Round($zipItem.Length / 1KB) + ' КБ)')

Write-Host '[2/6] Распаковка и проверка маркеров правок.'
$tmp = Join-Path $env:TEMP ('SecurityLab_S11_4_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Expand-Archive -Path $zipItem.FullName -DestinationPath $tmp -Force
} catch {
    Fail ('архив не распаковался: ' + $_.Exception.Message)
}
$updateRoot = Join-Path $tmp 'update'
if (-not (Test-Path $updateRoot)) { Fail 'в архиве нет папки update/' }
foreach ($rel in $markers.Keys) {
    $path = Join-Path $updateRoot ($rel -replace '/', '\')
    if (-not (Test-Path $path)) { Fail ('маркер-файл отсутствует в архиве: ' + $rel) }
    $content = [System.IO.File]::ReadAllText($path)
    foreach ($marker in $markers[$rel]) {
        if (-not $content.Contains($marker)) { Fail ("маркер '" + $marker + "' не найден в " + $rel) }
    }
}
if (-not (Test-Path (Join-Path $updateRoot 'dashboard\dist\index.html'))) {
    Fail 'в архиве нет dashboard/dist/index.html (собранный интерфейс)'
}
Write-Host ('      Маркеры подтверждены в ' + $markers.Count + ' файлах + dist.')

Write-Host '[3/6] Резервная копия заменяемых файлов.'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$backupRoot = Join-Path (Join-Path $projectRoot '_backup_S11_4') $stamp
$backedUp = 0
foreach ($rel in $markers.Keys) {
    $dest = Join-Path $projectRoot ($rel -replace '/', '\')
    if (Test-Path $dest) {
        $bk = Join-Path $backupRoot ($rel -replace '/', '\')
        New-Item -ItemType Directory -Path (Split-Path $bk -Parent) -Force | Out-Null
        Copy-Item $dest $bk -Force
        $backedUp++
    }
}
Write-Host ('      Сохранено файлов: ' + $backedUp + ' -> ' + $backupRoot)

Write-Host '[4/6] Копирование update/ в корень проекта.'
$dist = Join-Path $projectRoot 'dashboard\dist'
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
Copy-Item (Join-Path $updateRoot '*') $projectRoot -Recurse -Force
foreach ($rel in $markers.Keys) {
    $path = Join-Path $projectRoot ($rel -replace '/', '\')
    if (-not (Test-Path $path)) { Fail ('после копирования отсутствует файл: ' + $rel) }
    $content = [System.IO.File]::ReadAllText($path)
    foreach ($marker in $markers[$rel]) {
        if (-not $content.Contains($marker)) { Fail ("маркер '" + $marker + "' не найден после копирования в " + $rel) }
    }
}
Write-Host '      Файлы обновлены; маркеры подтверждены на месте.'

Write-Host '[5/6] Пересборка образа securitylab-hermes:s4 (это может занять пару минут).'
$docker = Invoke-Native 'docker' @('info')
if ($docker.Code -ne 0) {
    Fail 'Docker engine недоступен; запустите Docker Desktop и повторите скрипт целиком'
}
$build = Invoke-Native 'docker' @('compose', '-f', 'compose.ai.yaml', '--profile', 'build', 'build', '--progress=plain', 'hermes')
$logFile = Join-Path $backupRoot 'docker_build.log'
[System.IO.File]::WriteAllText($logFile, $build.Output)
if ($build.Code -ne 0) {
    Fail ('сборка образа завершилась с ошибкой (лог: ' + $logFile + ')')
}
$lines = $build.Output -split "`r?`n"
$copyIndex = -1
$stepId = $null
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^\s*#(\d+)\s+\[[\d/]+\]\s+COPY securitylab') {
        $copyIndex = $i; $stepId = $matches[1]; break
    }
    if ($lines[$i] -match '^\s*Step\s+\d+/\d+\s*:\s*COPY securitylab') {
        $copyIndex = $i; break
    }
}
if ($copyIndex -lt 0) {
    Fail ('в логе сборки не найден шаг COPY securitylab; контроль CACHED невозможен (лог: ' + $logFile + ')')
}
$isCached = $false
for ($i = $copyIndex + 1; $i -lt [Math]::Min($lines.Count, $copyIndex + 6); $i++) {
    if ($stepId -and $lines[$i] -match ('^\s*#' + $stepId + '\s+CACHED')) { $isCached = $true; break }
    if ($stepId -and $lines[$i] -match ('^\s*#' + $stepId + '\s+DONE')) { break }
    if (-not $stepId -and $lines[$i].Contains('CACHED')) { $isCached = $true; break }
    if (-not $stepId -and $lines[$i] -match 'SUCCESS') { break }
}
if ($isCached) {
    Fail 'шаг COPY securitylab вышел CACHED - в образе остался прежний код worker. Убедитесь, что update применён в этот каталог, и запустите скрипт заново.'
}
Write-Host ('      Шаг COPY securitylab пересобран (не CACHED). Лог: ' + $logFile)

Write-Host '[6/6] py -3 -m securitylab ai-smoke.'
if (-not $env:SECURITYLAB_AI_CONFIG) {
    $localCfg = Join-Path $projectRoot 'ai.local.toml'
    if (Test-Path $localCfg) {
        $env:SECURITYLAB_AI_CONFIG = $localCfg
        Write-Host '      SECURITYLAB_AI_CONFIG установлен на ai.local.toml (только для этого окна).'
    } else {
        Write-Host '      ВНИМАНИЕ: ai.local.toml не найден и SECURITYLAB_AI_CONFIG не задан; smoke проверит дефолтную конфигурацию.' -ForegroundColor Yellow
    }
}
$smoke = Invoke-Native 'py' @('-3', '-m', 'securitylab', 'ai-smoke')
[System.IO.File]::WriteAllText((Join-Path $backupRoot 'ai_smoke.log'), $smoke.Output)
if ($smoke.Code -ne 0 -or -not $smoke.Output.Contains('"status": "PASS"')) {
    Fail ('ai-smoke не прошёл (лог: ' + (Join-Path $backupRoot 'ai_smoke.log') + '); проверьте контейнер model и ai.local.toml')
}
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
Write-Host 'ГОТОВО: S11.4 применён, образ пересобран (COPY не CACHED), ai-smoke PASS.'
Write-Host 'Запуск после перезагрузки или сейчас: powershell -ExecutionPolicy Bypass -File .\scripts\Start-SecurityLab.ps1'

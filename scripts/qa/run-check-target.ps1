<#
.SYNOPSIS
    Запускает check-target.ps1 на удалённой Windows-цели.

.DESCRIPTION
    Обёртка infra\windows\rps.ps1 передаёт скрипт как -EncodedCommand, а base64 от
    UTF-16LE увеличивает объём вчетверо. Полный текст check-target.ps1 уже не
    вписывается в лимит командной строки Windows (32767 символов), и ssh падает с
    «The filename or extension is too long».

    Поэтому скрипт проверки копируется в каталог TEMP целевой машины, а через
    rps.ps1 передаётся короткий загрузчик, который его выполняет и удаляет.
    Ничего кроме временного файла на цели не создаётся и не меняется.

.EXAMPLE
    .\run-check-target.ps1
    .\run-check-target.ps1 -Target root@10.0.0.5 -Key C:\keys\id_ed25519
#>
[CmdletBinding()]
param(
    [string]$Target = 'root@35.208.225.47',
    [string]$Key = 'C:\remote-access\ssh\winsrv_test_ed25519',
    [string]$ScriptPath,
    [string]$RemoteTempDir = 'C:\Users\root\AppData\Local\Temp',
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
# Иначе кириллица из вывода цели превращается в вопросительные знаки.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

# $PSScriptRoot в блоке param() при запуске через -File пуст, поэтому каталог
# скрипта определяется здесь.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ScriptPath) { $ScriptPath = Join-Path $here 'check-target.ps1' }

if (-not (Test-Path $ScriptPath)) { throw "Не найден скрипт проверки: $ScriptPath" }
$rps = Join-Path $here '..\..\infra\windows\rps.ps1'
if (-not (Test-Path $rps)) { throw "Не найдена обёртка rps.ps1: $rps" }

$remotePath = Join-Path $RemoteTempDir 'qa-check-target.ps1'
$scpDest = '{0}:{1}' -f $Target, ($remotePath -replace '\\', '/')

Write-Verbose "Копирую $ScriptPath -> $scpDest"
& scp -i $Key -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 $ScriptPath $scpDest
if ($LASTEXITCODE -ne 0) { throw "scp завершился с кодом $LASTEXITCODE" }

$bootstrap = Join-Path $env:TEMP ("qa-bootstrap-{0}.ps1" -f ([guid]::NewGuid().ToString('N')))
$body = @"
`$p = '$remotePath'
if (-not (Test-Path `$p)) { "ОШИБКА: файл проверки не найден: `$p"; exit 2 }
& `$p
`$code = `$LASTEXITCODE
Remove-Item `$p -Force -ErrorAction SilentlyContinue
if (Test-Path `$p) { "ВНИМАНИЕ: временный файл не удалён: `$p" }
exit `$code
"@
# UTF-8 с BOM: Windows PowerShell 5.1 читает файл без BOM как ANSI и ломает кириллицу.
[System.IO.File]::WriteAllText($bootstrap, $body, (New-Object System.Text.UTF8Encoding($true)))

try {
    $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $rps -ScriptPath $bootstrap -Target $Target -Key $Key 2>&1
}
finally {
    Remove-Item $bootstrap -Force -ErrorAction SilentlyContinue
}

$lines = @($output | ForEach-Object { "$_" })
$lines
if ($OutFile) {
    # Отчёт сохраняется как UTF-8 внутри этого процесса: при передаче вывода
    # дальше по конвейеру кодировку легко потерять, и кириллица станет '?'.
    [System.IO.File]::WriteAllLines($OutFile, [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))
    Write-Verbose "Вывод сохранён в $OutFile"
}

# rps.ps1 не возвращает код завершения ssh, поэтому вердикт берётся из итоговой
# строки отчёта: иначе приёмочные ворота в CI всегда были бы зелёными.
$summary = $lines | Where-Object { $_ -match 'ИТОГО:\s+PASS=' } | Select-Object -First 1
if (-not $summary) {
    Write-Error 'Итоговая строка отчёта не найдена: проверка не выполнилась до конца.'
    exit 2
}
if ($summary -match 'FAIL=(\d+)' -and [int]$Matches[1] -gt 0) { exit 1 }
exit 0

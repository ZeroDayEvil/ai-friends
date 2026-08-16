<#
    Выполняет локальный .ps1 на тестовом сервере через SSH.

    Содержимое файла уходит как -EncodedCommand (UTF-16LE в base64): иначе кавычки
    и спецсимволы пришлось бы экранировать дважды -- для локального PowerShell
    и для удалённого cmd, который на Windows является оболочкой sshd по умолчанию.

    Base64 от UTF-16LE увеличивает объём вчетверо, поэтому крупные скрипты не
    вписываются в лимит командной строки Windows: ssh падает с «The filename or
    extension is too long». Такие скрипты копируются в TEMP цели, выполняются
    оттуда и удаляются.
#>
param(
    [Parameter(Mandatory)][string]$ScriptPath,
    [string]$Target = 'root@35.208.225.47',
    [string]$Key = 'C:\remote-access\ssh\winsrv_test_ed25519',
    # Аргументы удалённого скрипта, например '-Harden'. Скрипт оборачивается в
    # блок кода, потому что -EncodedCommand принимает выражение, а не файл, и
    # объявленный внутри param() иначе не получит значений.
    [string]$Arguments = '',
    [string]$RemoteTempDir = 'C:\Users\root\AppData\Local\Temp'
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$sshArgs = @(
    '-i', $Key, '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=15'
)

function Invoke-Encoded([string]$Text) {
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Text))
    & ssh @sshArgs $Target "powershell -NoProfile -EncodedCommand $enc"
}

# Прогресс-бары приезжают обратно как CLIXML-мусор в stderr, поэтому глушим их.
$body = [System.IO.File]::ReadAllText($ScriptPath, [System.Text.Encoding]::UTF8)
$text = if ($Arguments) {
    '$ProgressPreference = ''SilentlyContinue''; & {' + "`n$body`n" + '} ' + $Arguments
} else {
    '$ProgressPreference = ''SilentlyContinue''; ' + $body
}

# Порог с запасом ниже 32767: в команду попадают ещё путь к ssh, адрес цели и
# ключи. Точное значение неважно, важно уйти от границы, где ошибка невнятная.
$encodedLength = [Math]::Ceiling([Text.Encoding]::Unicode.GetByteCount($text) / 3) * 4
if ($encodedLength -lt 30000) {
    Invoke-Encoded $text
    exit $LASTEXITCODE
}

$remotePath = Join-Path $RemoteTempDir ("rps-{0}.ps1" -f ([guid]::NewGuid().ToString('N')))
$scpDest = '{0}:{1}' -f $Target, ($remotePath -replace '\\', '/')
& scp @sshArgs $ScriptPath $scpDest
if ($LASTEXITCODE -ne 0) { throw "scp завершился с кодом $LASTEXITCODE" }

# UTF-8 с BOM: PowerShell 5.1 читает файл без BOM как ANSI и ломает кириллицу,
# а scp переносит байты как есть, поэтому кодировку задаёт исходный файл.
$runner = @"
`$ProgressPreference = 'SilentlyContinue'
try { & '$remotePath' $Arguments; `$code = `$LASTEXITCODE }
finally {
    Remove-Item '$remotePath' -Force -ErrorAction SilentlyContinue
    if (Test-Path '$remotePath') { "ВНИМАНИЕ: временный файл не удалён: $remotePath" }
}
exit `$code
"@
Invoke-Encoded $runner
exit $LASTEXITCODE

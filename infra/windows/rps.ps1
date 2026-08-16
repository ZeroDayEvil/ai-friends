<#
    Выполняет локальный .ps1 на тестовом сервере через SSH.

    Содержимое файла уходит как -EncodedCommand (UTF-16LE в base64): иначе кавычки
    и спецсимволы пришлось бы экранировать дважды -- для локального PowerShell
    и для удалённого cmd, который на Windows является оболочкой sshd по умолчанию.
#>
param(
    [Parameter(Mandatory)][string]$ScriptPath,
    [string]$Target = 'root@35.208.225.47',
    [string]$Key = 'C:\remote-access\ssh\winsrv_test_ed25519'
)
# Прогресс-бары приезжают обратно как CLIXML-мусор в stderr, поэтому глушим их.
$text = '$ProgressPreference = ''SilentlyContinue''; ' + [System.IO.File]::ReadAllText($ScriptPath, [System.Text.Encoding]::UTF8)
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($text))
ssh -i $Key -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 `
    $Target "powershell -NoProfile -EncodedCommand $enc"

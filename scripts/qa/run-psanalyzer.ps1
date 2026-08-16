# Локальный прогон той же проверки, что и в CI (.github/workflows/ci.yml).
# CI падает только на Severity=Error, но предупреждения тоже печатаем.

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    Write-Host 'Ставлю PSScriptAnalyzer для текущего пользователя...'
    Install-Module PSScriptAnalyzer -Force -Scope CurrentUser -SkipPublisherCheck
}

Import-Module PSScriptAnalyzer

$issues = Invoke-ScriptAnalyzer -Path $PSScriptRoot\..\.. -Recurse -Severity Error, Warning

if (-not $issues) {
    Write-Host 'Замечаний нет.' -ForegroundColor Green
    exit 0
}

$issues |
    Select-Object Severity, RuleName, ScriptName, Line |
    Sort-Object Severity, ScriptName |
    Format-Table -AutoSize |
    Out-String -Width 200

$errors = @($issues | Where-Object Severity -eq 'Error')
"Ошибок: $($errors.Count), предупреждений: $(@($issues | Where-Object Severity -eq 'Warning').Count)"

if ($errors.Count -gt 0) {
    Write-Host 'CI упадёт на этих ошибках.' -ForegroundColor Red
    exit 1
}

Write-Host 'Ошибок нет: CI по этой проверке пройдёт.' -ForegroundColor Green
exit 0
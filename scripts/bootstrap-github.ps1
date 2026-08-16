<#
.SYNOPSIS
    Выкладывает локальный репозиторий на GitHub и включает защиту main.

.DESCRIPTION
    Пока GitHub CLI не установлен и не авторизован, репозиторий существует
    только локально. Этот скрипт превращает появление доступа в одну команду:
    создаёт приватный репозиторий, выкладывает историю, включает защиту ветки и
    подключает форк electerm-web.

    Требуется gh (https://cli.github.com) и `gh auth login`.

.PARAMETER Owner
    Учётная запись или организация на GitHub.

.PARAMETER Name
    Имя приватного репозитория.

.EXAMPLE
    .\bootstrap-github.ps1 -Owner myorg -Name electerm-platform
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Owner,
    [string]$Name = 'electerm-platform',
    [string]$RepoRoot = 'C:\electerm-platform',
    [switch]$SkipFork
)

$ErrorActionPreference = 'Stop'

function Assert-Command([string]$Cmd, [string]$Hint) {
    if (-not (Get-Command $Cmd -ErrorAction SilentlyContinue)) {
        throw "Не найдено: $Cmd. $Hint"
    }
}

Assert-Command 'git' 'Установите Git.'
Assert-Command 'gh'  'Установите GitHub CLI и выполните gh auth login.'

$slug = "$Owner/$Name"

Write-Host "== Проверка авторизации ==" -ForegroundColor Cyan
gh auth status
if ($LASTEXITCODE -ne 0) { throw 'gh не авторизован: выполните gh auth login.' }

Write-Host "`n== Репозиторий $slug ==" -ForegroundColor Cyan
$exists = $false
gh repo view $slug --json name 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { $exists = $true }

if ($exists) {
    Write-Host 'Уже существует, создание пропущено.'
} else {
    gh repo create $slug --private --description 'Платформа удалённого доступа: инфраструктура как код и форк electerm-web'
    Write-Host 'Создан приватный репозиторий.' -ForegroundColor Green
}

Push-Location $RepoRoot
try {
    if (-not (git remote | Select-String -Pattern '^origin$' -Quiet)) {
        git remote add origin "https://github.com/$slug.git"
    }
    git push -u origin main
    Write-Host 'История выложена.' -ForegroundColor Green

    Write-Host "`n== Защита main ==" -ForegroundColor Cyan
    # Требования: изменения только через пул-реквест с ревью и пройденным CI.
    # Это и есть тот рубеж, из-за которого работу агентов можно проверять
    # чтением диффа: ничего не попадёт в main в обход ревью.
    $protection = @{
        required_status_checks = @{
            strict   = $true
            contexts = @('Политика зависимостей', 'Оболочка', 'PowerShell')
        }
        enforce_admins                 = $false
        required_pull_request_reviews  = @{
            required_approving_review_count = 1
            dismiss_stale_reviews           = $true
            require_code_owner_reviews      = $true
        }
        restrictions                   = $null
        allow_force_pushes             = $false
        allow_deletions                = $false
        required_conversation_resolution = $true
    } | ConvertTo-Json -Depth 6

    $tmp = New-TemporaryFile
    Set-Content -Path $tmp -Value $protection -Encoding utf8
    gh api -X PUT "repos/$slug/branches/main/protection" `
        -H 'Accept: application/vnd.github+json' --input $tmp
    Remove-Item $tmp
    Write-Host 'Защита main включена: PR, ревью владельца кода, зелёный CI.' -ForegroundColor Green
    Write-Host 'enforce_admins оставлен выключенным, чтобы владелец мог починить сломанный CI.'
} finally {
    Pop-Location
}

if (-not $SkipFork) {
    Write-Host "`n== Форк electerm-web ==" -ForegroundColor Cyan
    $forkPath = Join-Path $RepoRoot 'apps\electerm-web'
    if (-not (Test-Path $forkPath)) {
        Write-Host "Нет рабочей копии $forkPath, шаг пропущен." -ForegroundColor Yellow
    } else {
        gh repo fork electerm/electerm-web --org $Owner --clone=false --remote=false 2>$null
        Push-Location $forkPath
        try {
            # upstream остаётся отдельным remote: обновления подтягиваются
            # осознанно, отдельным изменением с ревью.
            if (-not (git remote | Select-String -Pattern '^upstream$' -Quiet)) {
                git remote rename origin upstream
            }
            if (-not (git remote | Select-String -Pattern '^origin$' -Quiet)) {
                git remote add origin "https://github.com/$Owner/electerm-web.git"
            }
            git push -u origin platform
            Write-Host 'Ветка platform выложена в форк.' -ForegroundColor Green
        } finally {
            Pop-Location
        }
    }
}

Write-Host "`nГотово. Дальше: docs/design/runbook.md" -ForegroundColor Green

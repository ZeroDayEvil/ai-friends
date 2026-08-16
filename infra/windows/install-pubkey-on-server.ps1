<#
    Устанавливает публичный ключ winsrv_test_ed25519.pub на целевой Windows-сервер.
    Запускать НА СЕРВЕРЕ с правами администратора.

    Ключевой нюанс Windows: sshd игнорирует %USERPROFILE%\.ssh\authorized_keys,
    если пользователь входит в группу Administrators. Для таких учётных записей
    единственный рабочий путь -- C:\ProgramData\ssh\administrators_authorized_keys,
    причём файл обязан принадлежать Administrators/SYSTEM и не давать прав
    больше никому, иначе sshd молча откажет в доступе по ключу.

    Примеры:
        .\install-pubkey-on-server.ps1 -User Administrator
        .\install-pubkey-on-server.ps1 -User deploy -DisablePasswordAuth
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$User,

    # Отключить вход по паролю. Включайте только после того, как вход
    # по ключу реально проверен во втором, отдельном подключении.
    [switch]$DisablePasswordAuth
)

$ErrorActionPreference = 'Stop'

$PublicKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJxxoZJQdYplXKMLbqO8KPwd2LAki1XF3Gaw3biIn8I9 winsrv-test-2026-08-15'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    throw 'Нужны права администратора: PowerShell -> Run as Administrator.'
}

Write-Host '== 1. OpenSSH Server ==' -ForegroundColor Cyan
$caps = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
if ($caps.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name $caps.Name | Out-Null
    Write-Host 'OpenSSH Server установлен.' -ForegroundColor Green
} else {
    Write-Host 'OpenSSH Server уже установлен.'
}

Set-Service -Name sshd -StartupType Automatic
Start-Service -Name sshd

# Первый запуск sshd создаёт C:\ProgramData\ssh; без него дальше писать некуда.
$sshDataDir = Join-Path $env:ProgramData 'ssh'
if (-not (Test-Path $sshDataDir)) {
    throw "Каталог $sshDataDir не создан -- проверьте, что служба sshd действительно запустилась."
}

Write-Host ''
Write-Host '== 2. Установка ключа ==' -ForegroundColor Cyan

$isTargetAdmin = (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "*\$User" }) -ne $null

if ($isTargetAdmin) {
    $keyFile = Join-Path $sshDataDir 'administrators_authorized_keys'
    Write-Host "$User -- администратор, используется $keyFile" -ForegroundColor Yellow
} else {
    $profileDir = (Get-CimInstance Win32_UserProfile |
        Where-Object { $_.LocalPath -like "*\$User" }).LocalPath
    if (-not $profileDir) {
        throw "Профиль пользователя $User не найден. Войдите под ним хотя бы раз, затем повторите."
    }
    $userSshDir = Join-Path $profileDir '.ssh'
    New-Item -ItemType Directory -Path $userSshDir -Force | Out-Null
    $keyFile = Join-Path $userSshDir 'authorized_keys'
}

$existing = if (Test-Path $keyFile) { Get-Content $keyFile } else { @() }
if ($existing -contains $PublicKey) {
    Write-Host 'Ключ уже присутствует, повторно не добавляется.'
} else {
    # ASCII без BOM: sshd не разбирает authorized_keys в UTF-8 с BOM.
    Set-Content -Path $keyFile -Value (@($existing | Where-Object { $_ }) + $PublicKey) -Encoding ascii
    Write-Host 'Ключ добавлен.' -ForegroundColor Green
}

if ($isTargetAdmin) {
    icacls $keyFile /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
    Write-Host 'Права на administrators_authorized_keys приведены к требованиям sshd.'
}

Write-Host ''
Write-Host '== 3. Брандмауэр ==' -ForegroundColor Cyan
$fwRule = 'OpenSSH Server (sshd) 22'
Get-NetFirewallRule -DisplayName $fwRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName $fwRule -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort 22 -Profile Any | Out-Null
Write-Host 'Порт 22 открыт (Any). Ограничьте -RemoteAddress до mesh-подсети, когда она поднимется.' -ForegroundColor Yellow

if ($DisablePasswordAuth) {
    Write-Host ''
    Write-Host '== 4. Отключение входа по паролю ==' -ForegroundColor Cyan
    $cfg = Join-Path $sshDataDir 'sshd_config'
    Copy-Item $cfg "$cfg.bak" -Force
    $text = (Get-Content $cfg) -replace '^#?\s*PasswordAuthentication\s+.*', 'PasswordAuthentication no' `
                               -replace '^#?\s*PubkeyAuthentication\s+.*', 'PubkeyAuthentication yes'
    Set-Content -Path $cfg -Value $text -Encoding ascii
    Restart-Service sshd
    Write-Host "Пароли отключены, бэкап конфига: $cfg.bak" -ForegroundColor Green
} else {
    Restart-Service sshd
}

Write-Host ''
Write-Host 'Готово. Проверьте вход с рабочей машины:' -ForegroundColor Green
Write-Host "  ssh -i C:\remote-access\ssh\winsrv_test_ed25519 $User@<адрес-сервера>"

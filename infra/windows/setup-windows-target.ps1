<#
.SYNOPSIS
    Подготовка Windows-машины как цели платформы удалённого доступа.

.DESCRIPTION
    Скрипт безопасен по умолчанию: без ключей он только показывает текущее
    состояние и ничего не меняет. Каждое изменяющее действие включается явно,
    потому что часть из них требует перезагрузки или может отрезать доступ.

    Порядок применения на новой машине:
        1. -EnsureSsh            вход по ключу, чтобы был канал управления
        2. -CreateUsers          учётные записи сотрудников
        3. -InstallSessionHost   многосеансовый RDP (перезагрузка)
        4. -MeshOnly             сужение доступа до подсети меша, только когда
                                 меш уже работает

.PARAMETER MeshOnly
    Ограничивает RDP и SSH подсетью WireGuard. Применять только после того, как
    машина реально доступна через меш: иначе управление будет потеряно, и на
    облачной машине останется лишь пересоздание.

.EXAMPLE
    .\setup-windows-target.ps1
    .\setup-windows-target.ps1 -CreateUsers 'ivanov','petrov' -InstallSessionHost
    .\setup-windows-target.ps1 -MeshOnly -MeshSubnet '10.99.0.0/24'
#>
[CmdletBinding()]
param(
    [string[]]$CreateUsers,
    [switch]$EnsureSsh,
    [switch]$InstallSessionHost,
    [switch]$MeshOnly,
    [string]$MeshSubnet = '10.99.0.0/24',
    [switch]$Harden,
    [string]$CredentialOut = 'C:\ProgramData\electerm-platform\new-users.txt'
)

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) { throw 'Требуются права администратора.' }

function Write-Section([string]$Title) { Write-Host "`n== $Title ==" -ForegroundColor Cyan }

function New-StrongPassword {
    # Набор без похожих друг на друга символов: их придётся диктовать людям.
    $set = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%^*-_=+'
    $bytes = [byte[]]::new(20)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    -join ($bytes | ForEach-Object { $set[$_ % $set.Length] })
}

# ---------------------------------------------------------------------------
Write-Section 'Текущее состояние'
$os = Get-CimInstance Win32_OperatingSystem
$isServer = (Get-CimInstance Win32_OperatingSystem).ProductType -ne 1
"ОС            : $($os.Caption) build $($os.BuildNumber)"
"Тип           : $(if ($isServer) { 'серверная' } else { 'клиентская (один активный сеанс)' })"
$sshd = Get-Service sshd -ErrorAction SilentlyContinue
"sshd          : $(if ($sshd) { "$($sshd.Status)" } else { 'не установлен' })"
$rdsState = (Get-WindowsFeature -Name RDS-RD-Server -ErrorAction SilentlyContinue).InstallState
"RD Session Host: $(if ($rdsState) { $rdsState } else { 'недоступно на клиентской ОС' })"
$ts = Get-CimInstance -Namespace root/cimv2/TerminalServices -Class Win32_TerminalServiceSetting -ErrorAction SilentlyContinue
"Режим лицензий : $($ts.LicensingType)  (1 = только администрирование, 2 = per device, 4 = per user)"
"Правила RDP    : $((Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True').Count) включено"

# ---------------------------------------------------------------------------
if ($EnsureSsh) {
    Write-Section 'OpenSSH Server'
    $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
    if ($cap.State -ne 'Installed') {
        Add-WindowsCapability -Online -Name $cap.Name | Out-Null
        Write-Host 'Установлен.' -ForegroundColor Green
    } else { Write-Host 'Уже установлен.' }
    Set-Service sshd -StartupType Automatic
    Start-Service sshd

    # Оболочка по умолчанию -- PowerShell: иначе sshd отдаёт cmd.exe и любая
    # команда требует ручной обёртки.
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
        -Value "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -PropertyType String -Force | Out-Null
    Write-Host 'Ключи добавляются скриптом install-pubkey-on-server.ps1.'
}

# ---------------------------------------------------------------------------
if ($CreateUsers) {
    Write-Section 'Учётные записи'
    $dir = Split-Path $CredentialOut -Parent
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    # Файл с паролями доступен только администраторам и SYSTEM.
    icacls $dir /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null

    $created = foreach ($u in $CreateUsers) {
        if (Get-LocalUser -Name $u -ErrorAction SilentlyContinue) {
            Write-Host "$u уже существует, пропускаю."
            continue
        }
        $pass = New-StrongPassword
        New-LocalUser -Name $u -Password (ConvertTo-SecureString $pass -AsPlainText -Force) `
            -FullName $u -Description 'electerm-platform user' `
            -PasswordNeverExpires:$false -AccountNeverExpires | Out-Null
        Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $u
        Write-Host "$u создан и добавлен в Remote Desktop Users." -ForegroundColor Green
        [pscustomobject]@{ User = $u; Password = $pass }
    }

    if ($created) {
        # Пароли пишутся в защищённый файл, а не в вывод: вывод попадает в
        # журналы и историю сессий.
        $created | ForEach-Object { "$($_.User)`t$($_.Password)" } |
            Set-Content -Path $CredentialOut -Encoding utf8
        Write-Host "Пароли записаны в $CredentialOut (доступ только администраторам)." -ForegroundColor Yellow
        Write-Host 'Передайте их сотрудникам и удалите файл.'
    }
}

# ---------------------------------------------------------------------------
if ($InstallSessionHost) {
    Write-Section 'RD Session Host'
    if (-not $isServer) {
        Write-Host 'Клиентская Windows: роль недоступна, останется один активный сеанс.' -ForegroundColor Yellow
    } elseif ($rdsState -eq 'Installed') {
        Write-Host 'Уже установлена.'
    } else {
        Write-Host 'Внимание: после установки начнётся 120-дневный льготный период.' -ForegroundColor Yellow
        Write-Host 'Без сервера лицензий и CAL по его истечении подключения будут отклоняться.'
        $r = Install-WindowsFeature -Name RDS-RD-Server -IncludeManagementTools
        "Результат: $($r.ExitCode), перезагрузка нужна: $($r.RestartNeeded)"
    }
}

# ---------------------------------------------------------------------------
if ($Harden) {
    Write-Section 'Хардненинг'
    # NLA обязательна: без неё сеанс создаётся до аутентификации, что даёт
    # неаутентифицированному клиенту расходовать ресурсы и упрощает подбор.
    $tsg = Get-CimInstance -Namespace root/cimv2/TerminalServices -Class Win32_TSGeneralSetting
    Invoke-CimMethod -InputObject $tsg -MethodName SetUserAuthenticationRequired -Arguments @{ UserAuthenticationRequired = 1 } | Out-Null
    Invoke-CimMethod -InputObject $tsg -MethodName SetSecurityLayer -Arguments @{ SecurityLayer = 2 } | Out-Null
    'NLA включена, уровень безопасности TLS.'

    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    'SMBv1 отключён.'

    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable | Out-Null
    'Аудит входов включён.'

    # Блокировка после неудачных попыток: RDP открыт по паролю, и это основной
    # вектор подбора.
    net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 | Out-Null
    'Блокировка учётной записи: 10 попыток, 15 минут.'

    # WinRM закрывается снаружи. Управление идёт по SSH, а WinRM на 5985 -- это
    # ещё одна дверь, принимающая пароль, причём на облачных образах Windows её
    # правило нередко открыто для любых адресов. Служба остаётся работать для
    # локальных задач, недоступным становится только сетевой вход.
    $winrmRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and
            ($_.DisplayName -match 'WinRM|Windows Remote Management') }
    if ($winrmRules) {
        $winrmRules | Set-NetFirewallRule -Enabled False
        "WinRM закрыт снаружи: отключено правил $($winrmRules.Count)."
    } else {
        'Открытых правил WinRM не найдено.'
    }
}

# ---------------------------------------------------------------------------
if ($MeshOnly) {
    Write-Section "Ограничение доступа подсетью $MeshSubnet"

    $reachable = Test-NetConnection -ComputerName ($MeshSubnet -replace '\.0/\d+$', '.1') -Port 22 -InformationLevel Quiet -WarningAction SilentlyContinue
    if (-not $reachable) {
        Write-Host 'Концентратор меша недоступен с этой машины.' -ForegroundColor Red
        Write-Host 'Ограничение не применено: иначе доступ к машине будет потерян.'
        Write-Host 'Сначала поднимите узел WireGuard, затем запустите снова.'
    } else {
        foreach ($rule in @(
            @{ Name = 'electerm-platform RDP (mesh)'; Port = 3389 },
            @{ Name = 'electerm-platform SSH (mesh)'; Port = 22 }
        )) {
            Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
            New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow `
                -Protocol TCP -LocalPort $rule.Port -RemoteAddress $MeshSubnet -Profile Any | Out-Null
            Write-Host "$($rule.Name): разрешён только из $MeshSubnet" -ForegroundColor Green
        }
        # Штатные правила Windows для RDP открывают порт всем, поэтому их надо
        # выключить, иначе наше сужение ничего не даёт.
        Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue |
            Where-Object Enabled -eq 'True' |
            Set-NetFirewallRule -Enabled False
        Write-Host 'Штатные правила Remote Desktop отключены.'
    }
}

Write-Host "`nГотово." -ForegroundColor Green

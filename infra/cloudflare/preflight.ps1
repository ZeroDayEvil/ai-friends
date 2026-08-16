<#
.SYNOPSIS
Проверка готовности Cloudflare к настройке. Только чтение.

.DESCRIPTION
Скрипт не меняет ничего ни в Cloudflare, ни в DNS: модуль CfApi отклоняет любой
метод, кроме GET и HEAD, пока предохранитель не снят, а снимает его только
apply.ps1. Задача скрипта -- ответить на один вопрос: можно ли уже запускать
настройку, и если нет, то что именно мешает и на чьей стороне.

Проверяется по порядку: токены, аккаунт, состояние Zero Trust, наличие и статус
зон, делегирование у регистратора, адреса серверов имён, туннель и полнота
самого desired-state.json.

.PARAMETER ConfigPath
Путь к desired-state.json. По умолчанию рядом со скриптом.

.PARAMETER IncludeUnmanaged
Дополнительно показать состояние доменов, которые Cloudflare не обслуживает.

.EXAMPLE
$env:CF_ZONE_TOKEN = '...'; $env:CF_ACCOUNT_TOKEN = '...'
.\preflight.ps1 -IncludeUnmanaged

.OUTPUTS
Код возврата 0 -- к настройке можно приступать, 1 -- есть блокирующие пункты.
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [switch] $IncludeUnmanaged
)

$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'CfApi.psm1') -Force

$script:Rows = @()

function Add-Row {
    <#
    .SYNOPSIS
    Строка отчёта. Ключ -Informational снимает со строки право останавливать
    настройку: находки по доменам вне Cloudflare важны, но перекрывать ими запуск
    настройки Cloudflare неправильно -- это разные контуры.
    #>
    param(
        [Parameter(Mandatory)] [ValidateSet('OK', 'ВНИМАНИЕ', 'БЛОКИРУЕТ', 'ПРОПУСК', 'ДЕФЕКТ')] [string] $Status,
        [Parameter(Mandatory)] [string] $Check,
        [string] $Detail = '',
        [switch] $Informational
    )
    $script:Rows += [pscustomobject]@{
        Status   = $Status
        Check    = $Check
        Detail   = $Detail
        Blocking = (($Status -eq 'БЛОКИРУЕТ') -and (-not $Informational))
    }
    "{0,-10} {1,-34} {2}" -f $Status, $Check, $Detail
}

function Get-Prop {
    # Безопасное чтение необязательного поля из JSON.
    param($Object, [string] $Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
    return $Default
}

$state = Get-CfDesiredState -Path $ConfigPath
$accountId = $state.account_id

"=== Готовность Cloudflare, $(Get-Date -Format 'yyyy-MM-dd HH:mm') ==="
"Аккаунт: $accountId"
"Режим: только чтение (изменения не выполняются)"
""
"{0,-10} {1,-34} {2}" -f 'СТАТУС', 'ПРОВЕРКА', 'ПОДРОБНОСТИ'

# --- 1. Токены -------------------------------------------------------------
$zoneToken = $null
$accountToken = $null
try { $zoneToken = Get-CfToken -Scope Zone } catch { Add-Row -Status 'БЛОКИРУЕТ' -Check 'Токен зон' -Detail $_.Exception.Message }
try { $accountToken = Get-CfToken -Scope Account } catch { Add-Row -Status 'БЛОКИРУЕТ' -Check 'Токен аккаунта' -Detail $_.Exception.Message }

if ($zoneToken) {
    $verify = Test-CfToken -Token $zoneToken -AccountId $accountId
    if ($verify.Ok) { Add-Row -Status 'OK' -Check 'Токен зон' -Detail "действителен, id=$($verify.Result.id)" }
    else { Add-Row -Status 'БЛОКИРУЕТ' -Check 'Токен зон' -Detail (Get-CfErrorText -Response $verify) }
}
if ($accountToken) {
    $verify = Test-CfToken -Token $accountToken -AccountId $accountId
    if ($verify.Ok) { Add-Row -Status 'OK' -Check 'Токен аккаунта' -Detail "действителен, id=$($verify.Result.id)" }
    else { Add-Row -Status 'БЛОКИРУЕТ' -Check 'Токен аккаунта' -Detail (Get-CfErrorText -Response $verify) }
}

if (-not $zoneToken -or -not $accountToken) {
    ""
    'Без обоих токенов дальнейшие проверки невозможны.'
    exit 1
}

# --- 2. Аккаунт ------------------------------------------------------------
$account = Invoke-CfApi -Token $accountToken -Path "/accounts/$accountId"
if ($account.Ok) { Add-Row -Status 'OK' -Check 'Аккаунт доступен' -Detail "$($account.Result.name) (тариф $($account.Result.type))" }
else { Add-Row -Status 'БЛОКИРУЕТ' -Check 'Аккаунт доступен' -Detail (Get-CfErrorText -Response $account) }

# --- 3. Zero Trust ---------------------------------------------------------
$org = Get-CfAccessOrganization -Token $accountToken -AccountId $accountId
if ($org.Enabled) {
    $authDomain = Get-Prop $org.Org 'auth_domain' '(не задан)'
    Add-Row -Status 'OK' -Check 'Zero Trust включён' -Detail "домен команды: $authDomain"
    $configuredTeam = Get-Prop $state.access 'team_name' ''
    if (-not $configuredTeam) {
        Add-Row -Status 'ВНИМАНИЕ' -Check 'team_name в конфиге' -Detail "не заполнен, возьмите из домена команды: $authDomain"
    }
}
elseif ($org.NotEnabled) {
    Add-Row -Status 'БЛОКИРУЕТ' -Check 'Zero Trust включён' -Detail 'нет: включается в панели (Enable Access), через API не создаётся'
}
else {
    Add-Row -Status 'БЛОКИРУЕТ' -Check 'Zero Trust включён' -Detail (Get-CfErrorText -Response $org.Response)
}

# --- 4. Полнота политики доступа ------------------------------------------
$emails = @(Get-Prop $state.access 'allowed_emails' @())
if ($emails.Count -gt 0) {
    Add-Row -Status 'OK' -Check 'Список сотрудников' -Detail "$($emails.Count) адрес(ов)"
}
else {
    Add-Row -Status 'БЛОКИРУЕТ' -Check 'Список сотрудников' -Detail 'allowed_emails пуст: политика без списка открыла бы вход всем'
}

# --- 5. Туннель ------------------------------------------------------------
$tunnelName = $state.tunnel.name
$tunnel = Get-CfTunnel -Token $accountToken -AccountId $accountId -Name $tunnelName
if ($tunnel.Found) {
    Add-Row -Status 'OK' -Check "Туннель '$tunnelName'" -Detail "существует, id=$($tunnel.Tunnel.id), состояние $($tunnel.Tunnel.status)"
}
elseif ($tunnel.Response.Ok) {
    Add-Row -Status 'ВНИМАНИЕ' -Check "Туннель '$tunnelName'" -Detail 'не создан -- создаст apply.ps1'
}
else {
    Add-Row -Status 'БЛОКИРУЕТ' -Check "Туннель '$tunnelName'" -Detail (Get-CfErrorText -Response $tunnel.Response)
}

# --- 6. Зоны ---------------------------------------------------------------
""
'--- Зоны ---'
"{0,-10} {1,-34} {2}" -f 'СТАТУС', 'ПРОВЕРКА', 'ПОДРОБНОСТИ'

foreach ($zoneSpec in $state.zones) {
    $zoneName = $zoneSpec.name

    if (-not $zoneSpec.enabled) {
        $reason = Get-Prop $zoneSpec 'blocked_reason' 'отключена в конфиге'
        Add-Row -Status 'ПРОПУСК' -Check $zoneName -Detail $reason
        continue
    }

    $registry = Get-CfRegistryDelegation -Name $zoneName
    $dns = Get-CfDelegationState -Name $zoneName

    if ($registry.Exists -eq $false) {
        Add-Row -Status 'БЛОКИРУЕТ' -Check $zoneName -Detail 'домен не зарегистрирован (RDAP 404): зону в Cloudflare добавить нельзя, сначала покупка'
        continue
    }
    if ($null -eq $registry.Exists -and -not $dns.Exists) {
        Add-Row -Status 'БЛОКИРУЕТ' -Check $zoneName -Detail 'домена нет в DNS, RDAP недоступен: проверьте регистрацию вручную'
        continue
    }

    # Делегирование считаем по реестру: рекурсивный резолвер отдаёт NS-набор из
    # самой зоны, а он может расходиться с тем, куда реестр направляет запросы.
    if ($registry.NameServers.Count -gt 0) {
        $effectiveNs = $registry.NameServers
        $nsSource = 'реестр'
    }
    else {
        $effectiveNs = $dns.NameServers
        $nsSource = 'DNS'
    }
    $onCloudflare = (@($effectiveNs | Where-Object { $_ -like '*.ns.cloudflare.com' }).Count -gt 0)

    $found = Get-CfZone -Token $zoneToken -Name $zoneName
    if (-not $found.Response.Ok) {
        Add-Row -Status 'БЛОКИРУЕТ' -Check $zoneName -Detail (Get-CfErrorText -Response $found.Response)
        continue
    }

    if (-not $found.Found) {
        Add-Row -Status 'БЛОКИРУЕТ' -Check $zoneName -Detail "зоны нет в аккаунте: владелец добавляет её в панели (Add a site). Серверы имён ($nsSource): $($effectiveNs -join ', ')"
        continue
    }

    $zone = $found.Zone
    $assigned = @(Get-Prop $zone 'name_servers' @())

    if ($zone.status -eq 'active') {
        Add-Row -Status 'OK' -Check "$zoneName (зона)" -Detail "статус active, id=$($zone.id)"
    }
    else {
        Add-Row -Status 'БЛОКИРУЕТ' -Check "$zoneName (зона)" -Detail "статус $($zone.status): нужны серверы имён $($assigned -join ', ')"
    }

    if ($onCloudflare) {
        $missing = @($assigned | Where-Object { $effectiveNs -notcontains $_.ToLower() })
        if ($missing.Count -eq 0 -and $assigned.Count -gt 0) {
            Add-Row -Status 'OK' -Check "$zoneName (делегирование)" -Detail 'серверы имён Cloudflare совпадают с выданными'
        }
        else {
            Add-Row -Status 'ВНИМАНИЕ' -Check "$zoneName (делегирование)" -Detail "в реестре не все серверы Cloudflare: нет $($missing -join ', ')"
        }
    }
    else {
        Add-Row -Status 'БЛОКИРУЕТ' -Check "$zoneName (делегирование)" -Detail "серверы имён ($nsSource): $($effectiveNs -join ', ') -- нужны $($assigned -join ', ')"
    }

    # Расхождение реестра и зоны само по себе не блокирует, но чинить его нужно:
    # такие записи вводят в заблуждение при разборе аварий.
    if ($registry.NameServers.Count -gt 0 -and $dns.NameServers.Count -gt 0) {
        $drift = @($dns.NameServers | Where-Object { $registry.NameServers -notcontains $_ })
        if ($drift.Count -gt 0) {
            Add-Row -Status 'ВНИМАНИЕ' -Check "$zoneName (NS в зоне)" -Detail "в зоне прописаны серверы, которых нет в реестре: $($drift -join ', ')"
        }
    }

    if ($zone.status -eq 'active') {
        foreach ($hostSpec in $zoneSpec.hostnames) {
            $record = Get-CfDnsRecord -Token $zoneToken -ZoneId $zone.id -Name $hostSpec.name -Type 'CNAME'
            if ($record.Found) {
                Add-Row -Status 'OK' -Check "  $($hostSpec.name)" -Detail "CNAME -> $($record.Record.content), проксирование: $($record.Record.proxied)"
            }
            else {
                Add-Row -Status 'ВНИМАНИЕ' -Check "  $($hostSpec.name)" -Detail 'записи нет -- создаст apply.ps1'
            }
        }
    }
}

# --- 7. Домены вне Cloudflare ---------------------------------------------
if ($IncludeUnmanaged) {
    ""
    '--- Домены вне Cloudflare (справочно) ---'
    "{0,-10} {1,-34} {2}" -f 'СТАТУС', 'ПРОВЕРКА', 'ПОДРОБНОСТИ'

    $unmanaged = @()
    $section = Get-Prop $state 'not_managed_here' $null
    foreach ($key in @('direct_to_vps', 'own_nameservers')) {
        foreach ($item in @(Get-Prop $section $key @())) { $unmanaged += $item }
    }

    $expectedIp = Get-Prop $state 'expected_origin_ip' $null

    foreach ($item in $unmanaged) {
        $registry = Get-CfRegistryDelegation -Name $item.name

        if ($registry.Exists -eq $false) {
            Add-Row -Status 'ДЕФЕКТ' -Check $item.name -Detail 'домен не зарегистрирован (RDAP 404)' -Informational
            continue
        }

        # Здоровье проверяем у серверов имён из реестра: именно к ним пойдёт резолвер.
        $health = Get-CfDelegationState -Name $item.name -NameServers $registry.NameServers
        $detail = "серверы имён (реестр): $($registry.NameServers -join ', ')"

        if ($expectedIp) {
            $ips = @()
            try {
                $ips = @(Resolve-DnsName -Name $item.name -Type A -Server 1.1.1.1 -DnsOnly -ErrorAction Stop |
                    Where-Object { $_.QueryType -eq 'A' } | ForEach-Object { $_.IPAddress })
            }
            catch { $ips = @() }
            if ($ips.Count -gt 0) {
                $detail += "; A -> $($ips -join ', ')"
                if ($ips -notcontains $expectedIp) {
                    $detail += " (ожидался $expectedIp)"
                }
            }
        }

        if ($health.BadGlue.Count -gt 0) {
            Add-Row -Status 'ДЕФЕКТ' -Check $item.name -Detail "$detail; дефект серверов имён: $($health.BadGlue -join '; ')" -Informational
        }
        else {
            Add-Row -Status 'OK' -Check $item.name -Detail $detail
        }
    }
}

# --- Итог ------------------------------------------------------------------
$blocking = @($script:Rows | Where-Object { $_.Blocking })
$warnings = @($script:Rows | Where-Object { $_.Status -eq 'ВНИМАНИЕ' })
$defects = @($script:Rows | Where-Object { $_.Status -eq 'ДЕФЕКТ' })

""
"=== Итог: OK $((@($script:Rows | Where-Object { $_.Status -eq 'OK' })).Count), внимание $($warnings.Count), блокирует $($blocking.Count), дефекты вне Cloudflare $($defects.Count) ==="

if ($defects.Count -gt 0) {
    'Дефекты вне контура Cloudflare (настройку не останавливают, но требуют починки у регистратора):'
    foreach ($row in $defects) { "  - $($row.Check): $($row.Detail)" }
    ''
}

if ($blocking.Count -gt 0) {
    'Настройку запускать нельзя. Блокирующие пункты:'
    foreach ($row in $blocking) { "  - $($row.Check): $($row.Detail)" }
    exit 1
}

'Блокирующих пунктов нет: можно запускать apply.ps1 (сначала без -Apply).'
exit 0

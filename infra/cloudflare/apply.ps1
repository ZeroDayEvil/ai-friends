<#
.SYNOPSIS
Настройка Cloudflare по desired-state.json: туннель, записи DNS, режим TLS,
приложение и политика Access.

.DESCRIPTION
По умолчанию скрипт ничего не меняет: он показывает план -- список действий,
вычисленный из фактического состояния аккаунта. Изменения выполняются только с
ключом -Apply, и только если preflight.ps1 не нашёл блокирующих пунктов.

Все шаги идемпотентны: скрипт сначала ищет существующий объект и создаёт его
только при отсутствии, а при расхождении настроек правит их. Повторный запуск на
настроенном аккаунте не создаёт дубликатов и заканчивается пустым планом.

.PARAMETER Apply
Выполнить действия. Без этого ключа -- только план.

.PARAMETER ConfigPath
Путь к desired-state.json.

.PARAMETER OutDir
Куда положить файл учётных данных туннеля для переноса на узел.
По умолчанию каталог скрипта. Файл содержит секрет туннеля и в репозиторий
попадать не должен (см. .gitignore).

.PARAMETER SkipPreflight
Не запускать проверку готовности. Только для отладки: применение без проверки
способно создать записи в зоне, делегирование которой ещё не переключено.

.EXAMPLE
.\apply.ps1
Показать план, ничего не меняя.

.EXAMPLE
.\apply.ps1 -Apply
Применить план после успешной проверки готовности.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch] $Apply,
    [string] $ConfigPath,
    [string] $OutDir,
    [switch] $SkipPreflight
)

$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'CfApi.psm1') -Force

function Get-Prop {
    param($Object, [string] $Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
    return $Default
}

$state = Get-CfDesiredState -Path $ConfigPath
$accountId = $state.account_id
$zoneToken = Get-CfToken -Scope Zone
$accountToken = Get-CfToken -Scope Account

if (-not $OutDir) { $OutDir = $PSScriptRoot }

# --- Проверка готовности ---------------------------------------------------
if (-not $SkipPreflight) {
    '=== Проверка готовности ==='
    $preflight = Join-Path $PSScriptRoot 'preflight.ps1'
    & $preflight -ConfigPath $ConfigPath
    if ($LASTEXITCODE -ne 0) {
        ''
        'Проверка готовности нашла блокирующие пункты. Настройка не запускается.'
        exit 1
    }
    ''
}

# --- Сбор плана ------------------------------------------------------------
# Каждое действие -- описание и замыкание. Замыкания не вызываются, пока не
# передан -Apply, поэтому построение плана остаётся читающей операцией.
$plan = @()

function Add-Action {
    param(
        [Parameter(Mandatory)] [string] $Description,
        [Parameter(Mandatory)] [scriptblock] $Action
    )
    $script:plan += [pscustomobject]@{ Description = $Description; Action = $Action }
}

'=== Вычисление плана ==='

# 1. Туннель
$tunnelName = $state.tunnel.name
$tunnelLookup = Get-CfTunnel -Token $accountToken -AccountId $accountId -Name $tunnelName
if (-not $tunnelLookup.Response.Ok) {
    throw "Не удалось получить список туннелей: $(Get-CfErrorText -Response $tunnelLookup.Response)"
}

$tunnelId = $null
if ($tunnelLookup.Found) {
    $tunnelId = $tunnelLookup.Tunnel.id
    "Туннель '$tunnelName' уже существует (id=$tunnelId) -- создание не требуется."
}
else {
    Add-Action -Description "Создать туннель '$tunnelName'" -Action {
        # Секрет генерируется здесь и больше нигде не хранится: Cloudflare его не
        # отдаёт повторно, поэтому файл учётных данных пишется сразу.
        $secretBytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($secretBytes)
        $rng.Dispose()
        $secret = [Convert]::ToBase64String($secretBytes)

        $body = @{ name = $tunnelName; tunnel_secret = $secret; config_src = 'local' }
        $created = Invoke-CfApi -Token $accountToken -Method Post -Path "/accounts/$accountId/cfd_tunnel" -Body $body
        if (-not $created.Ok) { throw "Туннель не создан: $(Get-CfErrorText -Response $created)" }

        $script:tunnelId = $created.Result.id
        $credentials = @{
            AccountTag   = $accountId
            TunnelID     = $created.Result.id
            TunnelName   = $tunnelName
            TunnelSecret = $secret
        }
        $outFile = Join-Path $OutDir "$($created.Result.id).json"
        $credentials | ConvertTo-Json -Compress | Set-Content -LiteralPath $outFile -Encoding ascii
        "  туннель создан, id=$($created.Result.id)"
        "  файл учётных данных: $outFile -- перенести в /etc/cloudflared/ на узле и удалить локальную копию"
    }
}

# 2. Зоны: записи DNS и настройки TLS
$tunnelTarget = if ($tunnelId) { "$tunnelId.cfargotunnel.com" } else { '<id туннеля>.cfargotunnel.com' }

foreach ($zoneSpec in $state.zones) {
    if (-not $zoneSpec.enabled) {
        "Зона $($zoneSpec.name) пропущена: $(Get-Prop $zoneSpec 'blocked_reason' 'отключена в конфиге')"
        continue
    }

    $lookup = Get-CfZone -Token $zoneToken -Name $zoneSpec.name
    if (-not $lookup.Found) {
        throw "Зоны $($zoneSpec.name) нет в аккаунте. Её добавляет владелец в панели; повторите после появления зоны."
    }
    $zone = $lookup.Zone
    $zoneId = $zone.id

    if ($zone.status -ne 'active') {
        throw "Зона $($zoneSpec.name) в состоянии '$($zone.status)'. Записи в неактивной зоне не отвечают -- сначала переключение серверов имён."
    }

    foreach ($hostSpec in $zoneSpec.hostnames) {
        if (-not $hostSpec.via_tunnel) { continue }
        $hostName = $hostSpec.name
        $record = Get-CfDnsRecord -Token $zoneToken -ZoneId $zoneId -Name $hostName -Type 'CNAME'

        if (-not $record.Found) {
            Add-Action -Description "Создать CNAME $hostName -> $tunnelTarget (проксируемый)" -Action {
                $body = @{
                    type    = 'CNAME'
                    name    = $hostName
                    content = "$($script:tunnelId).cfargotunnel.com"
                    proxied = $true
                    comment = 'Управляется infra/cloudflare/apply.ps1'
                }
                $created = Invoke-CfApi -Token $zoneToken -Method Post -Path "/zones/$zoneId/dns_records" -Body $body
                if (-not $created.Ok) { throw "Запись $hostName не создана: $(Get-CfErrorText -Response $created)" }
                "  создана запись $hostName -> $($created.Result.content)"
            }.GetNewClosure()
        }
        else {
            $current = $record.Record
            $needsFix = ($current.content -ne $tunnelTarget -and $tunnelId) -or (-not $current.proxied)
            if ($needsFix) {
                Add-Action -Description "Исправить CNAME $hostName (сейчас -> $($current.content), проксирование $($current.proxied))" -Action {
                    $body = @{
                        type    = 'CNAME'
                        name    = $hostName
                        content = "$($script:tunnelId).cfargotunnel.com"
                        proxied = $true
                    }
                    $patched = Invoke-CfApi -Token $zoneToken -Method Patch -Path "/zones/$zoneId/dns_records/$($current.id)" -Body $body
                    if (-not $patched.Ok) { throw "Запись $hostName не исправлена: $(Get-CfErrorText -Response $patched)" }
                    "  запись $hostName приведена к плану"
                }.GetNewClosure()
            }
            else {
                "Запись $hostName уже соответствует плану."
            }
        }
    }

    # Настройки зоны сравниваются по одной: PATCH всех настроек сразу не
    # существует, а слепой PATCH каждой перезаписывал бы то, что уже верно.
    $settings = @(
        @{ Key = 'ssl'; Desired = $state.zone_defaults.ssl },
        @{ Key = 'always_use_https'; Desired = $state.zone_defaults.always_use_https },
        @{ Key = 'min_tls_version'; Desired = $state.zone_defaults.min_tls_version }
    )
    foreach ($setting in $settings) {
        $key = $setting.Key
        $desired = $setting.Desired
        $current = Invoke-CfApi -Token $zoneToken -Path "/zones/$zoneId/settings/$key"
        if (-not $current.Ok) {
            "Настройку $key зоны $($zoneSpec.name) прочитать не удалось: $(Get-CfErrorText -Response $current) -- пропущена."
            continue
        }
        if ("$($current.Result.value)" -eq "$desired") {
            "Настройка $key зоны $($zoneSpec.name) уже '$desired'."
            continue
        }
        Add-Action -Description "Зона $($zoneSpec.name): $key '$($current.Result.value)' -> '$desired'" -Action {
            $patched = Invoke-CfApi -Token $zoneToken -Method Patch -Path "/zones/$zoneId/settings/$key" -Body @{ value = $desired }
            if (-not $patched.Ok) { throw "Настройка $key не изменена: $(Get-CfErrorText -Response $patched)" }
            "  $key = $desired"
        }.GetNewClosure()
    }
}

# 3. Приложения и политики Access
$emails = @(Get-Prop $state.access 'allowed_emails' @())
if ($emails.Count -eq 0) {
    throw 'access.allowed_emails пуст. Политика без списка адресов открыла бы вход всем, поэтому приложение не создаётся.'
}

$appsResponse = Invoke-CfApi -Token $accountToken -Path "/accounts/$accountId/access/apps"
if (-not $appsResponse.Ok) {
    throw "Список приложений Access недоступен: $(Get-CfErrorText -Response $appsResponse). Если это not_enabled -- владелец ещё не включил Zero Trust."
}
$existingApps = @($appsResponse.Result)

foreach ($zoneSpec in $state.zones) {
    if (-not $zoneSpec.enabled) { continue }
    foreach ($hostSpec in $zoneSpec.hostnames) {
        if (-not $hostSpec.access) { continue }
        $hostName = $hostSpec.name

        $existing = $existingApps | Where-Object { $_.domain -eq $hostName } | Select-Object -First 1
        if ($existing) {
            "Приложение Access для $hostName уже существует (aud=$($existing.aud))."
            continue
        }

        Add-Action -Description "Создать приложение Access и политику для $hostName" -Action {
            $appBody = @{
                name             = "electerm-platform: $hostName"
                domain           = $hostName
                type             = 'self_hosted'
                session_duration = (Get-Prop $state.access 'session_duration' '24h')
                app_launcher_visible = $false
            }
            $app = Invoke-CfApi -Token $accountToken -Method Post -Path "/accounts/$accountId/access/apps" -Body $appBody
            if (-not $app.Ok) { throw "Приложение для $hostName не создано: $(Get-CfErrorText -Response $app)" }

            $include = foreach ($mail in $emails) { @{ email = @{ email = $mail } } }
            $policyBody = @{
                name       = "Сотрудники: $hostName"
                decision   = 'allow'
                include    = @($include)
                precedence = 1
            }
            if (Get-Prop $state.access 'require_mfa' $false) {
                $policyBody['require'] = @(@{ auth_method = @{ auth_method = 'mfa' } })
            }
            $policy = Invoke-CfApi -Token $accountToken -Method Post -Path "/accounts/$accountId/access/apps/$($app.Result.id)/policies" -Body $policyBody
            if (-not $policy.Ok) { throw "Политика для $hostName не создана: $(Get-CfErrorText -Response $policy)" }

            "  приложение создано, AUD=$($app.Result.aud)"
            "  в .env узла: CF_ACCESS_AUD=$($app.Result.aud)"
        }.GetNewClosure()
    }
}

# --- Вывод плана -----------------------------------------------------------
''
'=== План ==='
if ($plan.Count -eq 0) {
    'Изменений не требуется: фактическое состояние совпадает с желаемым.'
    exit 0
}
for ($i = 0; $i -lt $plan.Count; $i++) {
    "{0,3}. {1}" -f ($i + 1), $plan[$i].Description
}

if (-not $Apply) {
    ''
    "Действий в плане: $($plan.Count). Ничего не изменено."
    'Для применения: .\apply.ps1 -Apply'
    exit 0
}

# --- Применение ------------------------------------------------------------
''
'=== Применение ==='
if (-not $PSCmdlet.ShouldProcess("аккаунт Cloudflare $accountId", "выполнить $($plan.Count) действий")) {
    'Отменено оператором.'
    exit 0
}

Unlock-CfWriteMode

$failed = 0
for ($i = 0; $i -lt $plan.Count; $i++) {
    $step = $plan[$i]
    "{0,3}. {1}" -f ($i + 1), $step.Description
    try {
        & $step.Action
    }
    catch {
        $failed++
        "     ОШИБКА: $($_.Exception.Message)"
    }
}

''
if ($failed -gt 0) {
    "Выполнено с ошибками: $failed из $($plan.Count). Повторный запуск безопасен -- он пересчитает план по фактическому состоянию."
    exit 1
}

"Выполнено действий: $($plan.Count)."
'Дальше: перенести файл учётных данных туннеля на узел, заполнить CF_ACCESS_AUD и CF_ACCESS_TEAM_DOMAIN в .env, см. docs/design/runbook.md.'
exit 0

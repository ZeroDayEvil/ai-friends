# Общий слой доступа к API Cloudflare для preflight.ps1 и apply.ps1.
# Совместим с Windows PowerShell 5.1: без тернарных операторов и без -AsHashtable.

Set-StrictMode -Version Latest

$script:CfApiBase = 'https://api.cloudflare.com/client/v4'

# Предохранитель от записи. Модуль по умолчанию умеет только читать: любой метод,
# кроме GET и HEAD, отклоняется до отправки запроса. Снять предохранитель может
# только apply.ps1 вызовом Unlock-CfWriteMode. Смысл не в удобстве, а в том, что
# ошибка в коде проверки состояния физически не способна ничего изменить в аккаунте.
$script:CfWriteUnlocked = $false

function Unlock-CfWriteMode {
    <#
    .SYNOPSIS
    Разрешает изменяющие запросы в текущем процессе.
    .DESCRIPTION
    Вызывается только из apply.ps1 после подтверждения оператором. Обратной
    функции нет намеренно: снятие предохранителя действует до конца процесса,
    а не переключается туда-обратно в середине работы.
    #>
    [CmdletBinding()]
    param()
    $script:CfWriteUnlocked = $true
    Write-Verbose 'Изменяющие запросы разрешены.'
}

function Test-CfWriteMode {
    <#
    .SYNOPSIS
    Возвращает $true, если изменяющие запросы разрешены.
    #>
    [CmdletBinding()]
    param()
    return $script:CfWriteUnlocked
}

function Get-CfDesiredState {
    <#
    .SYNOPSIS
    Читает desired-state.json.
    #>
    [CmdletBinding()]
    param(
        [string] $Path
    )
    if (-not $Path) {
        $Path = Join-Path $PSScriptRoot 'desired-state.json'
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Не найден файл желаемого состояния: $Path"
    }
    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Get-CfToken {
    <#
    .SYNOPSIS
    Достаёт токен из переменной окружения.
    .DESCRIPTION
    Область Zone -- токен с правами DNS, Zone Settings, SSL внутри зон аккаунта.
    Область Account -- токен с правами Cloudflare Tunnel и Zero Trust Access.
    Разделение не наше изобретение: права на туннель существуют только на уровне
    аккаунта, а права на DNS -- только на уровне зоны, одним токеном обе задачи
    не закрываются без выдачи лишнего.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Zone', 'Account')]
        [string] $Scope
    )

    $names = @{
        Zone    = 'CF_ZONE_TOKEN'
        Account = 'CF_ACCOUNT_TOKEN'
    }
    $varName = $names[$Scope]
    $value = [Environment]::GetEnvironmentVariable($varName)
    if (-not $value) {
        throw "Не задана переменная окружения $varName (токен области $Scope)."
    }
    return $value
}

function Invoke-CfApi {
    <#
    .SYNOPSIS
    Запрос к API Cloudflare с разбором ошибок и повтором при 429 и 5xx.
    .OUTPUTS
    Объект с полями Ok, Result, ResultInfo, StatusCode, Errors.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Token,

        [Parameter(Mandatory)]
        [string] $Path,

        [ValidateSet('Get', 'Head', 'Post', 'Put', 'Patch', 'Delete')]
        [string] $Method = 'Get',

        [object] $Body,

        [int] $MaxAttempts = 3
    )

    if ($Method -notin @('Get', 'Head') -and -not $script:CfWriteUnlocked) {
        throw "Запрос $Method $Path отклонён: модуль работает в режиме только чтения. Изменения выполняет apply.ps1 после явного подтверждения."
    }

    $uri = $script:CfApiBase + $Path
    $headers = @{
        Authorization = "Bearer $Token"
        'Content-Type' = 'application/json'
    }

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $params = @{
                Uri             = $uri
                Method          = $Method
                Headers         = $headers
                UseBasicParsing = $true
                ErrorAction     = 'Stop'
            }
            if ($null -ne $Body) {
                $params['Body'] = ($Body | ConvertTo-Json -Depth 10 -Compress)
            }
            $response = Invoke-RestMethod @params

            $resultInfo = $null
            if ($response.PSObject.Properties.Name -contains 'result_info') {
                $resultInfo = $response.result_info
            }
            return [pscustomobject]@{
                Ok         = $true
                Result     = $response.result
                ResultInfo = $resultInfo
                StatusCode = 200
                Errors     = @()
            }
        }
        catch {
            $status = 0
            if ($_.Exception.PSObject.Properties.Name -contains 'Response' -and $_.Exception.Response) {
                $status = [int] $_.Exception.Response.StatusCode
            }

            $cfErrors = @()
            $bodyText = ''
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $bodyText = $reader.ReadToEnd()
                $reader.Dispose()
                $parsed = $bodyText | ConvertFrom-Json
                foreach ($e in $parsed.errors) {
                    $cfErrors += [pscustomobject]@{ Code = $e.code; Message = $e.message }
                }
            }
            catch {
                $cfErrors += [pscustomobject]@{ Code = 0; Message = $_.Exception.Message }
            }

            $retryable = ($status -eq 429 -or ($status -ge 500 -and $status -le 599))
            if ($retryable -and $attempt -lt $MaxAttempts) {
                $delay = [Math]::Pow(2, $attempt)
                Write-Verbose "HTTP $status по $Path, повтор через $delay с (попытка $attempt из $MaxAttempts)."
                Start-Sleep -Seconds $delay
                continue
            }

            return [pscustomobject]@{
                Ok         = $false
                Result     = $null
                ResultInfo = $null
                StatusCode = $status
                Errors     = $cfErrors
            }
        }
    }
}

function Get-CfErrorText {
    <#
    .SYNOPSIS
    Сводит ошибки ответа в одну строку для отчёта.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Response
    )
    if (-not $Response.Errors -or $Response.Errors.Count -eq 0) {
        return "HTTP $($Response.StatusCode)"
    }
    $parts = foreach ($e in $Response.Errors) { "$($e.Code): $($e.Message)" }
    return "HTTP $($Response.StatusCode) -- " + ($parts -join '; ')
}

function Test-CfToken {
    <#
    .SYNOPSIS
    Проверяет токен эндпоинтом уровня аккаунта.
    .DESCRIPTION
    Именно /accounts/<id>/tokens/verify, а не /user/tokens/verify: оба наших
    токена привязаны к аккаунту, и на пользовательском эндпоинте они законно
    отвечают 401 "Invalid API Token". Проверено 16.08.2026: 401 там не означает
    неработающий токен, и путать эти два случая нельзя.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $AccountId
    )
    return (Invoke-CfApi -Token $Token -Path "/accounts/$AccountId/tokens/verify")
}

function Get-CfZone {
    <#
    .SYNOPSIS
    Ищет зону по имени. Возвращает $null, если зоны нет.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $Name
    )
    $response = Invoke-CfApi -Token $Token -Path "/zones?name=$Name"
    if (-not $response.Ok) {
        return [pscustomobject]@{ Found = $false; Zone = $null; Response = $response }
    }
    $zone = $null
    if (@($response.Result).Count -gt 0) {
        $zone = @($response.Result)[0]
    }
    return [pscustomobject]@{ Found = ($null -ne $zone); Zone = $zone; Response = $response }
}

function Get-CfTunnel {
    <#
    .SYNOPSIS
    Ищет неудалённый туннель по имени.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $AccountId,
        [Parameter(Mandatory)] [string] $Name
    )
    $response = Invoke-CfApi -Token $Token -Path "/accounts/$AccountId/cfd_tunnel?is_deleted=false&name=$Name"
    if (-not $response.Ok) {
        return [pscustomobject]@{ Found = $false; Tunnel = $null; Response = $response }
    }
    $tunnel = $null
    foreach ($t in @($response.Result)) {
        if ($t.name -eq $Name) { $tunnel = $t; break }
    }
    return [pscustomobject]@{ Found = ($null -ne $tunnel); Tunnel = $tunnel; Response = $response }
}

function Get-CfAccessOrganization {
    <#
    .SYNOPSIS
    Состояние Zero Trust в аккаунте.
    .DESCRIPTION
    Если Zero Trust не включён, API отвечает 403 с кодом 9999 и текстом
    access.api.error.not_enabled. Через API это не обходится: организация
    создаётся в панели, потому что при её создании выбирается тариф.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $AccountId
    )
    $response = Invoke-CfApi -Token $Token -Path "/accounts/$AccountId/access/organizations"
    $notEnabled = $false
    foreach ($e in $response.Errors) {
        if ("$($e.Message)" -match 'not_enabled') { $notEnabled = $true }
    }
    return [pscustomobject]@{
        Enabled    = $response.Ok
        NotEnabled = $notEnabled
        Org        = $response.Result
        Response   = $response
    }
}

function Get-CfDnsRecord {
    <#
    .SYNOPSIS
    Ищет запись DNS в зоне по имени и типу.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $ZoneId,
        [Parameter(Mandatory)] [string] $Name,
        [string] $Type = 'CNAME'
    )
    $response = Invoke-CfApi -Token $Token -Path "/zones/$ZoneId/dns_records?name=$Name&type=$Type"
    if (-not $response.Ok) {
        return [pscustomobject]@{ Found = $false; Record = $null; Response = $response }
    }
    $record = $null
    if (@($response.Result).Count -gt 0) {
        $record = @($response.Result)[0]
    }
    return [pscustomobject]@{ Found = ($null -ne $record); Record = $record; Response = $response }
}

function Get-CfRegistryDelegation {
    <#
    .SYNOPSIS
    Делегирование по данным реестра через RDAP: зарегистрирован ли домен, у какого
    регистратора, какие серверы имён записаны в реестре.
    .DESCRIPTION
    Нужно отдельно от DNS, потому что рекурсивный резолвер отдаёт NS-набор из самой
    зоны, а он может расходиться с реестром. На mql5.ink это ровно так: в зоне
    прописаны ns1/ns2.example.com, а делегирование в реестре -- на
    ns1/ns2.hydradns.click. Решение "переключены ли серверы имён на Cloudflare"
    принимается по реестру, потому что резолверы идут именно по нему.
    Ещё RDAP отличает незарегистрированный домен (404) от зарегистрированного без
    записей, чего NXDOMAIN не различает.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [int] $TimeoutSec = 20
    )

    $result = [pscustomobject]@{
        Name        = $Name
        Queried     = $false
        Exists      = $null
        Registrar   = $null
        NameServers = @()
        Expiration  = $null
        Error       = $null
    }

    try {
        $rdap = Invoke-RestMethod -Uri "https://rdap.org/domain/$Name" `
            -Headers @{ Accept = 'application/rdap+json' } `
            -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop

        $result.Queried = $true
        $result.Exists = $true

        if ($rdap.PSObject.Properties.Name -contains 'nameservers') {
            $result.NameServers = @($rdap.nameservers |
                ForEach-Object { "$($_.ldhName)".ToLower() } |
                Sort-Object -Unique)
        }
        if ($rdap.PSObject.Properties.Name -contains 'events') {
            $expiration = $rdap.events | Where-Object { $_.eventAction -eq 'expiration' } | Select-Object -First 1
            if ($expiration) { $result.Expiration = $expiration.eventDate }
        }
        if ($rdap.PSObject.Properties.Name -contains 'entities') {
            $registrar = $rdap.entities | Where-Object { $_.roles -contains 'registrar' } | Select-Object -First 1
            if ($registrar -and $registrar.PSObject.Properties.Name -contains 'vcardArray') {
                $fn = $registrar.vcardArray[1] | Where-Object { $_[0] -eq 'fn' } | Select-Object -First 1
                if ($fn) { $result.Registrar = $fn[3] }
            }
        }
    }
    catch {
        $status = 0
        if ($_.Exception.PSObject.Properties.Name -contains 'Response' -and $_.Exception.Response) {
            $status = [int] $_.Exception.Response.StatusCode
        }
        if ($status -eq 404) {
            $result.Queried = $true
            $result.Exists = $false
        }
        else {
            # RDAP отвечает не для всех зон и ограничивает частоту запросов.
            # Недоступность RDAP -- не вывод о домене, поэтому Exists остаётся $null,
            # а вызывающая сторона откатывается на данные DNS.
            $result.Error = "RDAP недоступен (HTTP $status): $($_.Exception.Message)"
        }
    }

    return $result
}

function Get-CfDelegationState {
    <#
    .SYNOPSIS
    Делегирование домена по публичному DNS: есть ли домен, какие серверы имён,
    на какие адреса они указывают.
    .DESCRIPTION
    Читающая проверка вне Cloudflare. Нужна потому, что зона в Cloudflare может
    быть создана, а делегирование у регистратора -- нет, и наоборот: адреса
    серверов имён могут указывать в никуда. Отдельно ловим loopback и приватные
    адреса в glue: такой сервер имён недоступен из интернета, и половина запросов
    к домену просто теряется.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [string] $Resolver = '1.1.1.1',
        # Проверить адреса заданных серверов имён вместо тех, что отдаёт зона.
        # Используется, когда список берётся из реестра.
        [string[]] $NameServers
    )

    $exists = $true

    # Локальная переменная называется $servers, а не $nameServers: имена
    # переменных в PowerShell регистронезависимы, поэтому $nameServers -- это тот
    # же самый $NameServers, и присваивание затирало бы переданный параметр.
    if ($NameServers) {
        $servers = @($NameServers | ForEach-Object { "$_".ToLower() } | Sort-Object -Unique)
    }
    else {
        $servers = @()
        try {
            $ns = Resolve-DnsName -Name $Name -Type NS -Server $Resolver -DnsOnly -ErrorAction Stop |
                Where-Object { $_.QueryType -eq 'NS' }
            $servers = @($ns | ForEach-Object { "$($_.NameHost)".ToLower() } | Sort-Object -Unique)
        }
        catch {
            if ("$($_.Exception.Message)" -match 'does not exist') { $exists = $false }
        }
    }

    $addresses = @()
    $badGlue = @()
    foreach ($server in $servers) {
        $ips = @()
        $resolveFailed = $false
        try {
            $ips = @(Resolve-DnsName -Name $server -Type A -Server $Resolver -DnsOnly -ErrorAction Stop |
                Where-Object { $_.QueryType -eq 'A' } | ForEach-Object { $_.IPAddress })
        }
        catch {
            $resolveFailed = $true
            $badGlue += "$server -- адрес не разрешается"
        }
        foreach ($ip in $ips) {
            $addresses += [pscustomobject]@{ Server = $server; Address = $ip }
            # Сервер имён с адресом из приватного диапазона или loopback недоступен
            # снаружи. Делегирование на него теряет часть запросов: резолвер выбирает
            # серверы по очереди, и попадание на такой сервер заканчивается отказом.
            if ($ip -match '^127\.' -or $ip -match '^10\.' -or $ip -match '^192\.168\.' -or $ip -match '^169\.254\.' -or $ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.') {
                $badGlue += "$server -> $ip (адрес недоступен из интернета)"
            }
        }
        if ($ips.Count -eq 0 -and -not $resolveFailed) {
            $badGlue += "$server -- нет записи A"
        }
    }

    return [pscustomobject]@{
        Name        = $Name
        Exists      = $exists
        NameServers = $servers
        Addresses   = $addresses
        BadGlue     = $badGlue
        OnCloudflare = (@($servers | Where-Object { $_ -like '*.ns.cloudflare.com' }).Count -gt 0)
    }
}

Export-ModuleMember -Function @(
    'Unlock-CfWriteMode',
    'Test-CfWriteMode',
    'Get-CfDesiredState',
    'Get-CfToken',
    'Invoke-CfApi',
    'Get-CfErrorText',
    'Test-CfToken',
    'Get-CfZone',
    'Get-CfTunnel',
    'Get-CfAccessOrganization',
    'Get-CfDnsRecord',
    'Get-CfDelegationState',
    'Get-CfRegistryDelegation'
)

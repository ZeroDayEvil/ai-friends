<#
.SYNOPSIS
    Приёмочная проверка Windows-цели платформы удалённого доступа.

.DESCRIPTION
    Скрипт только читает состояние машины и ничего не меняет. Для каждого пункта
    печатается PASS/FAIL/WARN/INFO, ожидаемое значение (по docs/design/environments.md
    и infra/windows/setup-windows-target.ps1) и фактическое.

    Запуск на целевой машине через обёртку:
        powershell -ExecutionPolicy Bypass -File infra\windows\rps.ps1 `
            -ScriptPath scripts\qa\check-target.ps1

    Код возврата: 0 — все обязательные проверки прошли, 1 — есть хотя бы один FAIL.
    Это позволяет использовать скрипт как приёмочные ворота в CI.

.NOTES
    В скрипте намеренно нет блока param(): rps.ps1 передаёт содержимое файла как
    -EncodedCommand, добавляя перед ним присваивание $ProgressPreference, а param
    обязан быть первым оператором. Настройки задаются переменными ниже.

    Требуются права администратора: без них недоступны sshd -T, ACL файла ключей
    и часть настроек Terminal Services.
#>

# --- настройки --------------------------------------------------------------
$AuthKeysPath = "$env:ProgramData\ssh\administrators_authorized_keys"
$SshdConfigPath = "$env:ProgramData\ssh\sshd_config"
$WatchedPorts = @('22', '3389')
# Порты, которые слушаются в системе, но снаружи не нужны: если брандмауэр их
# пропускает, поверхность атаки шире заявленной.
$ShouldBeClosedPorts = @('135', '139', '445', '5985', '5986', '47001')
# Ожидания из environments.md: значения, которые платформа заявляет настроенными.
$ExpectedSshDirectives = [ordered]@{
    'passwordauthentication' = 'no'
    'pubkeyauthentication'   = 'yes'
    'maxauthtries'           = '3'
    'logingracetime'         = '30'
}

# --- инициализация ----------------------------------------------------------
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

$Checks = New-Object System.Collections.ArrayList

function Add-Check {
    param(
        [string]$Id,
        [string]$Name,
        [string]$Status,
        [string]$Expected = '',
        [string]$Actual = '',
        [string]$Note = ''
    )
    $null = $Checks.Add([pscustomobject]@{
            Id       = $Id
            Name     = $Name
            Status   = $Status
            Expected = $Expected
            Actual   = $Actual
            Note     = $Note
        })
}

function Add-CheckError {
    param([string]$Id, [string]$Name, [string]$Expected, $ErrorRecord)
    Add-Check -Id $Id -Name $Name -Status 'BLOCKED' -Expected $Expected `
        -Actual 'проверку выполнить не удалось' -Note $ErrorRecord.Exception.Message
}

function Get-PassFail {
    param([bool]$Ok)
    if ($Ok) { 'PASS' } else { 'FAIL' }
}

# sshd применяет ПЕРВОЕ вхождение параметра и только вне блоков Match, поэтому
# наивный поиск по всему файлу даёт неверный ответ.
function Get-SshdDirective {
    param([string[]]$ConfigLines, [string]$Name)
    foreach ($line in $ConfigLines) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        if ($t -match '^Match\s') { break }
        if ($t -match "^$Name\s+(.+)$") { return $Matches[1].Trim() }
    }
    return $null
}

function Get-SshdMatchBlocks {
    param([string[]]$ConfigLines)
    $blocks = New-Object System.Collections.ArrayList
    $current = $null
    foreach ($line in $ConfigLines) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        if ($t -match '^Match\s+(.+)$') {
            if ($current) { $null = $blocks.Add($current) }
            $current = [pscustomobject]@{ Header = $t; Directives = @() }
        }
        elseif ($current) {
            $current.Directives += $t
        }
    }
    if ($current) { $null = $blocks.Add($current) }
    return $blocks
}

# ===========================================================================
# ОС, время работы, ожидание перезагрузки
# ===========================================================================
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $kind = if ($os.ProductType -eq 1) { 'клиентская (один активный сеанс)' } else { 'серверная' }
    Add-Check -Id 'OS-01' -Name 'Версия и тип ОС' -Status 'INFO' `
        -Expected 'Windows Server 2025 Datacenter, build 26100' `
        -Actual "$($os.Caption), build $($os.BuildNumber).$($os.ServicePackMajorVersion), тип: $kind, имя: $($cs.Name), домен/группа: $($cs.Domain)"

    $boot = $os.LastBootUpTime
    $up = (Get-Date) - $boot
    Add-Check -Id 'OS-02' -Name 'Время работы с последней загрузки' -Status 'INFO' `
        -Actual ("загрузка $($boot.ToString('yyyy-MM-dd HH:mm:ss')), работает {0} д {1} ч {2} мин" -f $up.Days, $up.Hours, $up.Minutes) `
        -Note 'Проверка «после перезагрузки поднимается само» требует управляемого рестарта: см. StartMode служб ниже.'
}
catch { Add-CheckError -Id 'OS-01' -Name 'Версия и тип ОС' -Expected 'Windows Server 2025' -ErrorRecord $_ }

try {
    # Жёсткие признаки: перезагрузка действительно не завершена. Мягкие: система
    # работоспособна, но часть файлов будет заменена при следующей загрузке.
    $hard = New-Object System.Collections.ArrayList
    $soft = New-Object System.Collections.ArrayList
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $null = $hard.Add('Component Based Servicing\RebootPending')
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending') {
        $null = $hard.Add('Component Based Servicing\PackagesPending')
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $null = $hard.Add('WindowsUpdate\RebootRequired')
    }
    $cnKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName'
    $nameNow = (Get-ItemProperty "$cnKey\ActiveComputerName" -Name ComputerName -ErrorAction SilentlyContinue).ComputerName
    $nameNext = (Get-ItemProperty "$cnKey\ComputerName" -Name ComputerName -ErrorAction SilentlyContinue).ComputerName
    if ($nameNow -and $nameNext -and ($nameNow -ne $nameNext)) {
        $null = $hard.Add("переименование машины: $nameNow -> $nameNext")
    }
    $pfro = @((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)
    $pfro = @($pfro | Where-Object { $_ -and $_.Trim() -ne '' })
    if ($pfro.Count -gt 0) { $null = $soft.Add("PendingFileRenameOperations: $($pfro.Count) записей") }

    $status = 'PASS'
    $actual = 'перезагрузка не требуется'
    if ($hard.Count -gt 0) {
        $status = 'FAIL'
        $actual = 'требуется: ' + ($hard -join '; ')
        if ($soft.Count -gt 0) { $actual += '; дополнительно ' + ($soft -join '; ') }
    }
    elseif ($soft.Count -gt 0) {
        $status = 'WARN'
        $actual = 'жёстких признаков нет; отложенные операции с файлами: ' + ($soft -join '; ')
    }
    $sample = ''
    if ($pfro.Count -gt 0) {
        $sample = 'первые записи: ' + ((@($pfro | Select-Object -First 4) | ForEach-Object { $_ -replace '^\\\?\?\\', '' }) -join ' | ')
    }
    Add-Check -Id 'OS-03' -Name 'Ожидается ли перезагрузка' -Status $status `
        -Expected 'нет незавершённых установок обновлений и компонентов' -Actual $actual `
        -Note $sample
}
catch { Add-CheckError -Id 'OS-03' -Name 'Ожидается ли перезагрузка' -Expected 'перезагрузка не требуется' -ErrorRecord $_ }

# Перезагрузка меняет состояние узла и может отрезать доступ, поэтому регресс
# «после рестарта поднимается само» не выполняется автоматически. Здесь
# фиксируется только косвенное свидетельство: режимы запуска нужных служб.
Add-Check -Id 'OS-04' -Name 'Регресс: после перезагрузки узел поднимается сам' -Status 'BLOCKED' `
    -Expected 'sshd и слушатель RDP доступны без ручных действий после рестарта' `
    -Actual 'проверка требует управляемой перезагрузки и согласия владельца, скрипт её не выполняет' `
    -Note 'Косвенные свидетельства: SSH-02 (StartMode службы sshd) и RDP-04 (TermService).'

# ===========================================================================
# Служба sshd
# ===========================================================================
try {
    $sshd = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
    if ($null -eq $sshd) {
        Add-Check -Id 'SSH-01' -Name 'Служба sshd запущена' -Status 'FAIL' `
            -Expected 'State=Running' -Actual 'служба sshd не установлена'
        Add-Check -Id 'SSH-02' -Name 'Автозапуск sshd' -Status 'FAIL' `
            -Expected 'StartMode=Auto' -Actual 'служба sshd не установлена'
    }
    else {
        Add-Check -Id 'SSH-01' -Name 'Служба sshd запущена' -Status (Get-PassFail ($sshd.State -eq 'Running')) `
            -Expected 'State=Running' -Actual "State=$($sshd.State), Status=$($sshd.Status), PID=$($sshd.ProcessId)"
        Add-Check -Id 'SSH-02' -Name 'Автозапуск sshd' -Status (Get-PassFail ($sshd.StartMode -eq 'Auto')) `
            -Expected 'StartMode=Auto' -Actual "StartMode=$($sshd.StartMode), DelayedAutoStart=$($sshd.DelayedAutoStart), запуск от $($sshd.StartName)" `
            -Note 'Ручной запуск после перезагрузки — дефект автоматизации.'
    }
}
catch { Add-CheckError -Id 'SSH-01' -Name 'Служба sshd' -Expected 'State=Running, StartMode=Auto' -ErrorRecord $_ }

# ===========================================================================
# Действующая конфигурация sshd
# ===========================================================================
$effective = @{}
$effectiveSource = ''
try {
    $sshdExe = $null
    foreach ($p in @("$env:SystemRoot\System32\OpenSSH\sshd.exe", "$env:ProgramFiles\OpenSSH\sshd.exe")) {
        if (Test-Path $p) { $sshdExe = $p; break }
    }
    if ($sshdExe) {
        # sshd -T печатает действующие директивы с учётом порядка и значений по
        # умолчанию: это надёжнее, чем читать файл глазами.
        $dump = & $sshdExe -T 2>&1 | ForEach-Object { "$_" }
        foreach ($line in $dump) {
            if ($line -match '^([A-Za-z]+)\s+(.*)$') {
                $k = $Matches[1].ToLower()
                $v = $Matches[2].Trim()
                if ($effective.ContainsKey($k)) { $effective[$k] = $effective[$k] + '; ' + $v } else { $effective[$k] = $v }
            }
        }
        if ($effective.Count -gt 0) { $effectiveSource = "sshd -T ($sshdExe)" }
    }
}
catch { $effective = @{} }

$cfgLines = @()
try { $cfgLines = Get-Content $SshdConfigPath -ErrorAction Stop } catch { $cfgLines = @() }
if ($effective.Count -eq 0 -and $cfgLines.Count -gt 0) {
    $effectiveSource = "разбор $SshdConfigPath (первое вхождение вне блоков Match)"
    foreach ($k in $ExpectedSshDirectives.Keys) {
        $v = Get-SshdDirective -ConfigLines $cfgLines -Name $k
        if ($v) { $effective[$k] = $v.ToLower() }
    }
}

$idMap = [ordered]@{
    'passwordauthentication' = @('SSH-03', 'PasswordAuthentication')
    'pubkeyauthentication'   = @('SSH-04', 'PubkeyAuthentication')
    'maxauthtries'           = @('SSH-05', 'MaxAuthTries')
    'logingracetime'         = @('SSH-06', 'LoginGraceTime')
}
foreach ($key in $idMap.Keys) {
    $id = $idMap[$key][0]
    $label = $idMap[$key][1]
    $want = $ExpectedSshDirectives[$key]
    $got = $effective[$key]
    $fileValue = Get-SshdDirective -ConfigLines $cfgLines -Name $key
    if ($null -eq $got) {
        Add-Check -Id $id -Name "sshd: $label" -Status 'BLOCKED' -Expected "$label $want" `
            -Actual 'значение не определено' -Note "источник: $effectiveSource"
    }
    else {
        $ok = ($got.ToLower() -eq $want.ToLower())
        $note = "источник: $effectiveSource"
        if ($fileValue) { $note += "; в файле sshd_config: $label $fileValue" }
        Add-Check -Id $id -Name "sshd: $label" -Status (Get-PassFail $ok) -Expected "$label $want" `
            -Actual "$label $got" -Note $note
    }
}

try {
    $blocks = Get-SshdMatchBlocks -ConfigLines $cfgLines
    # Опасны только директивы, разрешающие иной способ входа. AuthorizedKeysFile в
    # блоке Match Group administrators — штатная конфигурация Windows: именно она
    # и заставляет sshd читать administrators_authorized_keys.
    $risky = New-Object System.Collections.ArrayList
    $benign = New-Object System.Collections.ArrayList
    foreach ($b in $blocks) {
        foreach ($d in $b.Directives) {
            if ($d -match '^(PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|AuthenticationMethods|KbdInteractiveAuthentication|ChallengeResponseAuthentication)\s') {
                $null = $risky.Add("$($b.Header) -> $d")
            }
            elseif ($d -match '^(AuthorizedKeysFile|ForceCommand|ChrootDirectory|PermitTunnel|AllowTcpForwarding)\s') {
                $null = $benign.Add("$($b.Header) -> $d")
            }
        }
    }
    $hdrs = @($blocks | ForEach-Object { $_.Header })
    $actual = if ($blocks.Count -eq 0) { 'блоков Match нет' } else { "блоки Match: $($hdrs -join ' | ')" }
    if ($risky.Count -gt 0) { $actual += '; переопределения способа входа: ' + ($risky -join ' | ') }
    $note = 'Директива внутри Match действует для подходящих подключений и может отменить общий запрет пароля.'
    if ($benign.Count -gt 0) { $note = 'Прочие директивы в Match (штатные): ' + ($benign -join ' | ') + '. ' + $note }
    Add-Check -Id 'SSH-07' -Name 'Блоки Match не переопределяют способ входа' -Status (Get-PassFail ($risky.Count -eq 0)) `
        -Expected 'внутри Match нет PasswordAuthentication / PubkeyAuthentication / PermitEmptyPasswords / AuthenticationMethods' `
        -Actual $actual -Note $note
}
catch { Add-CheckError -Id 'SSH-07' -Name 'Блоки Match' -Expected 'нет переопределений' -ErrorRecord $_ }

# ===========================================================================
# Оболочка sshd по умолчанию
# ===========================================================================
try {
    $shell = (Get-ItemProperty 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -ErrorAction SilentlyContinue).DefaultShell
    if (-not $shell) {
        Add-Check -Id 'SSH-08' -Name 'Оболочка sshd по умолчанию' -Status 'FAIL' `
            -Expected 'powershell.exe' `
            -Actual 'значение DefaultShell не задано, значит sshd отдаёт cmd.exe'
    }
    else {
        $isPwsh = $shell -match '(?i)powershell\.exe$|pwsh\.exe$'
        $exists = Test-Path $shell
        Add-Check -Id 'SSH-08' -Name 'Оболочка sshd по умолчанию' -Status (Get-PassFail ($isPwsh -and $exists)) `
            -Expected 'powershell.exe' `
            -Actual "DefaultShell=$shell, файл существует: $exists"
    }
}
catch { Add-CheckError -Id 'SSH-08' -Name 'Оболочка sshd по умолчанию' -Expected 'powershell.exe' -ErrorRecord $_ }

# ===========================================================================
# Ключи администратора и права на файл
# ===========================================================================
try {
    if (-not (Test-Path $AuthKeysPath)) {
        Add-Check -Id 'SSH-09' -Name 'Файл administrators_authorized_keys' -Status 'FAIL' `
            -Expected "$AuthKeysPath существует и содержит ключи" -Actual 'файл отсутствует'
        Add-Check -Id 'SSH-10' -Name 'Права на administrators_authorized_keys' -Status 'BLOCKED' `
            -Expected 'только Administrators и SYSTEM' -Actual 'файла нет'
    }
    else {
        $item = Get-Item $AuthKeysPath
        $keyLines = @(Get-Content $AuthKeysPath | Where-Object { $_.Trim() -ne '' -and -not $_.Trim().StartsWith('#') })
        $fps = New-Object System.Collections.ArrayList
        $tmp = Join-Path $env:TEMP ("qa-authkeys-{0}.pub" -f ([guid]::NewGuid().ToString('N')))
        foreach ($k in $keyLines) {
            try {
                Set-Content -Path $tmp -Value $k -Encoding ascii
                $fp = & ssh-keygen.exe -l -f $tmp 2>&1 | ForEach-Object { "$_" }
                $null = $fps.Add(($fp -join ' '))
            }
            catch { $null = $fps.Add('отпечаток вычислить не удалось') }
        }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        Add-Check -Id 'SSH-09' -Name 'Файл administrators_authorized_keys' -Status (Get-PassFail ($keyLines.Count -gt 0)) `
            -Expected "$AuthKeysPath существует и содержит ключи" `
            -Actual "ключей: $($keyLines.Count), размер $($item.Length) Б, изменён $($item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" `
            -Note $(if ($fps.Count) { 'отпечатки: ' + ($fps -join ' | ') } else { '' })

        $acl = Get-Acl $AuthKeysPath
        $allowedSids = @('S-1-5-32-544', 'S-1-5-18')  # BUILTIN\Administrators, NT AUTHORITY\SYSTEM
        $extra = New-Object System.Collections.ArrayList
        $shown = New-Object System.Collections.ArrayList
        foreach ($ace in $acl.Access) {
            $sid = $null
            try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
            catch { $sid = "$($ace.IdentityReference)" }
            $null = $shown.Add("$($ace.IdentityReference)=$($ace.FileSystemRights)$(if ($ace.IsInherited) { ' (наследуемая)' })")
            if ($allowedSids -notcontains $sid) { $null = $extra.Add("$($ace.IdentityReference) [$sid] $($ace.FileSystemRights)") }
        }
        $ownerSid = $null
        try { $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { }
        $ownerOk = ($allowedSids -contains $ownerSid)
        $inheritanceOff = $acl.AreAccessRulesProtected
        $aclOk = ($extra.Count -eq 0) -and $ownerOk -and $inheritanceOff
        $note = 'sshd молча отказывает в аутентификации, если на файле ключей есть права кроме Administrators и SYSTEM.'
        if ($extra.Count -gt 0) { $note = 'Лишние субъекты: ' + ($extra -join '; ') + '. ' + $note }
        if (-not $inheritanceOff) { $note = 'Наследование прав не отключено. ' + $note }
        Add-Check -Id 'SSH-10' -Name 'Права на administrators_authorized_keys' -Status (Get-PassFail $aclOk) `
            -Expected 'владелец и все ACE — только Administrators (S-1-5-32-544) или SYSTEM (S-1-5-18), наследование отключено' `
            -Actual "владелец=$($acl.Owner) [$ownerSid], наследование отключено=$inheritanceOff, ACE: $($shown -join '; ')" `
            -Note $note
    }
}
catch { Add-CheckError -Id 'SSH-09' -Name 'Ключи администратора' -Expected 'файл с ключами и строгие права' -ErrorRecord $_ }

# ===========================================================================
# RDP: NLA, уровень безопасности, доступность
# ===========================================================================
try {
    $tsg = Get-CimInstance -Namespace root/cimv2/TerminalServices -Class Win32_TSGeneralSetting -ErrorAction Stop |
        Where-Object { $_.TerminalName -eq 'RDP-Tcp' }
    if (-not $tsg) { $tsg = Get-CimInstance -Namespace root/cimv2/TerminalServices -Class Win32_TSGeneralSetting | Select-Object -First 1 }
    $rdpKey = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $regUa = (Get-ItemProperty $rdpKey -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
    $regSl = (Get-ItemProperty $rdpKey -Name SecurityLayer -ErrorAction SilentlyContinue).SecurityLayer
    $regPort = (Get-ItemProperty $rdpKey -Name PortNumber -ErrorAction SilentlyContinue).PortNumber

    Add-Check -Id 'RDP-01' -Name 'NLA для RDP включена' -Status (Get-PassFail ($tsg.UserAuthenticationRequired -eq 1)) `
        -Expected 'UserAuthenticationRequired=1' `
        -Actual "UserAuthenticationRequired=$($tsg.UserAuthenticationRequired) (реестр UserAuthentication=$regUa)" `
        -Note 'Без NLA сеанс создаётся до аутентификации: неаутентифицированный клиент расходует ресурсы, подбор пароля упрощается.'

    $slNames = @{ 0 = 'RDP Security Layer'; 1 = 'Negotiate'; 2 = 'TLS (SSL)' }
    Add-Check -Id 'RDP-02' -Name 'Уровень безопасности RDP' -Status (Get-PassFail ($tsg.SecurityLayer -eq 2)) `
        -Expected 'SecurityLayer=2 (TLS)' `
        -Actual "SecurityLayer=$($tsg.SecurityLayer) ($($slNames[[int]$tsg.SecurityLayer])), реестр SecurityLayer=$regSl"

    $deny = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
    Add-Check -Id 'RDP-03' -Name 'Подключения RDP разрешены' -Status 'INFO' `
        -Expected 'fDenyTSConnections=0 при работающем RDP' `
        -Actual "fDenyTSConnections=$deny, порт слушателя=$regPort, шифрование=$($tsg.MinEncryptionLevel)"
}
catch { Add-CheckError -Id 'RDP-01' -Name 'Настройки RDP' -Expected 'NLA=1, SecurityLayer=2' -ErrorRecord $_ }

try {
    $ts = Get-CimInstance Win32_Service -Filter "Name='TermService'" -ErrorAction Stop
    Add-Check -Id 'RDP-04' -Name 'Служба TermService' -Status (Get-PassFail ($ts.State -eq 'Running' -and $ts.StartMode -in @('Auto', 'Manual'))) `
        -Expected 'State=Running' `
        -Actual "State=$($ts.State), StartMode=$($ts.StartMode)" `
        -Note 'StartMode=Manual штатен: службу запускает триггер входящего подключения.'
}
catch { Add-CheckError -Id 'RDP-04' -Name 'Служба TermService' -Expected 'State=Running' -ErrorRecord $_ }

# ===========================================================================
# Брандмауэр: входящие правила для наблюдаемых портов
# ===========================================================================
try {
    $portFilters = @{}
    $addrFilters = @{}
    Get-NetFirewallPortFilter -All -ErrorAction Stop | ForEach-Object { $portFilters[$_.InstanceID] = $_ }
    Get-NetFirewallAddressFilter -All -ErrorAction Stop | ForEach-Object { $addrFilters[$_.InstanceID] = $_ }

    $allPorts = @($WatchedPorts) + @($ShouldBeClosedPorts)
    $exact = @{}
    $wild = @{}
    foreach ($port in $allPorts) {
        $exact[$port] = New-Object System.Collections.ArrayList
        $wild[$port] = New-Object System.Collections.ArrayList
    }

    foreach ($rule in Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop) {
        $pf = $portFilters[$rule.InstanceID]
        if (-not $pf) { continue }
        if ($pf.Protocol -notin @('TCP', 'Any')) { continue }
        $af = $addrFilters[$rule.InstanceID]
        $remote = if ($af) { (@($af.RemoteAddress) -join ',') } else { 'н/д' }
        $scope = 'любая программа'
        if ($rule.Program -and $rule.Program -ne 'Any') { $scope = "программа $($rule.Program)" }
        elseif ($rule.Service -and $rule.Service -ne 'Any') { $scope = "служба $($rule.Service)" }

        foreach ($port in $allPorts) {
            $hit = $false
            $wildcard = $false
            foreach ($p in @($pf.LocalPort)) {
                if ($p -eq 'Any') { $hit = $true; $wildcard = $true }
                elseif ($p -eq $port) { $hit = $true }
                elseif ($p -match '^(\d+)-(\d+)$') {
                    if ([int]$port -ge [int]$Matches[1] -and [int]$port -le [int]$Matches[2]) { $hit = $true }
                }
            }
            if (-not $hit) { continue }
            $row = [pscustomobject]@{
                Name      = $rule.DisplayName
                Profile   = "$($rule.Profile)"
                Remote    = $remote
                LocalPort = (@($pf.LocalPort) -join ',')
                Protocol  = $pf.Protocol
                Scope     = $scope
            }
            if ($wildcard) { $null = $wild[$port].Add($row) } else { $null = $exact[$port].Add($row) }
        }
    }

    $fwIds = @{ '22' = 'FW-01'; '3389' = 'FW-02' }
    foreach ($port in $WatchedPorts) {
        $list = $exact[$port]
        $wildList = $wild[$port]
        # Правила с LocalPort=Any перечисляются отдельно: их десятки, они привязаны
        # к программам и службам, и в общем списке они прячут значимые строки.
        $wildAnyProgram = @($wildList | Where-Object { $_.Scope -eq 'любая программа' -and $_.Remote -eq 'Any' })
        $wildNote = "Правил с LocalPort=Any, покрывающих порт: $($wildList.Count)"
        if ($wildAnyProgram.Count -gt 0) {
            $wildNote += '; из них без ограничения по программе и адресу: ' +
                ((@($wildAnyProgram | ForEach-Object { "«$($_.Name)» профиль=$($_.Profile)" })) -join ', ')
        }

        if ($list.Count -eq 0) {
            Add-Check -Id $fwIds[$port] -Name "Правила брандмауэра для входящего $port/TCP" -Status 'FAIL' `
                -Expected "есть включённое разрешающее правило именно для $port/TCP" `
                -Actual 'правил с явным указанием этого порта не найдено' -Note $wildNote
            continue
        }
        $lines = foreach ($r in $list) {
            "«$($r.Name)» профиль=$($r.Profile) порты=$($r.LocalPort)/$($r.Protocol) RemoteAddress=$($r.Remote) область=$($r.Scope)"
        }
        $openToWorld = @($list | Where-Object { $_.Remote -eq 'Any' }).Count -gt 0
        $status = if ($openToWorld) { 'WARN' } else { 'PASS' }
        $note = if ($openToWorld) {
            "Порт $port принимает подключения с любого адреса (RemoteAddress=Any), то есть из интернета. $wildNote"
        }
        else { "Доступ ограничен перечисленными адресами. $wildNote" }
        Add-Check -Id $fwIds[$port] -Name "Правила брандмауэра для входящего $port/TCP" -Status $status `
            -Expected 'разрешено только с доверенных адресов' `
            -Actual ("правил с явным портом: $($list.Count); " + ($lines -join ' || ')) -Note $note
    }

    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    Add-Check -Id 'FW-03' -Name 'Профили брандмауэра включены' -Status (Get-PassFail (@($profiles | Where-Object { -not $_.Enabled }).Count -eq 0)) `
        -Expected 'Domain, Private, Public: Enabled=True, входящие по умолчанию Block' `
        -Actual (($profiles | ForEach-Object { "$($_.Name)=Enabled:$($_.Enabled),Inbound:$($_.DefaultInboundAction),Outbound:$($_.DefaultOutboundAction)" }) -join '; ') `
        -Note 'NotConfigured трактуется как поведение по умолчанию: входящие блокируются, исходящие разрешаются. Ограничения исходящего трафика на этом узле нет.'

    # Отдельно: не пропускает ли брандмауэр порты, которые снаружи не нужны.
    $leaks = New-Object System.Collections.ArrayList
    foreach ($port in $ShouldBeClosedPorts) {
        foreach ($r in $exact[$port]) {
            if ($r.Remote -eq 'Any') {
                $null = $leaks.Add("${port}: «$($r.Name)» профиль=$($r.Profile) RemoteAddress=Any")
            }
        }
    }
    Add-Check -Id 'FW-05' -Name 'Лишние порты не разрешены брандмауэром' -Status (Get-PassFail ($leaks.Count -eq 0)) `
        -Expected ('нет включённых правил, разрешающих с любого адреса порты ' + ($ShouldBeClosedPorts -join ', ')) `
        -Actual $(if ($leaks.Count -eq 0) { 'таких правил нет' } else { $leaks -join ' || ' }) `
        -Note 'Проверяется правило узла, а не доступность снаружи: облачный брандмауэр может закрывать порт независимо. Внешнюю доступность проверяйте с машины оркестратора.'

    $conn = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { "$($_.InterfaceAlias)=$($_.NetworkCategory)" })
    Add-Check -Id 'FW-04' -Name 'Профиль сети на интерфейсах' -Status 'INFO' `
        -Expected 'профиль определяет, какие правила действуют' `
        -Actual $(if ($conn.Count) { $conn -join '; ' } else { 'не определено' }) `
        -Note 'Правило, привязанное только к Private, не действует, если интерфейс отнесён к Public.'
}
catch { Add-CheckError -Id 'FW-01' -Name 'Правила брандмауэра' -Expected 'правила для 22 и 3389' -ErrorRecord $_ }

try {
    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Where-Object { $_.LocalAddress -in @('0.0.0.0', '::') } |
            Sort-Object LocalPort -Unique)
    $rows = foreach ($l in $listen) {
        $pname = try { (Get-Process -Id $l.OwningProcess -ErrorAction Stop).ProcessName } catch { "pid $($l.OwningProcess)" }
        "$($l.LocalPort)/$pname"
    }
    Add-Check -Id 'NET-01' -Name 'Порты, слушающие на всех интерфейсах' -Status 'INFO' `
        -Expected 'по назначению узла ожидаются 22 (sshd) и 3389 (RDP); остальное — поверхность атаки' `
        -Actual ($rows -join ', ') `
        -Note 'Слушатель на 0.0.0.0 доступен снаружи, если его пропускает брандмауэр.'
}
catch { Add-CheckError -Id 'NET-01' -Name 'Слушающие порты' -Expected 'перечень' -ErrorRecord $_ }

# ===========================================================================
# WinRM: второй канал управления, который заявлен не был
# ===========================================================================
try {
    $winrm = Get-CimInstance Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop
    $listeners = @()
    try {
        $raw = & winrm enumerate winrm/config/listener 2>&1 | ForEach-Object { "$_" }
        $listeners = @($raw | Where-Object { $_ -match '^\s*(Transport|Port|ListeningOn)\s*=' } | ForEach-Object { $_.Trim() })
    }
    catch { }
    $state = if ($winrm) { "State=$($winrm.State), StartMode=$($winrm.StartMode)" } else { 'служба отсутствует' }
    $running = $winrm -and $winrm.State -eq 'Running'
    Add-Check -Id 'WRM-01' -Name 'WinRM как дополнительный канал управления' -Status $(if ($running) { 'WARN' } else { 'PASS' }) `
        -Expected 'в environments.md WinRM не заявлен; канал управления — только SSH по ключу' `
        -Actual "$state; слушатели: $(if ($listeners.Count) { ($listeners | Select-Object -First 8) -join ', ' } else { 'не перечислены' })" `
        -Note 'WinRM аутентифицирует по паролю (Negotiate/NTLM), то есть в обход заявленного «входа только по ключу». Если он не нужен, службу и правила брандмауэра следует отключить.'

    if ($running) {
        $auth = @()
        try {
            $auth = @(Get-ChildItem WSMan:\localhost\Service\Auth -ErrorAction Stop | ForEach-Object { "$($_.Name)=$($_.Value)" })
            $unenc = (Get-Item WSMan:\localhost\Service\AllowUnencrypted -ErrorAction SilentlyContinue).Value
            if ($null -ne $unenc) { $auth += "AllowUnencrypted=$unenc" }
        }
        catch { }
        Add-Check -Id 'WRM-02' -Name 'Способы аутентификации WinRM' -Status 'INFO' `
            -Expected 'Basic=false, AllowUnencrypted=false' `
            -Actual $(if ($auth.Count) { $auth -join ', ' } else { 'прочитать не удалось' })
    }
}
catch { Add-CheckError -Id 'WRM-01' -Name 'WinRM' -Expected 'состояние службы' -ErrorRecord $_ }

# ===========================================================================
# SMBv1
# ===========================================================================
try {
    $smb = Get-SmbServerConfiguration -ErrorAction Stop
    Add-Check -Id 'SMB-01' -Name 'SMBv1 (серверная часть) выключен' -Status (Get-PassFail (-not $smb.EnableSMB1Protocol)) `
        -Expected 'EnableSMB1Protocol=False' `
        -Actual "EnableSMB1Protocol=$($smb.EnableSMB1Protocol), EnableSMB2Protocol=$($smb.EnableSMB2Protocol), RequireSecuritySignature=$($smb.RequireSecuritySignature)"
}
catch { Add-CheckError -Id 'SMB-01' -Name 'SMBv1 выключен' -Expected 'EnableSMB1Protocol=False' -ErrorRecord $_ }

try {
    $featureState = 'н/д'
    $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($f) { $featureState = "$($f.State)" }
    $drv = Get-CimInstance Win32_Service -Filter "Name='mrxsmb10'" -ErrorAction SilentlyContinue
    $drvState = if ($drv) { "$($drv.State)/$($drv.StartMode)" } else { 'драйвер отсутствует' }
    Add-Check -Id 'SMB-02' -Name 'Компонент и драйвер SMB1' -Status 'INFO' `
        -Expected 'компонент Disabled, клиентский драйвер не запущен' `
        -Actual "компонент SMB1Protocol=$featureState, драйвер mrxsmb10=$drvState" `
        -Note 'Отключение серверной части не удаляет клиентскую: исходящие подключения по SMBv1 остаются возможны.'
}
catch { Add-CheckError -Id 'SMB-02' -Name 'Компонент SMB1' -Expected 'Disabled' -ErrorRecord $_ }

# ===========================================================================
# Роли RDS и режим лицензирования
# ===========================================================================
try {
    $isServer = (Get-CimInstance Win32_OperatingSystem).ProductType -ne 1
    if (-not $isServer) {
        Add-Check -Id 'RDS-01' -Name 'Установленные роли RDS' -Status 'INFO' `
            -Expected 'на клиентской ОС роли RDS недоступны' `
            -Actual 'клиентская ОС: один активный сеанс, роль RD Session Host невозможна'
    }
    else {
        $feats = Get-WindowsFeature -Name RDS-* -ErrorAction Stop
        $installed = @($feats | Where-Object { $_.InstallState -eq 'Installed' })
        $actual = if ($installed.Count -eq 0) { 'ни одна роль RDS не установлена' }
        else { ($installed | ForEach-Object { "$($_.Name) ($($_.DisplayName))" }) -join '; ' }
        Add-Check -Id 'RDS-01' -Name 'Установленные роли RDS' -Status 'INFO' `
            -Expected 'по environments.md роли RDS не установлены' -Actual $actual `
            -Note ('Состояние всех компонентов RDS-*: ' + (($feats | ForEach-Object { "$($_.Name)=$($_.InstallState)" }) -join ', '))
    }
}
catch { Add-CheckError -Id 'RDS-01' -Name 'Роли RDS' -Expected 'перечень ролей' -ErrorRecord $_ }

try {
    $tss = Get-CimInstance -Namespace root/cimv2/TerminalServices -Class Win32_TerminalServiceSetting -ErrorAction Stop
    $lt = [int]$tss.LicensingType
    $ltNames = @{
        0 = 'Personal Terminal Server'
        1 = 'только удалённое администрирование (максимум 2 сеанса)'
        2 = 'Per Device'
        4 = 'Per User'
        5 = 'не настроено'
    }
    $ltName = if ($ltNames.ContainsKey($lt)) { $ltNames[$lt] } else { 'неизвестное значение' }
    Add-Check -Id 'RDS-02' -Name 'Режим лицензирования Terminal Services' -Status 'INFO' `
        -Expected 'LicensingType=1 (административные сеансы), по environments.md' `
        -Actual "LicensingType=$lt ($ltName), PolicySourceLicensingType=$($tss.PolicySourceLicensingType)" `
        -Note 'При LicensingType=1 многопользовательские сценарии матрицы совместимости ограничены двумя административными сеансами.'
}
catch { Add-CheckError -Id 'RDS-02' -Name 'Режим лицензирования' -Expected 'LicensingType' -ErrorRecord $_ }

# ===========================================================================
# Дополнительный контекст для отчёта
# ===========================================================================
try {
    $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { "$($_.Name) [$($_.ObjectClass)/$($_.PrincipalSource)]" })
    $rdu = @(Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)" })
    Add-Check -Id 'ACC-01' -Name 'Состав групп доступа' -Status 'INFO' `
        -Actual "Administrators: $($admins -join ', '); Remote Desktop Users: $(if ($rdu.Count) { $rdu -join ', ' } else { 'пусто' })"
}
catch { Add-CheckError -Id 'ACC-01' -Name 'Состав групп доступа' -Expected 'перечень' -ErrorRecord $_ }

try {
    $lockout = (net accounts) -join "`n"
    $threshold = if ($lockout -match '(?m)^.*lockout threshold\s*:\s*(\S+)') { $Matches[1] } else { 'н/д' }
    Add-Check -Id 'ACC-02' -Name 'Блокировка при подборе пароля' -Status 'INFO' `
        -Expected 'порог блокировки задан (RDP принимает пароль)' -Actual "lockout threshold=$threshold" `
        -Note 'Порог Never при открытом в интернет 3389 означает неограниченный подбор пароля.'
}
catch { Add-CheckError -Id 'ACC-02' -Name 'Блокировка при подборе пароля' -Expected 'порог блокировки' -ErrorRecord $_ }

try {
    $users = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
            "$($_.Name)=$(if ($_.Enabled) { 'включён' } else { 'отключён' })$(if ($_.PasswordLastSet) { '' } else { ', пароль не задан' })"
        })
    # Встроенный Administrator по умолчанию не блокируется при подборе пароля:
    # это отдельная политика. При 3389, открытом в интернет, разница существенна.
    $allowAdminLockout = 'не определено'
    $sec = Join-Path $env:TEMP ("qa-secpol-{0}.inf" -f ([guid]::NewGuid().ToString('N')))
    try {
        & secedit /export /cfg $sec /areas SECURITYPOLICY /quiet 2>&1 | Out-Null
        if (Test-Path $sec) {
            $line = Get-Content $sec -Encoding Unicode | Where-Object { $_ -match 'AllowAdministratorLockout' }
            if ($line) { $allowAdminLockout = ($line -split '=')[-1].Trim() } else { $allowAdminLockout = 'параметр отсутствует (трактуется как 0)' }
        }
    }
    finally { Remove-Item $sec -Force -ErrorAction SilentlyContinue }

    $adminEnabled = 'н/д'
    $a = Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
    if ($a) { $adminEnabled = if ($a.Enabled) { 'включена' } else { 'отключена' } }
    $risk = ($adminEnabled -eq 'включена') -and ($allowAdminLockout -notmatch '^1$')
    Add-Check -Id 'ACC-04' -Name 'Встроенная учётная запись Administrator и её блокировка' -Status $(if ($risk) { 'WARN' } else { 'PASS' }) `
        -Expected 'Administrator отключена либо AllowAdministratorLockout=1' `
        -Actual "Administrator: $adminEnabled, AllowAdministratorLockout=$allowAdminLockout; локальные учётные записи: $($users -join ', ')" `
        -Note 'Порог блокировки не распространяется на встроенного Administrator, если AllowAdministratorLockout не включён: при 3389 в интернете это неограниченный подбор пароля к этой записи.'
}
catch { Add-CheckError -Id 'ACC-04' -Name 'Встроенная учётная запись Administrator' -Expected 'отключена или блокируется' -ErrorRecord $_ }

try {
    $gce = Get-CimInstance Win32_Service -Filter "Name='GCEAgent'" -ErrorAction SilentlyContinue
    $actual = if ($gce) { "State=$($gce.State), StartMode=$($gce.StartMode)" } else { 'служба отсутствует' }
    Add-Check -Id 'ACC-03' -Name 'Агент GCE (аварийный сброс пароля)' -Status 'INFO' `
        -Expected 'по environments.md служба остановлена, сброс пароля из консоли GCP недоступен' -Actual $actual `
        -Note 'Если агент не работает, при потере ключа единственный путь — пересоздание машины.'
}
catch { Add-CheckError -Id 'ACC-03' -Name 'Агент GCE' -Expected 'состояние службы' -ErrorRecord $_ }

# ===========================================================================
# Вывод
# ===========================================================================
function Write-Wrapped {
    param([string]$Label, [string]$Text)
    if (-not $Text) { return }
    $indent = ' ' * 12
    "$indent$Label $Text"
}

''
'============================================================================'
"  Приёмка Windows-цели: $env:COMPUTERNAME"
"  Запуск: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))  под учётной записью $env:USERDOMAIN\$env:USERNAME"
'============================================================================'
''

foreach ($c in $Checks) {
    "[{0}] {1}  {2}" -f $c.Status.PadRight(7), $c.Id.PadRight(6), $c.Name
    Write-Wrapped -Label 'ожидалось :' -Text $c.Expected
    Write-Wrapped -Label 'фактически:' -Text $c.Actual
    Write-Wrapped -Label 'примечание:' -Text $c.Note
}

$pass = @($Checks | Where-Object { $_.Status -eq 'PASS' }).Count
$fail = @($Checks | Where-Object { $_.Status -eq 'FAIL' }).Count
$warn = @($Checks | Where-Object { $_.Status -eq 'WARN' }).Count
$blocked = @($Checks | Where-Object { $_.Status -eq 'BLOCKED' }).Count
$info = @($Checks | Where-Object { $_.Status -eq 'INFO' }).Count

''
'----------------------------------------------------------------------------'
"ИТОГО: PASS=$pass  FAIL=$fail  WARN=$warn  BLOCKED=$blocked  INFO=$info  (всего $($Checks.Count))"
if ($fail -gt 0) {
    'Провалившиеся проверки: ' + ((@($Checks | Where-Object { $_.Status -eq 'FAIL' }) | ForEach-Object { $_.Id }) -join ', ')
}
'----------------------------------------------------------------------------'

'--- BEGIN JSON ---'
$Checks | ConvertTo-Json -Depth 4 -Compress
'--- END JSON ---'

exit $(if ($fail -gt 0) { 1 } else { 0 })

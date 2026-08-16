# Состояние правил брандмауэра для SSH и профиль сетевого подключения.
# Только чтение.

$ErrorActionPreference = 'Continue'

"=== Профиль сетевых интерфейсов ==="
Get-NetConnectionProfile | ForEach-Object {
    "{0} -> {1}" -f $_.InterfaceAlias, $_.NetworkCategory
}

""
"=== Правила для входящего 22 ==="
Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { ($_ | Get-NetFirewallPortFilter).LocalPort -contains 22 } |
    ForEach-Object {
        $addr = ($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ','
        "{0,-34} профиль={1,-22} адреса={2}" -f $_.DisplayName, $_.Profile, $addr
    }

""
"=== Активные профили брандмауэра ==="
Get-NetFirewallProfile | ForEach-Object {
    "{0,-8} включён={1} политика входящих={2}" -f $_.Name, $_.Enabled, $_.DefaultInboundAction
}

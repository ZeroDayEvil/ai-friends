# Состояние сетевого доступа к WinRM на цели.
# Только чтение: показывает правила и слушающие порты.

$ErrorActionPreference = 'Continue'

"=== Правила брандмауэра для WinRM ==="
Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match 'WinRM|Windows Remote Management' } |
    ForEach-Object {
        $ports = ($_ | Get-NetFirewallPortFilter).LocalPort -join ','
        $addr = ($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ','
        "{0,-6} {1,-9} {2,-10} {3,-14} {4}" -f $_.Enabled, $_.Direction, $ports, $addr, $_.DisplayName
    }

""
"=== Слушающие порты 5985/5986 ==="
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -in 5985, 5986 } |
    ForEach-Object { "порт $($_.LocalPort) слушает на $($_.LocalAddress)" }

""
"=== Служба WinRM ==="
$s = Get-Service WinRM -ErrorAction SilentlyContinue
"статус: $($s.Status), автозапуск: $((Get-CimInstance Win32_Service -Filter "Name='WinRM'").StartMode)"

'=== RDS features ==='
Get-WindowsFeature -Name RDS-*, Remote-Desktop-Services |
    Select-Object Name, InstallState |
    Format-Table -AutoSize | Out-String -Width 100

'=== Terminal services settings ==='
$ts = Get-CimInstance -Namespace root/cimv2/TerminalServices -Class Win32_TerminalServiceSetting
"LicensingType     : $($ts.LicensingType)   (2=PerDevice, 4=PerUser, 5=not configured/remote admin)"
"AllowTSConnections: $($ts.AllowTSConnections)"
$gp = Get-CimInstance -Namespace root/cimv2/TerminalServices -Class Win32_TSGeneralSetting
"SecurityLayer/NLA : $($gp.SecurityLayer) / $($gp.UserAuthenticationRequired)"
"MaxConnections    : $((Get-CimInstance -Namespace root/cimv2/TerminalServices -Class Win32_TerminalServiceSetting).MaxConnectionAllowed)"

'=== Local accounts ==='
Get-LocalUser | Select-Object Name, Enabled, LastLogon |
    Format-Table -AutoSize | Out-String -Width 100
"RDU group members : $((Get-LocalGroupMember 'Remote Desktop Users' -ErrorAction SilentlyContinue | ForEach-Object Name) -join ', ')"

'=== Network ==='
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' } |
    Select-Object InterfaceAlias, IPAddress, PrefixLength |
    Format-Table -AutoSize | Out-String -Width 100
"Gateway  : $((Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop)"
"DNS      : $((Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses | Select-Object -First 1).ServerAddresses -join ', ')"

'=== System ==='
"TimeZone : $((Get-TimeZone).Id)"
"Domain   : $((Get-CimInstance Win32_ComputerSystem).Domain) (part of domain: $((Get-CimInstance Win32_ComputerSystem).PartOfDomain))"
$pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
           (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
"RebootPending : $pending"
"Defender RTP  : $((Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled)"
"GCE agent     : $((Get-Service GCEAgent -ErrorAction SilentlyContinue).Status)"

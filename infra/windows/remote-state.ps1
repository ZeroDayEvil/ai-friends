$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
"OS       : $($os.Caption) build $($os.BuildNumber)"
"Hardware : $($cs.NumberOfLogicalProcessors) vCPU, $([math]::Round($cs.TotalPhysicalMemory/1GB,1)) GB RAM"
"Disk C   : $([math]::Round((Get-PSDrive C).Free/1GB,1)) GB free of $([math]::Round(((Get-PSDrive C).Used+(Get-PSDrive C).Free)/1GB,1)) GB"
$svc = Get-CimInstance Win32_Service -Filter "Name='sshd'"
"sshd     : $($svc.State), startup=$($svc.StartMode)"
$shell = (Get-ItemProperty 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -ErrorAction SilentlyContinue).DefaultShell
"ssh shell: $(if ($shell) { $shell } else { 'cmd.exe (default)' })"
"fw 22    : $((Get-NetFirewallRule -DisplayName 'OpenSSH Server (sshd) 22' -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Enabled)/$($_.Profile)" }) -join ',')"
$cfg = Get-Content "$env:ProgramData\ssh\sshd_config" | Where-Object { $_ -match '^\s*(PasswordAuthentication|PubkeyAuthentication)\s' }
"sshd_cfg : $(if ($cfg) { $cfg -join ' | ' } else { 'defaults (password auth ON)' })"
"authkeys : $(@(Get-Content "$env:ProgramData\ssh\administrators_authorized_keys").Count) line(s)"
"admins   : $((Get-LocalGroupMember Administrators | ForEach-Object Name) -join ', ')"
"RDP NLA  : $((Get-CimInstance -Namespace root/cimv2/TerminalServices -Class Win32_TSGeneralSetting).UserAuthenticationRequired)"
"uptime   : $([math]::Round(((Get-Date) - $os.LastBootUpTime).TotalMinutes)) min"

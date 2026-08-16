$ErrorActionPreference = 'Stop'
$cfgPath = "$env:ProgramData\ssh\sshd_config"

# Оболочка по умолчанию: без неё sshd отдаёт cmd.exe, и любой вызов PowerShell
# приходится оборачивать вручную.
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value $ps `
    -PropertyType String -Force | Out-Null
"shell    : $ps"

$backup = "$cfgPath.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
Copy-Item $cfgPath $backup
"backup   : $backup"

# Директивы задаются явными строками, а не правкой закомментированных:
# sshd применяет ПЕРВОЕ вхождение параметра, поэтому важно, чтобы наши
# значения шли до блока "Match Group administrators" в конце файла.
$want = [ordered]@{
    'PubkeyAuthentication'           = 'yes'
    'PasswordAuthentication'         = 'no'
    'ChallengeResponseAuthentication' = 'no'
    'PermitEmptyPasswords'           = 'no'
    'LoginGraceTime'                 = '30'
    'MaxAuthTries'                   = '3'
}

$lines = [System.Collections.Generic.List[string]](Get-Content $cfgPath)
foreach ($k in $want.Keys) {
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^\s*#?\s*$k\s") { $lines[$i] = "#removed# $($lines[$i])" }
    }
}
$insert = @('', '# --- managed block ---') + ($want.Keys | ForEach-Object { "$_ $($want[$_])" })
$matchIdx = ($lines | Select-String -Pattern '^\s*Match\s' | Select-Object -First 1).LineNumber
if ($matchIdx) { $lines.InsertRange($matchIdx - 1, [string[]]$insert) }
else { $lines.AddRange([string[]]$insert) }

Set-Content -Path $cfgPath -Value $lines -Encoding ascii

Restart-Service sshd
Start-Sleep -Seconds 2
"sshd     : $((Get-Service sshd).Status)"
''
'effective directives:'
Get-Content $cfgPath | Where-Object { $_ -match '^\s*(Pubkey|Password|Challenge|PermitEmpty|LoginGrace|MaxAuth|Match)' }

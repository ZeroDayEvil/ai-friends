[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('VerifySource', 'Hydrate', 'AuditManifest', 'BuildOffline', 'Test', 'Package', 'All')]
    [string]$Mode,
    [string]$ManifestPath,
    [string]$RepoRoot,
    [string]$StagingDirectory,
    [string]$ReceiptPath = 'hydrate-receipt.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'Build.Primitives.psm1'
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    Write-Error "Required module '$modulePath' was not found."
    exit 1
}

Import-Module -Name $modulePath -Force

$lockedModes = @('BuildOffline', 'Test', 'Package', 'All')
if ($lockedModes -contains $Mode) {
    Write-Host ("Mode '{0}' is locked. BuildOffline/Test/Package/All remain disabled until audited manifests and explicit approval exist." -f $Mode)
    exit 64
}

try {
    switch ($Mode) {
        'VerifySource' {
            if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
                throw "VerifySource requires -ManifestPath."
            }

            if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
                $RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
            }

            $result = Invoke-VerifySource -ManifestPath $ManifestPath -RepoRoot $RepoRoot
            Write-Host ("VerifySource passed. Scope: {0}. Files verified: {1}." -f $result.ScopeRoot, $result.FileCount)
            exit 0
        }
        'Hydrate' {
            if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
                throw "Hydrate requires -ManifestPath."
            }

            if ([string]::IsNullOrWhiteSpace($StagingDirectory)) {
                throw "Hydrate requires -StagingDirectory."
            }

            $result = Invoke-Hydrate -ManifestPath $ManifestPath -StagingDirectory $StagingDirectory -ReceiptPath $ReceiptPath
            Write-Host ("Hydrate completed. Artifacts downloaded: {0}. Receipt: {1}." -f $result.ArtifactCount, $result.ReceiptPath)
            exit 0
        }
        'AuditManifest' {
            if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
                throw "AuditManifest requires -ManifestPath."
            }

            $result = Invoke-AuditManifest -ManifestPath $ManifestPath
            Write-Host ("AuditManifest passed. Artifacts: {0}. Official hosts: {1}." -f $result.ArtifactCount, ($result.OfficialHosts -join ', '))
            exit 0
        }
        default {
            throw "Unsupported mode '$Mode'."
        }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

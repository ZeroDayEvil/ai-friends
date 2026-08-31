[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$modulePath = Join-Path $repoRoot 'scripts\build\Build.Primitives.psm1'
$buildScriptPath = Join-Path $repoRoot 'scripts\build\Build.ps1'

if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    throw "Module file not found: $modulePath"
}

if (-not (Test-Path -LiteralPath $buildScriptPath -PathType Leaf)) {
    throw "Build script not found: $buildScriptPath"
}

Import-Module -Name $modulePath -Force

$tempRoot = Join-Path $env:TEMP ("build-primitives-tests-" + [Guid]::NewGuid().ToString('N'))
[System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null

$total = 0
$passed = 0
$failures = New-Object System.Collections.Generic.List[string]

function Write-JsonUtf8 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    Set-Content -LiteralPath $Path -Value (ConvertTo-Json -InputObject $Value -Depth 8) -Encoding UTF8
}

function Assert-ThrowsContains {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action,
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $thrown = $false
    try {
        & $Action
    }
    catch {
        $thrown = $true
        if ($_.Exception.Message -notmatch [Regex]::Escape($Text)) {
            throw "Expected error containing '$Text', actual: $($_.Exception.Message)"
        }
    }

    if (-not $thrown) {
        throw "Expected command to fail with '$Text'."
    }
}

function Invoke-Case {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Body
    )

    $script:total += 1
    try {
        & $Body
        $script:passed += 1
        Write-Host ("[PASS] {0}" -f $Name) -ForegroundColor Green
    }
    catch {
        $script:failures.Add(("{0}: {1}" -f $Name, $_.Exception.Message))
        Write-Host ("[FAIL] {0}: {1}" -f $Name, $_.Exception.Message) -ForegroundColor Red
    }
}

function New-ValidHydrateManifest {
    return @{
        schemaVersion = 1
        officialHosts = @('example.com')
        artifacts = @(
            @{
                id = 'artifact-one'
                version = '1.2.3'
                url = 'https://example.com/artifact-one.zip'
                destination = 'cache/artifact-one.zip'
                size = 16
                sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                license = 'MIT'
                trustTier = 'official'
                purpose = 'Static test artifact metadata.'
                installPolicy = 'manual-copy'
                lifecycle = 'pinned'
            }
        )
    }
}

try {
    Invoke-Case -Name 'VerifySource rejects traversal paths' -Body {
        $repo = Join-Path $tempRoot 'repo-traversal'
        [System.IO.Directory]::CreateDirectory((Join-Path $repo 'scope')) | Out-Null
        Set-Content -LiteralPath (Join-Path $repo 'scope\safe.txt') -Value 'ok' -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $repo 'outside.txt') -Value 'outside' -Encoding ASCII

        $manifestPath = Join-Path $tempRoot 'verify-traversal.json'
        Write-JsonUtf8 -Path $manifestPath -Value @{
            schemaVersion = 1
            scopeRoot = 'scope'
            files = @(
                @{
                    path = '../outside.txt'
                    size = 7
                    sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                }
            )
        }

        Assert-ThrowsContains -Action { Invoke-VerifySource -ManifestPath $manifestPath -RepoRoot $repo } -Text 'traversal'
    }

    Invoke-Case -Name 'VerifySource detects hash mismatch' -Body {
        $repo = Join-Path $tempRoot 'repo-hash'
        [System.IO.Directory]::CreateDirectory((Join-Path $repo 'scope')) | Out-Null
        Set-Content -LiteralPath (Join-Path $repo 'scope\item.txt') -Value 'abc' -Encoding ASCII -NoNewline

        $manifestPath = Join-Path $tempRoot 'verify-hash.json'
        Write-JsonUtf8 -Path $manifestPath -Value @{
            schemaVersion = 1
            scopeRoot = 'scope'
            files = @(
                @{
                    path = 'scope/item.txt'
                    size = 3
                    sha256 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
                }
            )
        }

        Assert-ThrowsContains -Action { Invoke-VerifySource -ManifestPath $manifestPath -RepoRoot $repo } -Text 'hash mismatch'
    }

    Invoke-Case -Name 'Hydrate rejects duplicate destination' -Body {
        $manifest = New-ValidHydrateManifest
        $manifest.artifacts = @(
            $manifest.artifacts[0],
            @{
                id = 'artifact-two'
                version = '2.0.0'
                url = 'https://example.com/artifact-two.zip'
                destination = 'cache/artifact-one.zip'
                size = 32
                sha256 = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
                license = 'MIT'
                trustTier = 'official'
                purpose = 'Duplicate destination test.'
                installPolicy = 'manual-copy'
                lifecycle = 'pinned'
            }
        )

        $manifestPath = Join-Path $tempRoot 'hydrate-duplicate-destination.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        $staging = Join-Path $tempRoot 'staging-duplicate-destination'
        Assert-ThrowsContains -Action { Invoke-Hydrate -ManifestPath $manifestPath -StagingDirectory $staging } -Text 'duplicate destination'
    }

    Invoke-Case -Name 'AuditManifest rejects non-HTTPS URL' -Body {
        $manifest = New-ValidHydrateManifest
        $manifest.artifacts[0].url = 'http://example.com/artifact-one.zip'

        $manifestPath = Join-Path $tempRoot 'audit-non-https.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        Assert-ThrowsContains -Action { Invoke-AuditManifest -ManifestPath $manifestPath } -Text 'HTTPS'
    }

    Invoke-Case -Name 'AuditManifest rejects floating version' -Body {
        $manifest = New-ValidHydrateManifest
        $manifest.artifacts[0].version = 'latest'

        $manifestPath = Join-Path $tempRoot 'audit-floating-version.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        Assert-ThrowsContains -Action { Invoke-AuditManifest -ManifestPath $manifestPath } -Text 'exact version'
    }

    Invoke-Case -Name 'AuditManifest rejects forbidden license' -Body {
        $manifest = New-ValidHydrateManifest
        $manifest.artifacts[0].license = 'GPL-3.0'

        $manifestPath = Join-Path $tempRoot 'audit-forbidden-license.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        Assert-ThrowsContains -Action { Invoke-AuditManifest -ManifestPath $manifestPath } -Text 'license'
    }

    Invoke-Case -Name 'AuditManifest rejects forbidden trust tier' -Body {
        $manifest = New-ValidHydrateManifest
        $manifest.artifacts[0].trustTier = 'untrusted'

        $manifestPath = Join-Path $tempRoot 'audit-forbidden-tier.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        Assert-ThrowsContains -Action { Invoke-AuditManifest -ManifestPath $manifestPath } -Text 'trust tier'
    }

    Invoke-Case -Name 'AuditManifest rejects missing lifecycle' -Body {
        $manifest = New-ValidHydrateManifest
        $manifest.artifacts[0].Remove('lifecycle')

        $manifestPath = Join-Path $tempRoot 'audit-missing-lifecycle.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        Assert-ThrowsContains -Action { Invoke-AuditManifest -ManifestPath $manifestPath } -Text 'lifecycle'
    }

    Invoke-Case -Name 'Locked modes fail closed' -Body {
        $lockedModes = @('BuildOffline', 'Test', 'Package', 'All')
        foreach ($mode in $lockedModes) {
            $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $buildScriptPath -Mode $mode 2>&1
            $exitCode = $LASTEXITCODE

            if ($exitCode -eq 0) {
                throw "Mode '$mode' unexpectedly returned exit code 0."
            }

            $joinedOutput = ($output | ForEach-Object { "$_" }) -join "`n"
            if ($joinedOutput -notmatch 'locked') {
                throw "Mode '$mode' did not report a locked fail-closed message."
            }
        }
    }
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host ("FAILED: {0}/{1} tests failed." -f $failures.Count, $total) -ForegroundColor Red
    foreach ($failure in $failures) {
        Write-Host (" - {0}" -f $failure) -ForegroundColor Red
    }
    exit 1
}

Write-Host ''
Write-Host ("PASSED: {0}/{1} tests passed." -f $passed, $total) -ForegroundColor Green
exit 0

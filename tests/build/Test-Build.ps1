[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$modulePath = Join-Path $repoRoot 'scripts\build\Build.Primitives.psm1'
$buildScriptPath = Join-Path $repoRoot 'scripts\build\Build.ps1'
$isWindows = $env:OS -eq 'Windows_NT'

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
$skipped = 0
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

function Get-Sha256Hex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function New-SkipResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    return [PSCustomObject]@{
        __skip = $true
        reason = $Reason
    }
}

function Assert-ThrowsError {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedId,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedMessage
    )

    $caught = $null
    try {
        & $Action
    }
    catch {
        $caught = $_
    }

    if ($null -eq $caught) {
        throw "Expected an error with id '$ExpectedId', but command succeeded."
    }

    $actualId = [string]$caught.FullyQualifiedErrorId
    if ($actualId -ne $ExpectedId) {
        throw "Expected error id '$ExpectedId', got '$actualId'."
    }

    $actualMessage = [string]$caught.Exception.Message
    if ($actualMessage -ne $ExpectedMessage) {
        throw "Expected message '$ExpectedMessage', got '$actualMessage'."
    }
}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
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
        $result = & $Body
        if ($null -ne $result -and $result.PSObject.Properties['__skip'] -and $result.__skip) {
            $script:skipped += 1
            Write-Host ("[SKIP] {0}: {1}" -f $Name, $result.reason) -ForegroundColor Yellow
            return
        }

        $script:passed += 1
        Write-Host ("[PASS] {0}" -f $Name) -ForegroundColor Green
    }
    catch {
        $script:failures.Add(("{0}: {1}" -f $Name, $_.Exception.Message))
        Write-Host ("[FAIL] {0}: {1}" -f $Name, $_.Exception.Message) -ForegroundColor Red
    }
}

function New-ValidHydrateManifest {
    param(
        [string]$Id = 'artifact-one',
        [string]$Version = '1.2.3',
        [string]$Url = 'https://example.com/artifact-one.bin',
        [string]$Destination = 'cache/artifact-one.bin',
        [Int64]$Size = 16,
        [string]$Sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        [string]$License = 'MIT',
        [string]$TrustTier = 'official',
        [string]$Purpose = 'Static test artifact metadata.',
        [string]$InstallPolicy = 'manual-copy',
        [string]$Lifecycle = 'pinned'
    )

    $uri = [System.Uri]$Url
    return @{
        schemaVersion = 1
        officialHosts = @($uri.Host)
        artifacts = @(
            @{
                id = $Id
                version = $Version
                url = $Url
                destination = $Destination
                size = $Size
                sha256 = $Sha256
                license = $License
                trustTier = $TrustTier
                purpose = $Purpose
                installPolicy = $InstallPolicy
                lifecycle = $Lifecycle
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

        Assert-ThrowsError -Action { Invoke-VerifySource -ManifestPath $manifestPath -RepoRoot $repo } `
            -ExpectedId 'Build.Path.Traversal' `
            -ExpectedMessage "files[0].path '../outside.txt' contains traversal segment '..'."
    }

    Invoke-Case -Name 'VerifySource detects hash mismatch' -Body {
        $repo = Join-Path $tempRoot 'repo-hash'
        [System.IO.Directory]::CreateDirectory((Join-Path $repo 'scope')) | Out-Null
        $filePath = Join-Path $repo 'scope\item.txt'
        Set-Content -LiteralPath $filePath -Value 'abc' -Encoding ASCII -NoNewline
        $actualHash = Get-Sha256Hex -Path $filePath

        $manifestPath = Join-Path $tempRoot 'verify-hash.json'
        $expectedHash = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        Write-JsonUtf8 -Path $manifestPath -Value @{
            schemaVersion = 1
            scopeRoot = 'scope'
            files = @(
                @{
                    path = 'scope/item.txt'
                    size = 3
                    sha256 = $expectedHash
                }
            )
        }

        Assert-ThrowsError -Action { Invoke-VerifySource -ManifestPath $manifestPath -RepoRoot $repo } `
            -ExpectedId 'Build.VerifySource.Mismatch' `
            -ExpectedMessage ("VerifySource manifest mismatch:`n - hash mismatch for 'scope/item.txt': expected {0}, got {1}." -f $expectedHash.ToUpperInvariant(), $actualHash)
    }

    Invoke-Case -Name 'VerifySource rejects unexpected extra file' -Body {
        $repo = Join-Path $tempRoot 'repo-extra'
        [System.IO.Directory]::CreateDirectory((Join-Path $repo 'scope')) | Out-Null
        $expectedFilePath = Join-Path $repo 'scope\expected.txt'
        $extraFilePath = Join-Path $repo 'scope\extra.txt'
        Set-Content -LiteralPath $expectedFilePath -Value 'ok' -Encoding ASCII -NoNewline
        Set-Content -LiteralPath $extraFilePath -Value 'extra' -Encoding ASCII -NoNewline

        $manifestPath = Join-Path $tempRoot 'verify-extra.json'
        Write-JsonUtf8 -Path $manifestPath -Value @{
            schemaVersion = 1
            scopeRoot = 'scope'
            files = @(
                @{
                    path = 'scope/expected.txt'
                    size = 2
                    sha256 = (Get-Sha256Hex -Path $expectedFilePath)
                }
            )
        }

        Assert-ThrowsError -Action { Invoke-VerifySource -ManifestPath $manifestPath -RepoRoot $repo } `
            -ExpectedId 'Build.VerifySource.Mismatch' `
            -ExpectedMessage "VerifySource manifest mismatch:`n - file count mismatch: expected 1, got 2.`n - Unexpected file 'scope/extra.txt'."
    }

    Invoke-Case -Name 'VerifySource rejects non-NFC path in manifest' -Body {
        $repo = Join-Path $tempRoot 'repo-non-nfc-manifest'
        [System.IO.Directory]::CreateDirectory((Join-Path $repo 'scope')) | Out-Null
        Set-Content -LiteralPath (Join-Path $repo 'scope\ok.txt') -Value 'ok' -Encoding ASCII -NoNewline

        $nfdSegment = [string]::Concat('cafe', [char]0x0301, '.txt')
        $nfdPath = "scope/$nfdSegment"
        $manifestPath = Join-Path $tempRoot 'verify-non-nfc-manifest.json'
        Write-JsonUtf8 -Path $manifestPath -Value @{
            schemaVersion = 1
            scopeRoot = 'scope'
            files = @(
                @{
                    path = $nfdPath
                    size = 2
                    sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                }
            )
        }

        Assert-ThrowsError -Action { Invoke-VerifySource -ManifestPath $manifestPath -RepoRoot $repo } `
            -ExpectedId 'Build.Path.NonNfcComponent' `
            -ExpectedMessage ("files[0].path '{0}' contains non-NFC path component '{1}'." -f $nfdPath, $nfdSegment)
    }

    Invoke-Case -Name 'VerifySource rejects NFC/NFD coexistence on disk' -Body {
        $repo = Join-Path $tempRoot 'repo-nfc-nfd'
        $scope = Join-Path $repo 'scope'
        [System.IO.Directory]::CreateDirectory($scope) | Out-Null

        $nfcName = [string]::Concat('caf', [char]0x00E9, '.txt')
        $nfdName = [string]::Concat('cafe', [char]0x0301, '.txt')
        $nfcPath = Join-Path $scope $nfcName
        $nfdPath = Join-Path $scope $nfdName

        Set-Content -LiteralPath $nfcPath -Value 'nfc' -Encoding UTF8 -NoNewline
        Set-Content -LiteralPath $nfdPath -Value 'nfd' -Encoding UTF8 -NoNewline

        $names = Get-ChildItem -LiteralPath $scope -File | Select-Object -ExpandProperty Name
        $distinctNames = @($names | Select-Object -Unique)
        if ($distinctNames.Count -lt 2) {
            return (New-SkipResult -Reason 'Filesystem does not preserve distinct NFC/NFD sibling names.')
        }

        $manifestPath = Join-Path $tempRoot 'verify-nfc-nfd.json'
        Write-JsonUtf8 -Path $manifestPath -Value @{
            schemaVersion = 1
            scopeRoot = 'scope'
            files = @(
                @{
                    path = "scope/$nfcName"
                    size = (Get-Item -LiteralPath $nfcPath).Length
                    sha256 = (Get-Sha256Hex -Path $nfcPath)
                }
            )
        }

        Assert-ThrowsError -Action { Invoke-VerifySource -ManifestPath $manifestPath -RepoRoot $repo } `
            -ExpectedId 'Build.Path.NonNfcComponent' `
            -ExpectedMessage ("actual file path '{0}' contains non-NFC path component '{1}'." -f "scope/$nfdName", $nfdName)
    }

    Invoke-Case -Name 'VerifySource rejects Hook and hook collision when supported' -Body {
        $repo = Join-Path $tempRoot 'repo-case-collision'
        $scope = Join-Path $repo 'scope'
        [System.IO.Directory]::CreateDirectory($scope) | Out-Null

        if ($isWindows) {
            try {
                & fsutil.exe file setCaseSensitiveInfo $scope enable | Out-Null
            }
            catch {
            }
        }

        $upperPath = Join-Path $scope 'Hook.ps1'
        $lowerPath = Join-Path $scope 'hook.ps1'
        Set-Content -LiteralPath $upperPath -Value 'upper' -Encoding ASCII -NoNewline
        Set-Content -LiteralPath $lowerPath -Value 'lower' -Encoding ASCII -NoNewline

        $names = Get-ChildItem -LiteralPath $scope -File | Select-Object -ExpandProperty Name
        $hasUpper = $names -contains 'Hook.ps1'
        $hasLower = $names -contains 'hook.ps1'
        if (-not ($hasUpper -and $hasLower)) {
            return (New-SkipResult -Reason 'Filesystem does not support distinct Hook.ps1 and hook.ps1 in this directory.')
        }

        $manifestPath = Join-Path $tempRoot 'verify-case-collision.json'
        Write-JsonUtf8 -Path $manifestPath -Value @{
            schemaVersion = 1
            scopeRoot = 'scope'
            files = @(
                @{
                    path = 'scope/Hook.ps1'
                    size = 5
                    sha256 = (Get-Sha256Hex -Path $upperPath)
                }
            )
        }

        Assert-ThrowsError -Action { Invoke-VerifySource -ManifestPath $manifestPath -RepoRoot $repo } `
            -ExpectedId 'Build.VerifySource.ActualPathCollision' `
            -ExpectedMessage "VerifySource found case/normalization collision for path key 'SCOPE/HOOK.PS1' on disk."
    }

    Invoke-Case -Name 'Hydrate rejects duplicate destination' -Body {
        $manifest = New-ValidHydrateManifest
        $manifest.artifacts = @(
            $manifest.artifacts[0],
            @{
                id = 'artifact-two'
                version = '2.0.0'
                url = 'https://example.com/artifact-two.bin'
                destination = 'cache/artifact-one.bin'
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
        Assert-ThrowsError -Action { Invoke-Hydrate -ManifestPath $manifestPath -StagingDirectory $staging } `
            -ExpectedId 'Build.Manifest.DuplicateDestination' `
            -ExpectedMessage "artifacts contains duplicate destination 'cache/artifact-one.bin'."
    }

    Invoke-Case -Name 'AuditManifest rejects non-HTTPS URL' -Body {
        $manifest = New-ValidHydrateManifest -Url 'http://example.com/artifact-one.bin'
        $manifestPath = Join-Path $tempRoot 'audit-non-https.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        Assert-ThrowsError -Action { Invoke-AuditManifest -ManifestPath $manifestPath } `
            -ExpectedId 'Build.Manifest.NonHttpsUrl' `
            -ExpectedMessage "artifact 'artifact-one' URL must use HTTPS."
    }

    Invoke-Case -Name 'AuditManifest rejects floating version' -Body {
        $manifest = New-ValidHydrateManifest -Version 'latest'
        $manifestPath = Join-Path $tempRoot 'audit-floating-version.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        Assert-ThrowsError -Action { Invoke-AuditManifest -ManifestPath $manifestPath } `
            -ExpectedId 'Build.Manifest.NonExactVersion' `
            -ExpectedMessage "artifact 'artifact-one' must declare an exact version (no latest, wildcards, or ranges)."
    }

    Invoke-Case -Name 'AuditManifest rejects forbidden license' -Body {
        $manifest = New-ValidHydrateManifest -License 'GPL-3.0'
        $manifestPath = Join-Path $tempRoot 'audit-forbidden-license.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        Assert-ThrowsError -Action { Invoke-AuditManifest -ManifestPath $manifestPath } `
            -ExpectedId 'Build.Manifest.ForbiddenLicense' `
            -ExpectedMessage "artifact 'artifact-one' license 'GPL-3.0' is not allowed."
    }

    Invoke-Case -Name 'AuditManifest rejects forbidden trust tier' -Body {
        $manifest = New-ValidHydrateManifest -TrustTier 'untrusted'
        $manifestPath = Join-Path $tempRoot 'audit-forbidden-tier.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        Assert-ThrowsError -Action { Invoke-AuditManifest -ManifestPath $manifestPath } `
            -ExpectedId 'Build.Manifest.ForbiddenTrustTier' `
            -ExpectedMessage "artifact 'artifact-one' trust tier 'untrusted' is not allowed."
    }

    Invoke-Case -Name 'AuditManifest rejects missing lifecycle' -Body {
        $manifest = New-ValidHydrateManifest
        $manifest.artifacts[0].Remove('lifecycle')

        $manifestPath = Join-Path $tempRoot 'audit-missing-lifecycle.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        Assert-ThrowsError -Action { Invoke-AuditManifest -ManifestPath $manifestPath } `
            -ExpectedId 'Build.Manifest.MissingField' `
            -ExpectedMessage "artifacts[0] is missing required field 'lifecycle'."
    }

    Invoke-Case -Name 'Hydrate rejects receipt prefix collision with destination' -Body {
        $manifest = New-ValidHydrateManifest -Destination 'cache/artifact-one.bin'
        $manifestPath = Join-Path $tempRoot 'hydrate-receipt-prefix-collision.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        $staging = Join-Path $tempRoot 'staging-receipt-prefix-collision'
        $receiptPath = 'cache/artifact-one.bin/receipt.json'

        Assert-ThrowsError -Action { Invoke-Hydrate -ManifestPath $manifestPath -StagingDirectory $staging -ReceiptPath $receiptPath } `
            -ExpectedId 'Build.Hydrate.ReceiptPathCollision' `
            -ExpectedMessage "ReceiptPath '$receiptPath' collides by prefix with artifact destination 'cache/artifact-one.bin'."
    }

    Invoke-Case -Name 'Hydrate rejects existing receipt file' -Body {
        $payloadPath = Join-Path $tempRoot 'receipt-existing-payload.bin'
        Set-Content -LiteralPath $payloadPath -Value 'payload' -Encoding ASCII -NoNewline
        $payloadSize = (Get-Item -LiteralPath $payloadPath).Length
        $payloadHash = Get-Sha256Hex -Path $payloadPath

        $manifest = New-ValidHydrateManifest -Size $payloadSize -Sha256 $payloadHash -Destination 'cache/artifact-one.bin' -Url 'https://example.com/artifact-one.bin'
        $manifestPath = Join-Path $tempRoot 'hydrate-existing-receipt-manifest.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        $staging = Join-Path $tempRoot 'staging-existing-receipt'
        [System.IO.Directory]::CreateDirectory($staging) | Out-Null
        $receiptPath = 'receipts/hydrate.json'
        $receiptFile = Join-Path $staging ($receiptPath -replace '/', '\')
        [System.IO.Directory]::CreateDirectory((Split-Path -Parent $receiptFile)) | Out-Null
        Set-Content -LiteralPath $receiptFile -Value '{}' -Encoding UTF8

        $downloader = {
            param($Artifact, $OutFile)
            Copy-Item -LiteralPath $payloadPath -Destination $OutFile -Force
            return [PSCustomObject]@{ ResponseUri = [System.Uri]$Artifact.Url }
        }

        Assert-ThrowsError -Action { Invoke-Hydrate -ManifestPath $manifestPath -StagingDirectory $staging -ReceiptPath $receiptPath -Downloader $downloader } `
            -ExpectedId 'Build.Hydrate.ReceiptExists' `
            -ExpectedMessage "ReceiptPath '$receiptPath' already exists."
    }

    Invoke-Case -Name 'Hydrate rejects receipt path through junction' -Body {
        if (-not $isWindows) {
            return (New-SkipResult -Reason 'Junction test is Windows-specific.')
        }

        $manifest = New-ValidHydrateManifest
        $manifestPath = Join-Path $tempRoot 'hydrate-receipt-junction.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        $staging = Join-Path $tempRoot 'staging-receipt-junction'
        $outside = Join-Path $tempRoot 'outside-receipt-junction'
        [System.IO.Directory]::CreateDirectory($staging) | Out-Null
        [System.IO.Directory]::CreateDirectory($outside) | Out-Null

        $junctionPath = Join-Path $staging 'link'
        try {
            New-Item -ItemType Junction -Path $junctionPath -Target $outside -ErrorAction Stop | Out-Null
        }
        catch {
            return (New-SkipResult -Reason 'Unable to create junction for receipt reparse-point test.')
        }

        $junctionFullPath = (Get-Item -LiteralPath $junctionPath -Force).FullName
        $expectedMessage = "ReceiptPath path '$junctionFullPath' traverses a reparse point, which is forbidden."
        Assert-ThrowsError -Action { Invoke-Hydrate -ManifestPath $manifestPath -StagingDirectory $staging -ReceiptPath 'link/receipt.json' } `
            -ExpectedId 'Build.Hydrate.ReceiptPathReparsePoint' `
            -ExpectedMessage $expectedMessage
    }

    Invoke-Case -Name 'Hydrate success uses downloader seam and atomic promotes' -Body {
        $payloadPath = Join-Path $tempRoot 'hydrate-success-payload.bin'
        Set-Content -LiteralPath $payloadPath -Value 'payload-ok' -Encoding ASCII -NoNewline
        $payloadSize = (Get-Item -LiteralPath $payloadPath).Length
        $payloadHash = Get-Sha256Hex -Path $payloadPath

        $manifest = New-ValidHydrateManifest -Size $payloadSize -Sha256 $payloadHash -Destination 'cache/artifact-one.bin' -Url 'https://example.com/artifact-one.bin'
        $manifestPath = Join-Path $tempRoot 'hydrate-success-manifest.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        $staging = Join-Path $tempRoot 'staging-success'
        $receiptPath = 'receipts/hydrate.json'
        $downloader = {
            param($Artifact, $OutFile)
            Copy-Item -LiteralPath $payloadPath -Destination $OutFile -Force
            return [PSCustomObject]@{ ResponseUri = [System.Uri]$Artifact.Url }
        }

        $result = Invoke-Hydrate -ManifestPath $manifestPath -StagingDirectory $staging -ReceiptPath $receiptPath -Downloader $downloader
        Assert-True -Condition ($result.ArtifactCount -eq 1) -Message 'Expected exactly one hydrated artifact.'

        $destinationPath = Join-Path $staging 'cache\artifact-one.bin'
        Assert-True -Condition (Test-Path -LiteralPath $destinationPath -PathType Leaf) -Message 'Hydrated destination file is missing.'

        $receiptFile = Join-Path $staging ($receiptPath -replace '/', '\')
        Assert-True -Condition (Test-Path -LiteralPath $receiptFile -PathType Leaf) -Message 'Hydrate receipt file is missing.'

        $receipt = Get-Content -LiteralPath $receiptFile -Raw | ConvertFrom-Json
        Assert-True -Condition ($receipt.artifacts.Count -eq 1) -Message 'Receipt must contain exactly one artifact record.'
        Assert-True -Condition ($receipt.artifacts[0].sourceUrl -eq 'https://example.com/artifact-one.bin') -Message 'Receipt sourceUrl mismatch.'
        Assert-True -Condition ($receipt.artifacts[0].sha256 -eq $payloadHash) -Message 'Receipt hash mismatch.'

        $leftoverTemps = Get-ChildItem -LiteralPath $staging -Recurse -File -Filter '*.tmp.*' -ErrorAction SilentlyContinue
        Assert-True -Condition (@($leftoverTemps).Count -eq 0) -Message 'Temporary files were not fully promoted/cleaned up.'
    }

    Invoke-Case -Name 'Hydrate rejects redirect to a non-official host' -Body {
        $payloadPath = Join-Path $tempRoot 'hydrate-redirect-payload.bin'
        Set-Content -LiteralPath $payloadPath -Value 'payload-ok' -Encoding ASCII -NoNewline
        $payloadSize = (Get-Item -LiteralPath $payloadPath).Length
        $payloadHash = Get-Sha256Hex -Path $payloadPath

        $manifest = New-ValidHydrateManifest -Size $payloadSize -Sha256 $payloadHash -Destination 'cache/artifact-one.bin' -Url 'https://example.com/artifact-one.bin'
        $manifestPath = Join-Path $tempRoot 'hydrate-redirect-manifest.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        $staging = Join-Path $tempRoot 'staging-redirect'
        $downloader = {
            param($Artifact, $OutFile)
            Copy-Item -LiteralPath $payloadPath -Destination $OutFile -Force
            return [PSCustomObject]@{ ResponseUri = [System.Uri]'https://evil.example.net/artifact-one.bin' }
        }

        Assert-ThrowsError -Action { Invoke-Hydrate -ManifestPath $manifestPath -StagingDirectory $staging -Downloader $downloader } `
            -ExpectedId 'Build.Hydrate.RedirectHostMismatch' `
            -ExpectedMessage "artifact 'artifact-one' redirected to host 'evil.example.net', expected 'example.com'. Cross-host redirects are forbidden."
    }

    Invoke-Case -Name 'Hydrate detects size mismatch' -Body {
        $payloadPath = Join-Path $tempRoot 'hydrate-size-payload.bin'
        Set-Content -LiteralPath $payloadPath -Value 'short' -Encoding ASCII -NoNewline
        $payloadHash = Get-Sha256Hex -Path $payloadPath

        $manifest = New-ValidHydrateManifest -Size 999 -Sha256 $payloadHash -Destination 'cache/artifact-one.bin' -Url 'https://example.com/artifact-one.bin'
        $manifestPath = Join-Path $tempRoot 'hydrate-size-mismatch-manifest.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        $staging = Join-Path $tempRoot 'staging-size-mismatch'
        $downloader = {
            param($Artifact, $OutFile)
            Copy-Item -LiteralPath $payloadPath -Destination $OutFile -Force
            return [PSCustomObject]@{ ResponseUri = [System.Uri]$Artifact.Url }
        }

        Assert-ThrowsError -Action { Invoke-Hydrate -ManifestPath $manifestPath -StagingDirectory $staging -Downloader $downloader } `
            -ExpectedId 'Build.Hydrate.SizeMismatch' `
            -ExpectedMessage "artifact 'artifact-one' size mismatch: expected 999, got 5."
    }

    Invoke-Case -Name 'Hydrate detects hash mismatch' -Body {
        $payloadPath = Join-Path $tempRoot 'hydrate-hash-payload.bin'
        Set-Content -LiteralPath $payloadPath -Value 'payload' -Encoding ASCII -NoNewline
        $payloadSize = (Get-Item -LiteralPath $payloadPath).Length
        $expectedHash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'

        $manifest = New-ValidHydrateManifest -Size $payloadSize -Sha256 $expectedHash -Destination 'cache/artifact-one.bin' -Url 'https://example.com/artifact-one.bin'
        $manifestPath = Join-Path $tempRoot 'hydrate-hash-mismatch-manifest.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        $staging = Join-Path $tempRoot 'staging-hash-mismatch'
        $downloader = {
            param($Artifact, $OutFile)
            Copy-Item -LiteralPath $payloadPath -Destination $OutFile -Force
            return [PSCustomObject]@{ ResponseUri = [System.Uri]$Artifact.Url }
        }

        $actualHash = Get-Sha256Hex -Path $payloadPath
        Assert-ThrowsError -Action { Invoke-Hydrate -ManifestPath $manifestPath -StagingDirectory $staging -Downloader $downloader } `
            -ExpectedId 'Build.Hydrate.HashMismatch' `
            -ExpectedMessage ("artifact 'artifact-one' hash mismatch: expected {0}, got {1}." -f $expectedHash.ToUpperInvariant(), $actualHash)
    }

    Invoke-Case -Name 'Hydrate passes Authenticode signer and thumbprint checks' -Body {
        if (-not $isWindows) {
            return (New-SkipResult -Reason 'Authenticode tests require Windows.')
        }

        $signedSource = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (-not (Test-Path -LiteralPath $signedSource -PathType Leaf)) {
            return (New-SkipResult -Reason 'Signed powershell.exe source file was not found.')
        }

        $signature = Get-AuthenticodeSignature -FilePath $signedSource
        if ($null -eq $signature -or $signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
            return (New-SkipResult -Reason 'Signed powershell.exe does not have a valid Authenticode signature in this environment.')
        }

        $size = (Get-Item -LiteralPath $signedSource).Length
        $sha256 = Get-Sha256Hex -Path $signedSource
        $thumbprint = $signature.SignerCertificate.Thumbprint.ToUpperInvariant()
        $subject = $signature.SignerCertificate.Subject

        $manifest = New-ValidHydrateManifest -Id 'signed-powershell' -Url 'https://example.com/powershell.exe' -Destination 'signed/powershell.exe' -Size $size -Sha256 $sha256
        $manifest.artifacts[0].authenticode = @{
            thumbprint = $thumbprint
            subject = $subject
        }

        $manifestPath = Join-Path $tempRoot 'hydrate-authenticode-pass.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        $staging = Join-Path $tempRoot 'staging-authenticode-pass'
        $downloader = {
            param($Artifact, $OutFile)
            Copy-Item -LiteralPath $signedSource -Destination $OutFile -Force
            return [PSCustomObject]@{ ResponseUri = [System.Uri]$Artifact.Url }
        }

        $result = Invoke-Hydrate -ManifestPath $manifestPath -StagingDirectory $staging -Downloader $downloader
        Assert-True -Condition ($result.ArtifactCount -eq 1) -Message 'Expected one Authenticode-validated artifact.'
        Assert-True -Condition (Test-Path -LiteralPath (Join-Path $staging 'signed\powershell.exe') -PathType Leaf) -Message 'Authenticode output file missing.'
    }

    Invoke-Case -Name 'Hydrate fails on Authenticode thumbprint mismatch' -Body {
        if (-not $isWindows) {
            return (New-SkipResult -Reason 'Authenticode tests require Windows.')
        }

        $signedSource = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (-not (Test-Path -LiteralPath $signedSource -PathType Leaf)) {
            return (New-SkipResult -Reason 'Signed powershell.exe source file was not found.')
        }

        $signature = Get-AuthenticodeSignature -FilePath $signedSource
        if ($null -eq $signature -or $signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
            return (New-SkipResult -Reason 'Signed powershell.exe does not have a valid Authenticode signature in this environment.')
        }

        $size = (Get-Item -LiteralPath $signedSource).Length
        $sha256 = Get-Sha256Hex -Path $signedSource
        $subject = $signature.SignerCertificate.Subject

        $manifest = New-ValidHydrateManifest -Id 'signed-thumbprint-mismatch' -Url 'https://example.com/powershell.exe' -Destination 'signed/powershell.exe' -Size $size -Sha256 $sha256
        $manifest.artifacts[0].authenticode = @{
            thumbprint = '0000000000000000000000000000000000000000'
            subject = $subject
        }

        $manifestPath = Join-Path $tempRoot 'hydrate-authenticode-thumbprint-mismatch.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        $staging = Join-Path $tempRoot 'staging-authenticode-thumbprint-mismatch'
        $downloader = {
            param($Artifact, $OutFile)
            Copy-Item -LiteralPath $signedSource -Destination $OutFile -Force
            return [PSCustomObject]@{ ResponseUri = [System.Uri]$Artifact.Url }
        }

        Assert-ThrowsError -Action { Invoke-Hydrate -ManifestPath $manifestPath -StagingDirectory $staging -Downloader $downloader } `
            -ExpectedId 'Build.Authenticode.ThumbprintMismatch' `
            -ExpectedMessage "artifact 'signed-thumbprint-mismatch' Authenticode thumbprint mismatch."
    }

    Invoke-Case -Name 'Hydrate fails on Authenticode subject mismatch' -Body {
        if (-not $isWindows) {
            return (New-SkipResult -Reason 'Authenticode tests require Windows.')
        }

        $signedSource = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (-not (Test-Path -LiteralPath $signedSource -PathType Leaf)) {
            return (New-SkipResult -Reason 'Signed powershell.exe source file was not found.')
        }

        $signature = Get-AuthenticodeSignature -FilePath $signedSource
        if ($null -eq $signature -or $signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
            return (New-SkipResult -Reason 'Signed powershell.exe does not have a valid Authenticode signature in this environment.')
        }

        $size = (Get-Item -LiteralPath $signedSource).Length
        $sha256 = Get-Sha256Hex -Path $signedSource
        $thumbprint = $signature.SignerCertificate.Thumbprint.ToUpperInvariant()

        $manifest = New-ValidHydrateManifest -Id 'signed-subject-mismatch' -Url 'https://example.com/powershell.exe' -Destination 'signed/powershell.exe' -Size $size -Sha256 $sha256
        $manifest.artifacts[0].authenticode = @{
            thumbprint = $thumbprint
            subject = 'CN=Not The Real Signer'
        }

        $manifestPath = Join-Path $tempRoot 'hydrate-authenticode-subject-mismatch.json'
        Write-JsonUtf8 -Path $manifestPath -Value $manifest

        $staging = Join-Path $tempRoot 'staging-authenticode-subject-mismatch'
        $downloader = {
            param($Artifact, $OutFile)
            Copy-Item -LiteralPath $signedSource -Destination $OutFile -Force
            return [PSCustomObject]@{ ResponseUri = [System.Uri]$Artifact.Url }
        }

        Assert-ThrowsError -Action { Invoke-Hydrate -ManifestPath $manifestPath -StagingDirectory $staging -Downloader $downloader } `
            -ExpectedId 'Build.Authenticode.SubjectMismatch' `
            -ExpectedMessage "artifact 'signed-subject-mismatch' Authenticode subject mismatch."
    }

    Invoke-Case -Name 'Locked modes fail closed with exit code 64' -Body {
        $lockedModes = @('BuildOffline', 'Test', 'Package', 'All')
        foreach ($mode in $lockedModes) {
            $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $buildScriptPath -Mode $mode 2>&1
            $exitCode = $LASTEXITCODE
            if ($exitCode -ne 64) {
                throw "Mode '$mode' expected exit code 64, got $exitCode."
            }

            $line = ($output | ForEach-Object { "$_" } | Select-Object -Last 1)
            $expected = "Mode '$mode' is locked. BuildOffline/Test/Package/All remain disabled until audited manifests and explicit approval exist."
            if ($line -ne $expected) {
                throw "Mode '$mode' expected message '$expected', got '$line'."
            }
        }
    }
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host ("FAILED: {0}/{1} tests failed. Passed: {2}. Skipped: {3}." -f $failures.Count, $total, $passed, $skipped) -ForegroundColor Red
    foreach ($failure in $failures) {
        Write-Host (" - {0}" -f $failure) -ForegroundColor Red
    }
    exit 1
}

Write-Host ''
Write-Host ("PASSED: {0}/{1} tests passed. Skipped: {2}." -f $passed, $total, $skipped) -ForegroundColor Green
exit 0

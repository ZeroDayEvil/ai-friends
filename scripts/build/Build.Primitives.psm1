Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AllowedLicenses = @(
    'MIT',
    'Apache-2.0',
    'BSD-2-Clause',
    'BSD-3-Clause',
    'ISC',
    'MPL-2.0',
    'Python-2.0',
    'Zlib'
)

$script:AllowedTrustTiers = @(
    'official',
    'vendor-audited'
)

$script:AllowedInstallPolicies = @(
    'manual-copy',
    'extract-only'
)

$script:AllowedLifecyclePolicies = @(
    'pinned',
    'frozen'
)

$script:AuthenticodeExtensions = @(
    '.exe',
    '.dll',
    '.msi',
    '.ps1',
    '.psm1',
    '.psd1'
)

function Read-JsonObject {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath
    )

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "Manifest file '$ManifestPath' was not found."
    }

    $raw = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Manifest file '$ManifestPath' is empty."
    }

    $parsed = ConvertFrom-Json -InputObject $raw
    if ($parsed -is [System.Array]) {
        throw "Manifest file '$ManifestPath' must be a JSON object."
    }

    return $parsed
}

function Assert-AllowedFields {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$InputObject,
        [Parameter(Mandatory = $true)]
        [string[]]$AllowedFields,
        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $allowedLookup = @{}
    foreach ($name in $AllowedFields) {
        $allowedLookup[$name] = $true
    }

    foreach ($property in $InputObject.PSObject.Properties) {
        if (-not $allowedLookup.ContainsKey($property.Name)) {
            throw "$Context contains unknown field '$($property.Name)'."
        }
    }
}

function Assert-RequiredFields {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$InputObject,
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredFields,
        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    foreach ($name in $RequiredFields) {
        $property = $InputObject.PSObject.Properties[$name]
        if ($null -eq $property) {
            throw "$Context is missing required field '$name'."
        }

        if ($null -eq $property.Value) {
            throw "$Context field '$name' must not be null."
        }
    }
}

function Get-PathInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,
        [Parameter(Mandatory = $true)]
        [string]$FieldName
    )

    if ([string]::IsNullOrWhiteSpace($BasePath)) {
        throw "$FieldName must be provided."
    }

    $fullPath = [System.IO.Path]::GetFullPath($BasePath)
    $withSeparator = if ($fullPath.EndsWith('\')) { $fullPath } else { "$fullPath\" }

    return [PSCustomObject]@{
        FullPath      = $fullPath
        WithSeparator = $withSeparator
    }
}

function Normalize-RelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue,
        [Parameter(Mandatory = $true)]
        [string]$FieldName
    )

    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        throw "$FieldName must be a non-empty relative path."
    }

    $candidate = $PathValue.Trim()
    if ($candidate.StartsWith('\\') -or $candidate.StartsWith('/')) {
        throw "$FieldName '$PathValue' must not start with UNC or absolute separators."
    }

    if ([System.IO.Path]::IsPathRooted($candidate)) {
        throw "$FieldName '$PathValue' must be relative."
    }

    if ($candidate.Contains(':')) {
        throw "$FieldName '$PathValue' must not contain ':'. Device and ADS paths are forbidden."
    }

    $canonical = $candidate -replace '\\', '/'
    if ($canonical.StartsWith('//')) {
        throw "$FieldName '$PathValue' must not be a UNC/device path."
    }

    $segments = $canonical.Split('/')
    foreach ($segment in $segments) {
        if ([string]::IsNullOrWhiteSpace($segment)) {
            throw "$FieldName '$PathValue' contains an empty path segment."
        }

        if ($segment -eq '.') {
            throw "$FieldName '$PathValue' contains '.' which is not allowed."
        }

        if ($segment -eq '..') {
            throw "$FieldName '$PathValue' contains traversal segment '..'."
        }
    }

    return ($segments -join '/')
}

function Resolve-SafeChildPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,
        [Parameter(Mandatory = $true)]
        [string]$FieldName
    )

    $baseInfo = Get-PathInfo -BasePath $BasePath -FieldName $FieldName
    $normalized = Normalize-RelativePath -PathValue $RelativePath -FieldName $FieldName
    $relativeWindows = $normalized -replace '/', '\'
    $fullPath = [System.IO.Path]::GetFullPath((Join-Path $baseInfo.FullPath $relativeWindows))

    if (-not $fullPath.StartsWith($baseInfo.WithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$FieldName '$RelativePath' escapes the base path."
    }

    return [PSCustomObject]@{
        FullPath      = $fullPath
        RelativePath  = $normalized
        BaseFullPath  = $baseInfo.FullPath
        BaseWithSlash = $baseInfo.WithSeparator
    }
}

function Convert-ToRepoRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$RootPathInfo,
        [Parameter(Mandatory = $true)]
        [string]$FullPath
    )

    $resolved = [System.IO.Path]::GetFullPath($FullPath)
    if ($resolved.Equals($RootPathInfo.FullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        return '.'
    }

    if (-not $resolved.StartsWith($RootPathInfo.WithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path '$FullPath' escapes repository root '$($RootPathInfo.FullPath)'."
    }

    return ($resolved.Substring($RootPathInfo.WithSeparator.Length) -replace '\\', '/')
}

function Convert-ToStrictInt64 {
    param(
        [Parameter(Mandatory = $true)]
        $Value,
        [Parameter(Mandatory = $true)]
        [string]$FieldName,
        [switch]$AllowZero
    )

    if ($null -eq $Value) {
        throw "$FieldName must be an integer."
    }

    try {
        $converted = [Int64]$Value
    }
    catch {
        throw "$FieldName must be an integer."
    }

    if ([double]$Value -ne [double]$converted) {
        throw "$FieldName must be an integer."
    }

    if ($AllowZero) {
        if ($converted -lt 0) {
            throw "$FieldName must be greater than or equal to zero."
        }
    }
    else {
        if ($converted -le 0) {
            throw "$FieldName must be greater than zero."
        }
    }

    return $converted
}

function Normalize-Sha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,
        [Parameter(Mandatory = $true)]
        [string]$FieldName
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$FieldName must be a non-empty SHA-256 value."
    }

    if ($Value -notmatch '^[a-fA-F0-9]{64}$') {
        throw "$FieldName must be a 64-character hex SHA-256 value."
    }

    return $Value.ToUpperInvariant()
}

function Normalize-HostName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostValue,
        [Parameter(Mandatory = $true)]
        [string]$FieldName
    )

    if ([string]::IsNullOrWhiteSpace($HostValue)) {
        throw "$FieldName must be a non-empty host name."
    }

    $hostText = $HostValue.Trim().ToLowerInvariant()
    if ($hostText -notmatch '^[a-z0-9.-]+$') {
        throw "$FieldName '$HostValue' is not a valid host name."
    }

    if ($hostText.StartsWith('.') -or $hostText.EndsWith('.')) {
        throw "$FieldName '$HostValue' is not a valid host name."
    }

    if ($hostText.Contains('..')) {
        throw "$FieldName '$HostValue' is not a valid host name."
    }

    return $hostText
}

function Test-ExactVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    if ([string]::IsNullOrWhiteSpace($Version)) {
        return $false
    }

    $value = $Version.Trim()
    if ($value -match '(?i)\b(latest|stable|nightly|main|master|head)\b') {
        return $false
    }

    if ($value -match '[<>=~^|*]') {
        return $false
    }

    if ($value -match '\s') {
        return $false
    }

    if ($value -match '(^|[.\-])x($|[.\-])') {
        return $false
    }

    if ($value -notmatch '^[0-9]+(\.[0-9]+){0,3}([\-+][0-9A-Za-z.\-]+)?$') {
        return $false
    }

    return $true
}

function Assert-NoReparsePointsInTree {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath,
        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if (-not (Test-Path -LiteralPath $RootPath)) {
        throw "$Context path '$RootPath' was not found."
    }

    $rootItem = Get-Item -LiteralPath $RootPath -Force
    if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Context '$RootPath' is a reparse point and is not allowed."
    }

    $reparseNode = Get-ChildItem -LiteralPath $RootPath -Recurse -Force |
        Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 } |
        Select-Object -First 1
    if ($null -ne $reparseNode) {
        throw "$Context contains reparse point '$($reparseNode.FullName)', which is not allowed."
    }
}

function Assert-NoReparsePointsInExistingChain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,
        [Parameter(Mandatory = $true)]
        [string]$FieldName
    )

    $baseInfo = Get-PathInfo -BasePath $BasePath -FieldName $FieldName
    $targetFull = [System.IO.Path]::GetFullPath($TargetPath)

    if (-not (Test-Path -LiteralPath $baseInfo.FullPath)) {
        return
    }

    $baseItem = Get-Item -LiteralPath $baseInfo.FullPath -Force
    if (($baseItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$FieldName base path '$($baseInfo.FullPath)' is a reparse point."
    }

    if ($targetFull.Equals($baseInfo.FullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        return
    }

    if (-not $targetFull.StartsWith($baseInfo.WithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$FieldName target '$TargetPath' escapes base path '$($baseInfo.FullPath)'."
    }

    $relative = $targetFull.Substring($baseInfo.WithSeparator.Length)
    $segments = $relative.Split('\')
    $cursor = $baseInfo.FullPath

    foreach ($segment in $segments) {
        $cursor = Join-Path $cursor $segment
        if (-not (Test-Path -LiteralPath $cursor)) {
            break
        }

        $item = Get-Item -LiteralPath $cursor -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$FieldName path '$cursor' traverses a reparse point, which is forbidden."
        }
    }
}

function Assert-AuthenticodeSignature {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [psobject]$Requirement,
        [Parameter(Mandatory = $true)]
        [string]$ArtifactId
    )

    $extension = [System.IO.Path]::GetExtension($FilePath).ToLowerInvariant()
    if (-not ($script:AuthenticodeExtensions -contains $extension)) {
        throw "artifact '$ArtifactId' requests Authenticode requirements, but '$extension' is not a supported PE/MSI/PS1 extension."
    }

    $signature = Get-AuthenticodeSignature -FilePath $FilePath
    if ($null -eq $signature -or $signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
        throw "artifact '$ArtifactId' Authenticode signature is missing or invalid."
    }

    if ($null -ne $Requirement.Thumbprint) {
        $actualThumbprint = $signature.SignerCertificate.Thumbprint.ToUpperInvariant()
        if ($actualThumbprint -ne $Requirement.Thumbprint) {
            throw "artifact '$ArtifactId' Authenticode thumbprint mismatch."
        }
    }

    if ($null -ne $Requirement.Subject) {
        if (-not $signature.SignerCertificate.Subject.Equals($Requirement.Subject, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "artifact '$ArtifactId' Authenticode subject mismatch."
        }
    }
}

function Validate-HydrateManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath
    )

    $manifest = Read-JsonObject -ManifestPath $ManifestPath
    Assert-AllowedFields -InputObject $manifest -AllowedFields @('schemaVersion', 'officialHosts', 'artifacts') -Context 'Manifest'
    Assert-RequiredFields -InputObject $manifest -RequiredFields @('schemaVersion', 'officialHosts', 'artifacts') -Context 'Manifest'

    $schemaVersion = Convert-ToStrictInt64 -Value $manifest.schemaVersion -FieldName 'schemaVersion' -AllowZero
    if ($schemaVersion -ne 1) {
        throw "schemaVersion '$schemaVersion' is not supported. Expected value: 1."
    }

    if (-not ($manifest.officialHosts -is [System.Array])) {
        throw "officialHosts must be an array."
    }

    if (-not ($manifest.artifacts -is [System.Array])) {
        throw "artifacts must be an array."
    }

    if ($manifest.officialHosts.Count -eq 0) {
        throw "officialHosts must contain at least one host."
    }

    if ($manifest.artifacts.Count -eq 0) {
        throw "artifacts must contain at least one artifact."
    }

    $officialHosts = @()
    $officialHostLookup = @{}
    $hostIndex = 0
    foreach ($rawHost in $manifest.officialHosts) {
        $normalizedHost = Normalize-HostName -HostValue ([string]$rawHost) -FieldName ("officialHosts[{0}]" -f $hostIndex)
        if ($officialHostLookup.ContainsKey($normalizedHost)) {
            throw "officialHosts contains duplicate host '$normalizedHost'."
        }

        $officialHostLookup[$normalizedHost] = $true
        $officialHosts += $normalizedHost
        $hostIndex += 1
    }

    $idLookup = @{}
    $destinationLookup = @{}
    $validatedArtifacts = @()

    $artifactIndex = 0
    foreach ($artifact in $manifest.artifacts) {
        if ($artifact -is [System.Array]) {
            throw "artifacts[$artifactIndex] must be a JSON object."
        }

        $requiredFields = @('id', 'version', 'url', 'destination', 'size', 'sha256', 'license', 'trustTier', 'purpose', 'installPolicy', 'lifecycle')
        $allowedFields = $requiredFields + @('authenticode')
        Assert-AllowedFields -InputObject $artifact -AllowedFields $allowedFields -Context ("artifacts[{0}]" -f $artifactIndex)
        Assert-RequiredFields -InputObject $artifact -RequiredFields $requiredFields -Context ("artifacts[{0}]" -f $artifactIndex)

        $id = [string]$artifact.id
        if ([string]::IsNullOrWhiteSpace($id)) {
            throw "artifacts[$artifactIndex].id must be non-empty."
        }

        $idKey = $id.Trim().ToLowerInvariant()
        if ($idLookup.ContainsKey($idKey)) {
            throw "artifacts contains duplicate id '$id'."
        }
        $idLookup[$idKey] = $true

        $version = [string]$artifact.version
        if (-not (Test-ExactVersion -Version $version)) {
            throw "artifact '$id' must declare an exact version (no latest, wildcards, or ranges)."
        }
        $version = $version.Trim()

        $uri = $null
        if (-not [System.Uri]::TryCreate([string]$artifact.url, [System.UriKind]::Absolute, [ref]$uri)) {
            throw "artifact '$id' has an invalid URL."
        }

        if ($uri.Scheme -ne 'https') {
            throw "artifact '$id' URL must use HTTPS."
        }

        if (-not [string]::IsNullOrWhiteSpace($uri.UserInfo)) {
            throw "artifact '$id' URL must not include credentials."
        }

        $sourceHost = Normalize-HostName -HostValue $uri.Host -FieldName ("artifact '{0}' host" -f $id)
        if (-not $officialHostLookup.ContainsKey($sourceHost)) {
            throw "artifact '$id' host '$sourceHost' is not in officialHosts."
        }

        $destination = Normalize-RelativePath -PathValue ([string]$artifact.destination) -FieldName ("artifact '{0}' destination" -f $id)
        $destinationKey = $destination.ToLowerInvariant()

        if ($destinationLookup.ContainsKey($destinationKey)) {
            throw "artifacts contains duplicate destination '$destination'."
        }

        foreach ($existingKey in $destinationLookup.Keys) {
            if ($destinationKey.StartsWith("$existingKey/") -or $existingKey.StartsWith("$destinationKey/")) {
                throw "Destination collision between '$destination' and '$($destinationLookup[$existingKey])'."
            }
        }

        $destinationLookup[$destinationKey] = $destination

        $size = Convert-ToStrictInt64 -Value $artifact.size -FieldName ("artifact '{0}' size" -f $id)
        $sha256 = Normalize-Sha256 -Value ([string]$artifact.sha256) -FieldName ("artifact '{0}' sha256" -f $id)

        $license = [string]$artifact.license
        if ([string]::IsNullOrWhiteSpace($license)) {
            throw "artifact '$id' license must be declared."
        }
        $license = $license.Trim()
        if (-not ($script:AllowedLicenses -contains $license)) {
            throw "artifact '$id' license '$license' is not allowed."
        }

        $trustTier = [string]$artifact.trustTier
        if ([string]::IsNullOrWhiteSpace($trustTier)) {
            throw "artifact '$id' trustTier must be declared."
        }
        $trustTier = $trustTier.Trim()
        if (-not ($script:AllowedTrustTiers -contains $trustTier)) {
            throw "artifact '$id' trust tier '$trustTier' is not allowed."
        }

        $purpose = [string]$artifact.purpose
        if ([string]::IsNullOrWhiteSpace($purpose)) {
            throw "artifact '$id' purpose must be declared."
        }
        $purpose = $purpose.Trim()

        $installPolicy = [string]$artifact.installPolicy
        if ([string]::IsNullOrWhiteSpace($installPolicy)) {
            throw "artifact '$id' installPolicy must be declared."
        }
        $installPolicy = $installPolicy.Trim()
        if (-not ($script:AllowedInstallPolicies -contains $installPolicy)) {
            throw "artifact '$id' install policy '$installPolicy' is not allowed."
        }

        $lifecycle = [string]$artifact.lifecycle
        if ([string]::IsNullOrWhiteSpace($lifecycle)) {
            throw "artifact '$id' lifecycle must be declared."
        }
        $lifecycle = $lifecycle.Trim()
        if (-not ($script:AllowedLifecyclePolicies -contains $lifecycle)) {
            throw "artifact '$id' lifecycle '$lifecycle' is not allowed."
        }

        $authenticode = $null
        $authenticodeField = $artifact.PSObject.Properties['authenticode']
        if ($null -ne $authenticodeField -and $null -ne $artifact.authenticode) {
            if ($artifact.authenticode -is [System.Array]) {
                throw "artifact '$id' authenticode must be an object."
            }

            Assert-AllowedFields -InputObject $artifact.authenticode -AllowedFields @('thumbprint', 'subject') -Context ("artifact '{0}'.authenticode" -f $id)

            $thumbprint = $null
            $subject = $null

            $thumbprintField = $artifact.authenticode.PSObject.Properties['thumbprint']
            if ($null -ne $thumbprintField -and -not [string]::IsNullOrWhiteSpace([string]$artifact.authenticode.thumbprint)) {
                $thumbprintText = ([string]$artifact.authenticode.thumbprint).Trim().ToUpperInvariant()
                if ($thumbprintText -notmatch '^[A-F0-9]{40}$') {
                    throw "artifact '$id' authenticode.thumbprint must be a 40-character hex SHA-1 thumbprint."
                }
                $thumbprint = $thumbprintText
            }

            $subjectField = $artifact.authenticode.PSObject.Properties['subject']
            if ($null -ne $subjectField -and -not [string]::IsNullOrWhiteSpace([string]$artifact.authenticode.subject)) {
                $subject = ([string]$artifact.authenticode.subject).Trim()
            }

            if ($null -eq $thumbprint -and $null -eq $subject) {
                throw "artifact '$id' authenticode must declare thumbprint and/or subject."
            }

            $authenticode = [PSCustomObject]@{
                Thumbprint = $thumbprint
                Subject    = $subject
            }
        }

        $validatedArtifacts += [PSCustomObject]@{
            Index         = $artifactIndex
            Id            = $id.Trim()
            Version       = $version
            Url           = $uri.AbsoluteUri
            SourceHost    = $sourceHost
            Destination   = $destination
            Size          = $size
            Sha256        = $sha256
            License       = $license
            TrustTier     = $trustTier
            Purpose       = $purpose
            InstallPolicy = $installPolicy
            Lifecycle     = $lifecycle
            Authenticode  = $authenticode
        }

        $artifactIndex += 1
    }

    return [PSCustomObject]@{
        ManifestPath       = (Resolve-Path -LiteralPath $ManifestPath).Path
        SchemaVersion      = $schemaVersion
        OfficialHosts      = $officialHosts
        OfficialHostLookup = $officialHostLookup
        Artifacts          = $validatedArtifacts
    }
}

function Invoke-AuditManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath
    )

    $validated = Validate-HydrateManifest -ManifestPath $ManifestPath
    return [PSCustomObject]@{
        ManifestPath = $validated.ManifestPath
        ArtifactCount = $validated.Artifacts.Count
        OfficialHosts = $validated.OfficialHosts
    }
}

function Invoke-VerifySource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $repoInfo = Get-PathInfo -BasePath $RepoRoot -FieldName 'RepoRoot'
    if (-not (Test-Path -LiteralPath $repoInfo.FullPath -PathType Container)) {
        throw "RepoRoot '$RepoRoot' was not found."
    }

    $manifest = Read-JsonObject -ManifestPath $ManifestPath
    Assert-AllowedFields -InputObject $manifest -AllowedFields @('schemaVersion', 'scopeRoot', 'files') -Context 'VerifySource manifest'
    Assert-RequiredFields -InputObject $manifest -RequiredFields @('schemaVersion', 'scopeRoot', 'files') -Context 'VerifySource manifest'

    $schemaVersion = Convert-ToStrictInt64 -Value $manifest.schemaVersion -FieldName 'schemaVersion' -AllowZero
    if ($schemaVersion -ne 1) {
        throw "schemaVersion '$schemaVersion' is not supported. Expected value: 1."
    }

    if (-not ($manifest.files -is [System.Array])) {
        throw "VerifySource manifest field 'files' must be an array."
    }

    if ($manifest.files.Count -eq 0) {
        throw "VerifySource manifest field 'files' must contain at least one file."
    }

    $scopeRoot = Resolve-SafeChildPath -BasePath $repoInfo.FullPath -RelativePath ([string]$manifest.scopeRoot) -FieldName 'scopeRoot'
    if (-not (Test-Path -LiteralPath $scopeRoot.FullPath -PathType Container)) {
        throw "scopeRoot '$($scopeRoot.RelativePath)' was not found under RepoRoot."
    }

    Assert-NoReparsePointsInTree -RootPath $scopeRoot.FullPath -Context 'scopeRoot'
    $scopeInfo = Get-PathInfo -BasePath $scopeRoot.FullPath -FieldName 'scopeRoot'

    $expectedByKey = @{}
    $index = 0
    foreach ($fileEntry in $manifest.files) {
        if ($fileEntry -is [System.Array]) {
            throw "files[$index] must be a JSON object."
        }

        Assert-AllowedFields -InputObject $fileEntry -AllowedFields @('path', 'size', 'sha256') -Context ("files[{0}]" -f $index)
        Assert-RequiredFields -InputObject $fileEntry -RequiredFields @('path', 'size', 'sha256') -Context ("files[{0}]" -f $index)

        $resolvedFile = Resolve-SafeChildPath -BasePath $repoInfo.FullPath -RelativePath ([string]$fileEntry.path) -FieldName ("files[{0}].path" -f $index)
        $isInScope = $resolvedFile.FullPath.Equals($scopeInfo.FullPath, [System.StringComparison]::OrdinalIgnoreCase) -or
            $resolvedFile.FullPath.StartsWith($scopeInfo.WithSeparator, [System.StringComparison]::OrdinalIgnoreCase)
        if (-not $isInScope) {
            throw "files[$index].path '$($resolvedFile.RelativePath)' is outside scopeRoot '$($scopeRoot.RelativePath)'."
        }

        $key = $resolvedFile.RelativePath.ToLowerInvariant()
        if ($expectedByKey.ContainsKey($key)) {
            throw "VerifySource manifest contains duplicate path '$($resolvedFile.RelativePath)'."
        }

        $size = Convert-ToStrictInt64 -Value $fileEntry.size -FieldName ("files[{0}].size" -f $index) -AllowZero
        $sha256 = Normalize-Sha256 -Value ([string]$fileEntry.sha256) -FieldName ("files[{0}].sha256" -f $index)

        $expectedByKey[$key] = [PSCustomObject]@{
            Path   = $resolvedFile.RelativePath
            Size   = $size
            Sha256 = $sha256
        }

        $index += 1
    }

    $actualByKey = @{}
    foreach ($file in (Get-ChildItem -LiteralPath $scopeInfo.FullPath -File -Recurse -Force)) {
        if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "scopeRoot contains reparse point '$($file.FullName)'."
        }

        $relativePath = Convert-ToRepoRelativePath -RootPathInfo $repoInfo -FullPath $file.FullName
        $actualByKey[$relativePath.ToLowerInvariant()] = [PSCustomObject]@{
            Path     = $relativePath
            FullPath = $file.FullName
            Size     = [Int64]$file.Length
        }
    }

    $issues = New-Object System.Collections.Generic.List[string]

    foreach ($expectedKey in ($expectedByKey.Keys | Sort-Object)) {
        if (-not $actualByKey.ContainsKey($expectedKey)) {
            $issues.Add("Missing file '$($expectedByKey[$expectedKey].Path)'.")
            continue
        }

        $expected = $expectedByKey[$expectedKey]
        $actual = $actualByKey[$expectedKey]
        if ($actual.Size -ne $expected.Size) {
            $issues.Add(("size mismatch for '{0}': expected {1}, got {2}." -f $expected.Path, $expected.Size, $actual.Size))
            continue
        }

        $actualHash = (Get-FileHash -LiteralPath $actual.FullPath -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($actualHash -ne $expected.Sha256) {
            $issues.Add(("hash mismatch for '{0}': expected {1}, got {2}." -f $expected.Path, $expected.Sha256, $actualHash))
        }
    }

    foreach ($actualKey in ($actualByKey.Keys | Sort-Object)) {
        if (-not $expectedByKey.ContainsKey($actualKey)) {
            $issues.Add("Unexpected file '$($actualByKey[$actualKey].Path)'.")
        }
    }

    if ($issues.Count -gt 0) {
        throw ("VerifySource manifest mismatch:`n - " + [string]::Join("`n - ", $issues))
    }

    return [PSCustomObject]@{
        ScopeRoot = $scopeRoot.RelativePath
        FileCount = $expectedByKey.Count
    }
}

function Invoke-Hydrate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,
        [Parameter(Mandatory = $true)]
        [string]$StagingDirectory,
        [string]$ReceiptPath = 'hydrate-receipt.json'
    )

    if ([string]::IsNullOrWhiteSpace($ReceiptPath)) {
        throw "ReceiptPath must be a non-empty relative path."
    }

    $validated = Validate-HydrateManifest -ManifestPath $ManifestPath

    if (-not (Test-Path -LiteralPath $StagingDirectory)) {
        [System.IO.Directory]::CreateDirectory($StagingDirectory) | Out-Null
    }

    $stagingInfo = Get-PathInfo -BasePath $StagingDirectory -FieldName 'StagingDirectory'
    if (-not (Test-Path -LiteralPath $stagingInfo.FullPath -PathType Container)) {
        throw "StagingDirectory '$StagingDirectory' is not a directory."
    }

    Assert-NoReparsePointsInExistingChain -BasePath $stagingInfo.FullPath -TargetPath $stagingInfo.FullPath -FieldName 'StagingDirectory'

    $planned = @()
    $destinationLookup = @{}
    foreach ($artifact in $validated.Artifacts) {
        $destination = Resolve-SafeChildPath -BasePath $stagingInfo.FullPath -RelativePath $artifact.Destination -FieldName ("artifact '{0}' destination" -f $artifact.Id)
        $destinationKey = $destination.RelativePath.ToLowerInvariant()

        if ($destinationLookup.ContainsKey($destinationKey)) {
            throw "artifacts contains duplicate destination '$($destination.RelativePath)'."
        }

        foreach ($existingKey in $destinationLookup.Keys) {
            if ($destinationKey.StartsWith("$existingKey/") -or $existingKey.StartsWith("$destinationKey/")) {
                throw "Destination collision between '$($destination.RelativePath)' and '$($destinationLookup[$existingKey])'."
            }
        }

        $destinationLookup[$destinationKey] = $destination.RelativePath
        $planned += [PSCustomObject]@{
            Artifact    = $artifact
            Destination = $destination
        }
    }

    $receiptLocation = Resolve-SafeChildPath -BasePath $stagingInfo.FullPath -RelativePath $ReceiptPath -FieldName 'ReceiptPath'
    if ($destinationLookup.ContainsKey($receiptLocation.RelativePath.ToLowerInvariant())) {
        throw "ReceiptPath '$($receiptLocation.RelativePath)' collides with an artifact destination."
    }

    $receiptRecords = @()
    foreach ($item in $planned) {
        $artifact = $item.Artifact
        $destination = $item.Destination
        $destinationDirectory = Split-Path -Parent $destination.FullPath

        Assert-NoReparsePointsInExistingChain -BasePath $stagingInfo.FullPath -TargetPath $destinationDirectory -FieldName ("artifact '{0}' destination" -f $artifact.Id)

        if (-not (Test-Path -LiteralPath $destinationDirectory)) {
            [System.IO.Directory]::CreateDirectory($destinationDirectory) | Out-Null
        }

        $directoryItem = Get-Item -LiteralPath $destinationDirectory -Force
        if (($directoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "artifact '$($artifact.Id)' destination directory '$destinationDirectory' is a reparse point."
        }

        if (Test-Path -LiteralPath $destination.FullPath) {
            throw "Destination collision: '$($destination.RelativePath)' already exists."
        }

        $tempFile = Join-Path $destinationDirectory ("{0}.tmp.{1}" -f ([System.IO.Path]::GetFileName($destination.FullPath)), ([Guid]::NewGuid().ToString('N')))
        try {
            $response = Invoke-WebRequest -Uri $artifact.Url -OutFile $tempFile -UseBasicParsing -MaximumRedirection 5 -PassThru
            if ($null -eq $response -or $null -eq $response.BaseResponse -or $null -eq $response.BaseResponse.ResponseUri) {
                throw "artifact '$($artifact.Id)' download response did not provide a final URI."
            }

            $resolvedUri = $response.BaseResponse.ResponseUri
            if ($resolvedUri.Scheme -ne 'https') {
                throw "artifact '$($artifact.Id)' resolved URL must remain HTTPS."
            }

            $resolvedHost = Normalize-HostName -HostValue $resolvedUri.Host -FieldName ("artifact '{0}' resolved host" -f $artifact.Id)
            if ($resolvedHost -ne $artifact.SourceHost) {
                throw "artifact '$($artifact.Id)' redirected to host '$resolvedHost', expected '$($artifact.SourceHost)'. Cross-host redirects are forbidden."
            }

            if (-not $validated.OfficialHostLookup.ContainsKey($resolvedHost)) {
                throw "artifact '$($artifact.Id)' resolved host '$resolvedHost' is not official."
            }

            $fileLength = (Get-Item -LiteralPath $tempFile -Force).Length
            if ($fileLength -ne $artifact.Size) {
                throw "artifact '$($artifact.Id)' size mismatch: expected $($artifact.Size), got $fileLength."
            }

            $actualSha256 = (Get-FileHash -LiteralPath $tempFile -Algorithm SHA256).Hash.ToUpperInvariant()
            if ($actualSha256 -ne $artifact.Sha256) {
                throw "artifact '$($artifact.Id)' hash mismatch: expected $($artifact.Sha256), got $actualSha256."
            }

            if ($null -ne $artifact.Authenticode) {
                Assert-AuthenticodeSignature -FilePath $tempFile -Requirement $artifact.Authenticode -ArtifactId $artifact.Id
            }

            [System.IO.File]::Move($tempFile, $destination.FullPath)

            $receiptRecords += [PSCustomObject]@{
                id              = $artifact.Id
                version         = $artifact.Version
                sourceUrl       = $artifact.Url
                resolvedUrl     = $resolvedUri.AbsoluteUri
                destination     = $destination.RelativePath
                size            = $fileLength
                sha256          = $actualSha256
                downloadedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
            }
        }
        finally {
            if (Test-Path -LiteralPath $tempFile) {
                Remove-Item -LiteralPath $tempFile -Force
            }
        }
    }

    $receiptDirectory = Split-Path -Parent $receiptLocation.FullPath
    if (-not (Test-Path -LiteralPath $receiptDirectory)) {
        [System.IO.Directory]::CreateDirectory($receiptDirectory) | Out-Null
    }

    $receiptPayload = [PSCustomObject]@{
        schemaVersion    = 1
        manifestPath     = $validated.ManifestPath
        generatedAtUtc   = (Get-Date).ToUniversalTime().ToString('o')
        stagingDirectory = $stagingInfo.FullPath
        artifacts        = $receiptRecords
    }

    Set-Content -LiteralPath $receiptLocation.FullPath -Value (ConvertTo-Json -InputObject $receiptPayload -Depth 8) -Encoding UTF8

    return [PSCustomObject]@{
        ReceiptPath  = $receiptLocation.FullPath
        ArtifactCount = $receiptRecords.Count
    }
}

Export-ModuleMember -Function Invoke-VerifySource, Invoke-Hydrate, Invoke-AuditManifest

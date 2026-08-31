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

function Throw-BuildError {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [System.Management.Automation.ErrorCategory]$Category = [System.Management.Automation.ErrorCategory]::InvalidData
    )

    $exception = New-Object System.InvalidOperationException($Message)
    $record = New-Object System.Management.Automation.ErrorRecord($exception, $Id, $Category, $null)
    throw $record
}

function New-CaseInsensitiveDictionary {
    return New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
}

function Get-OrdinalPathKey {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    return ($RelativePath -replace '\\', '/').ToUpperInvariant()
}

function Test-RelativePathPrefixCollision {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LeftPath,
        [Parameter(Mandatory = $true)]
        [string]$RightPath
    )

    $leftKey = Get-OrdinalPathKey -RelativePath $LeftPath
    $rightKey = Get-OrdinalPathKey -RelativePath $RightPath

    return $leftKey.StartsWith("$rightKey/", [System.StringComparison]::Ordinal) -or
        $rightKey.StartsWith("$leftKey/", [System.StringComparison]::Ordinal)
}

function Read-JsonObject {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath
    )

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        Throw-BuildError -Id 'Build.Manifest.NotFound' -Message "Manifest file '$ManifestPath' was not found." -Category ObjectNotFound
    }

    $raw = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) {
        Throw-BuildError -Id 'Build.Manifest.Empty' -Message "Manifest file '$ManifestPath' is empty."
    }

    $parsed = ConvertFrom-Json -InputObject $raw
    if ($parsed -is [System.Array]) {
        Throw-BuildError -Id 'Build.Manifest.ExpectedObject' -Message "Manifest file '$ManifestPath' must be a JSON object."
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
        [string]$Context,
        [string]$ErrorId = 'Build.Manifest.UnknownField'
    )

    $allowedLookup = New-CaseInsensitiveDictionary
    foreach ($name in $AllowedFields) {
        if (-not $allowedLookup.ContainsKey($name)) {
            $allowedLookup.Add($name, $true)
        }
    }

    foreach ($property in $InputObject.PSObject.Properties) {
        if (-not $allowedLookup.ContainsKey($property.Name)) {
            Throw-BuildError -Id $ErrorId -Message "$Context contains unknown field '$($property.Name)'."
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
        [string]$Context,
        [string]$MissingFieldErrorId = 'Build.Manifest.MissingField',
        [string]$NullFieldErrorId = 'Build.Manifest.NullField'
    )

    foreach ($name in $RequiredFields) {
        $property = $InputObject.PSObject.Properties[$name]
        if ($null -eq $property) {
            Throw-BuildError -Id $MissingFieldErrorId -Message "$Context is missing required field '$name'."
        }

        if ($null -eq $property.Value) {
            Throw-BuildError -Id $NullFieldErrorId -Message "$Context field '$name' must not be null."
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
        Throw-BuildError -Id 'Build.Path.Empty' -Message "$FieldName must be provided."
    }

    $fullPath = [System.IO.Path]::GetFullPath($BasePath)
    $withSeparator = if ($fullPath.EndsWith('\')) { $fullPath } else { "$fullPath\" }

    return [PSCustomObject]@{
        FullPath      = $fullPath
        WithSeparator = $withSeparator
    }
}

function Assert-PathSegmentsAreNfc {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue,
        [Parameter(Mandatory = $true)]
        [string]$FieldName
    )

    $canonical = $PathValue -replace '\\', '/'
    $segments = $canonical.Split('/')

    foreach ($segment in $segments) {
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }

        if (-not $segment.IsNormalized([System.Text.NormalizationForm]::FormC)) {
            Throw-BuildError -Id 'Build.Path.NonNfcComponent' -Message "$FieldName '$PathValue' contains non-NFC path component '$segment'."
        }
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
        Throw-BuildError -Id 'Build.Path.Empty' -Message "$FieldName must be a non-empty relative path."
    }

    $candidate = $PathValue.Trim()
    if ($candidate.StartsWith('\\') -or $candidate.StartsWith('/')) {
        Throw-BuildError -Id 'Build.Path.AbsoluteOrUnc' -Message "$FieldName '$PathValue' must not start with UNC or absolute separators."
    }

    if ([System.IO.Path]::IsPathRooted($candidate)) {
        Throw-BuildError -Id 'Build.Path.AbsoluteOrUnc' -Message "$FieldName '$PathValue' must be relative."
    }

    if ($candidate.Contains(':')) {
        Throw-BuildError -Id 'Build.Path.DeviceOrAds' -Message "$FieldName '$PathValue' must not contain ':'. Device and ADS paths are forbidden."
    }

    $canonical = $candidate -replace '\\', '/'
    if ($canonical.StartsWith('//')) {
        Throw-BuildError -Id 'Build.Path.AbsoluteOrUnc' -Message "$FieldName '$PathValue' must not be a UNC/device path."
    }

    $segments = $canonical.Split('/')
    foreach ($segment in $segments) {
        if ([string]::IsNullOrWhiteSpace($segment)) {
            Throw-BuildError -Id 'Build.Path.EmptySegment' -Message "$FieldName '$PathValue' contains an empty path segment."
        }

        if ($segment -eq '.') {
            Throw-BuildError -Id 'Build.Path.DotSegment' -Message "$FieldName '$PathValue' contains '.' which is not allowed."
        }

        if ($segment -eq '..') {
            Throw-BuildError -Id 'Build.Path.Traversal' -Message "$FieldName '$PathValue' contains traversal segment '..'."
        }
    }

    Assert-PathSegmentsAreNfc -PathValue $canonical -FieldName $FieldName
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
        Throw-BuildError -Id 'Build.Path.EscapesBase' -Message "$FieldName '$RelativePath' escapes the base path."
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
        Throw-BuildError -Id 'Build.Path.EscapesBase' -Message "Path '$FullPath' escapes repository root '$($RootPathInfo.FullPath)'."
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
        Throw-BuildError -Id 'Build.Manifest.InvalidInteger' -Message "$FieldName must be an integer."
    }

    try {
        $converted = [Int64]$Value
    }
    catch {
        Throw-BuildError -Id 'Build.Manifest.InvalidInteger' -Message "$FieldName must be an integer."
    }

    if ([double]$Value -ne [double]$converted) {
        Throw-BuildError -Id 'Build.Manifest.InvalidInteger' -Message "$FieldName must be an integer."
    }

    if ($AllowZero) {
        if ($converted -lt 0) {
            Throw-BuildError -Id 'Build.Manifest.InvalidIntegerRange' -Message "$FieldName must be greater than or equal to zero."
        }
    }
    else {
        if ($converted -le 0) {
            Throw-BuildError -Id 'Build.Manifest.InvalidIntegerRange' -Message "$FieldName must be greater than zero."
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
        Throw-BuildError -Id 'Build.Manifest.InvalidSha256' -Message "$FieldName must be a non-empty SHA-256 value."
    }

    if ($Value -notmatch '^[a-fA-F0-9]{64}$') {
        Throw-BuildError -Id 'Build.Manifest.InvalidSha256' -Message "$FieldName must be a 64-character hex SHA-256 value."
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
        Throw-BuildError -Id 'Build.Manifest.InvalidHost' -Message "$FieldName must be a non-empty host name."
    }

    $hostText = $HostValue.Trim().ToLowerInvariant()
    if ($hostText -notmatch '^[a-z0-9.-]+$') {
        Throw-BuildError -Id 'Build.Manifest.InvalidHost' -Message "$FieldName '$HostValue' is not a valid host name."
    }

    if ($hostText.StartsWith('.') -or $hostText.EndsWith('.')) {
        Throw-BuildError -Id 'Build.Manifest.InvalidHost' -Message "$FieldName '$HostValue' is not a valid host name."
    }

    if ($hostText.Contains('..')) {
        Throw-BuildError -Id 'Build.Manifest.InvalidHost' -Message "$FieldName '$HostValue' is not a valid host name."
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
        [string]$Context,
        [string]$ErrorId = 'Build.Path.ReparsePoint'
    )

    if (-not (Test-Path -LiteralPath $RootPath)) {
        Throw-BuildError -Id $ErrorId -Message "$Context path '$RootPath' was not found." -Category ObjectNotFound
    }

    $rootItem = Get-Item -LiteralPath $RootPath -Force
    if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-BuildError -Id $ErrorId -Message "$Context '$RootPath' is a reparse point and is not allowed."
    }

    $reparseNode = Get-ChildItem -LiteralPath $RootPath -Recurse -Force |
        Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 } |
        Select-Object -First 1

    if ($null -ne $reparseNode) {
        Throw-BuildError -Id $ErrorId -Message "$Context contains reparse point '$($reparseNode.FullName)', which is not allowed."
    }
}

function Assert-NoReparsePointsInExistingChain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,
        [Parameter(Mandatory = $true)]
        [string]$FieldName,
        [string]$ErrorId = 'Build.Path.ReparsePoint'
    )

    $baseInfo = Get-PathInfo -BasePath $BasePath -FieldName $FieldName
    $targetFull = [System.IO.Path]::GetFullPath($TargetPath)

    if (-not (Test-Path -LiteralPath $baseInfo.FullPath)) {
        return
    }

    $baseItem = Get-Item -LiteralPath $baseInfo.FullPath -Force
    if (($baseItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-BuildError -Id $ErrorId -Message "$FieldName base path '$($baseInfo.FullPath)' is a reparse point."
    }

    if ($targetFull.Equals($baseInfo.FullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        return
    }

    if (-not $targetFull.StartsWith($baseInfo.WithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
        Throw-BuildError -Id 'Build.Path.EscapesBase' -Message "$FieldName target '$TargetPath' escapes base path '$($baseInfo.FullPath)'."
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
            Throw-BuildError -Id $ErrorId -Message "$FieldName path '$cursor' traverses a reparse point, which is forbidden."
        }
    }
}

function Assert-AuthenticodeSignature {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string]$DeclaredExtension,
        [Parameter(Mandatory = $true)]
        [psobject]$Requirement,
        [Parameter(Mandatory = $true)]
        [string]$ArtifactId
    )

    $extension = $DeclaredExtension.Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($extension)) {
        Throw-BuildError -Id 'Build.Authenticode.MissingDestinationExtension' -Message "artifact '$ArtifactId' Authenticode validation requires a destination extension."
    }

    if (-not ($script:AuthenticodeExtensions -contains $extension)) {
        Throw-BuildError -Id 'Build.Authenticode.UnsupportedDestinationExtension' -Message "artifact '$ArtifactId' destination extension '$extension' is not supported for Authenticode validation."
    }

    $signature = Get-AuthenticodeSignature -FilePath $FilePath
    if ($null -eq $signature -or $signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
        Throw-BuildError -Id 'Build.Authenticode.InvalidSignature' -Message "artifact '$ArtifactId' Authenticode signature is missing or invalid."
    }

    if ($null -ne $Requirement.Thumbprint) {
        $actualThumbprint = $signature.SignerCertificate.Thumbprint.ToUpperInvariant()
        if ($actualThumbprint -ne $Requirement.Thumbprint) {
            Throw-BuildError -Id 'Build.Authenticode.ThumbprintMismatch' -Message "artifact '$ArtifactId' Authenticode thumbprint mismatch."
        }
    }

    if ($null -ne $Requirement.Subject) {
        if (-not $signature.SignerCertificate.Subject.Equals($Requirement.Subject, [System.StringComparison]::OrdinalIgnoreCase)) {
            Throw-BuildError -Id 'Build.Authenticode.SubjectMismatch' -Message "artifact '$ArtifactId' Authenticode subject mismatch."
        }
    }
}

function Invoke-ArtifactDownload {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Artifact,
        [Parameter(Mandatory = $true)]
        [string]$TempFilePath,
        [scriptblock]$Downloader
    )

    if ($null -eq $Downloader) {
        $response = Invoke-WebRequest -Uri $Artifact.Url -OutFile $TempFilePath -UseBasicParsing -MaximumRedirection 5 -PassThru
        if ($null -eq $response -or $null -eq $response.BaseResponse -or $null -eq $response.BaseResponse.ResponseUri) {
            Throw-BuildError -Id 'Build.Hydrate.MissingResponseUri' -Message "artifact '$($Artifact.Id)' download response did not provide a final URI."
        }

        return $response.BaseResponse.ResponseUri
    }

    $downloadResult = & $Downloader $Artifact $TempFilePath
    if (-not (Test-Path -LiteralPath $TempFilePath -PathType Leaf)) {
        Throw-BuildError -Id 'Build.Hydrate.DownloaderMissingFile' -Message "artifact '$($Artifact.Id)' downloader did not create output file '$TempFilePath'."
    }

    if ($null -eq $downloadResult -or $null -eq $downloadResult.ResponseUri) {
        Throw-BuildError -Id 'Build.Hydrate.MissingResponseUri' -Message "artifact '$($Artifact.Id)' downloader did not return ResponseUri."
    }

    if ($downloadResult.ResponseUri -is [System.Uri]) {
        return $downloadResult.ResponseUri
    }

    $resolvedUri = $null
    if (-not [System.Uri]::TryCreate([string]$downloadResult.ResponseUri, [System.UriKind]::Absolute, [ref]$resolvedUri)) {
        Throw-BuildError -Id 'Build.Hydrate.InvalidResponseUri' -Message "artifact '$($Artifact.Id)' downloader returned an invalid ResponseUri."
    }

    return $resolvedUri
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
        Throw-BuildError -Id 'Build.Manifest.UnsupportedSchemaVersion' -Message "schemaVersion '$schemaVersion' is not supported. Expected value: 1."
    }

    if (-not ($manifest.officialHosts -is [System.Array])) {
        Throw-BuildError -Id 'Build.Manifest.InvalidOfficialHosts' -Message "officialHosts must be an array."
    }

    if (-not ($manifest.artifacts -is [System.Array])) {
        Throw-BuildError -Id 'Build.Manifest.InvalidArtifacts' -Message "artifacts must be an array."
    }

    if ($manifest.officialHosts.Count -eq 0) {
        Throw-BuildError -Id 'Build.Manifest.EmptyOfficialHosts' -Message "officialHosts must contain at least one host."
    }

    if ($manifest.artifacts.Count -eq 0) {
        Throw-BuildError -Id 'Build.Manifest.EmptyArtifacts' -Message "artifacts must contain at least one artifact."
    }

    $officialHostLookup = New-CaseInsensitiveDictionary
    $officialHosts = New-Object System.Collections.Generic.List[string]
    $hostIndex = 0
    foreach ($rawHost in $manifest.officialHosts) {
        $normalizedHost = Normalize-HostName -HostValue ([string]$rawHost) -FieldName ("officialHosts[{0}]" -f $hostIndex)
        if ($officialHostLookup.ContainsKey($normalizedHost)) {
            Throw-BuildError -Id 'Build.Manifest.DuplicateOfficialHost' -Message "officialHosts contains duplicate host '$normalizedHost'."
        }

        $officialHostLookup.Add($normalizedHost, $true)
        $officialHosts.Add($normalizedHost) | Out-Null
        $hostIndex += 1
    }

    $idLookup = New-CaseInsensitiveDictionary
    $destinationLookup = New-CaseInsensitiveDictionary
    $validatedArtifacts = New-Object System.Collections.Generic.List[object]

    $artifactIndex = 0
    foreach ($artifact in $manifest.artifacts) {
        if ($artifact -is [System.Array]) {
            Throw-BuildError -Id 'Build.Manifest.InvalidArtifactObject' -Message "artifacts[$artifactIndex] must be a JSON object."
        }

        $requiredFields = @('id', 'version', 'url', 'destination', 'size', 'sha256', 'license', 'trustTier', 'purpose', 'installPolicy', 'lifecycle')
        $allowedFields = $requiredFields + @('authenticode')
        Assert-AllowedFields -InputObject $artifact -AllowedFields $allowedFields -Context ("artifacts[{0}]" -f $artifactIndex)
        Assert-RequiredFields -InputObject $artifact -RequiredFields $requiredFields -Context ("artifacts[{0}]" -f $artifactIndex)

        $id = [string]$artifact.id
        if ([string]::IsNullOrWhiteSpace($id)) {
            Throw-BuildError -Id 'Build.Manifest.EmptyId' -Message "artifacts[$artifactIndex].id must be non-empty."
        }

        $id = $id.Trim()
        if ($idLookup.ContainsKey($id)) {
            Throw-BuildError -Id 'Build.Manifest.DuplicateId' -Message "artifacts contains duplicate id '$id'."
        }
        $idLookup.Add($id, $true)

        $version = [string]$artifact.version
        if (-not (Test-ExactVersion -Version $version)) {
            Throw-BuildError -Id 'Build.Manifest.NonExactVersion' -Message "artifact '$id' must declare an exact version (no latest, wildcards, or ranges)."
        }
        $version = $version.Trim()

        $uri = $null
        if (-not [System.Uri]::TryCreate([string]$artifact.url, [System.UriKind]::Absolute, [ref]$uri)) {
            Throw-BuildError -Id 'Build.Manifest.InvalidUrl' -Message "artifact '$id' has an invalid URL."
        }

        if ($uri.Scheme -ne 'https') {
            Throw-BuildError -Id 'Build.Manifest.NonHttpsUrl' -Message "artifact '$id' URL must use HTTPS."
        }

        if (-not [string]::IsNullOrWhiteSpace($uri.UserInfo)) {
            Throw-BuildError -Id 'Build.Manifest.UrlCredentialsForbidden' -Message "artifact '$id' URL must not include credentials."
        }

        $sourceHost = Normalize-HostName -HostValue $uri.Host -FieldName ("artifact '{0}' host" -f $id)
        if (-not $officialHostLookup.ContainsKey($sourceHost)) {
            Throw-BuildError -Id 'Build.Manifest.HostNotOfficial' -Message "artifact '$id' host '$sourceHost' is not in officialHosts."
        }

        $destination = Normalize-RelativePath -PathValue ([string]$artifact.destination) -FieldName ("artifact '{0}' destination" -f $id)
        if ($destinationLookup.ContainsKey($destination)) {
            Throw-BuildError -Id 'Build.Manifest.DuplicateDestination' -Message "artifacts contains duplicate destination '$destination'."
        }

        foreach ($existingDestination in $destinationLookup.Values) {
            if (Test-RelativePathPrefixCollision -LeftPath $destination -RightPath ([string]$existingDestination)) {
                Throw-BuildError -Id 'Build.Manifest.DestinationPrefixCollision' -Message "Destination collision between '$destination' and '$existingDestination'."
            }
        }

        $destinationLookup.Add($destination, $destination)

        $size = Convert-ToStrictInt64 -Value $artifact.size -FieldName ("artifact '{0}' size" -f $id)
        $sha256 = Normalize-Sha256 -Value ([string]$artifact.sha256) -FieldName ("artifact '{0}' sha256" -f $id)

        $license = [string]$artifact.license
        if ([string]::IsNullOrWhiteSpace($license)) {
            Throw-BuildError -Id 'Build.Manifest.MissingLicense' -Message "artifact '$id' license must be declared."
        }
        $license = $license.Trim()
        if (-not ($script:AllowedLicenses -contains $license)) {
            Throw-BuildError -Id 'Build.Manifest.ForbiddenLicense' -Message "artifact '$id' license '$license' is not allowed."
        }

        $trustTier = [string]$artifact.trustTier
        if ([string]::IsNullOrWhiteSpace($trustTier)) {
            Throw-BuildError -Id 'Build.Manifest.MissingTrustTier' -Message "artifact '$id' trustTier must be declared."
        }
        $trustTier = $trustTier.Trim()
        if (-not ($script:AllowedTrustTiers -contains $trustTier)) {
            Throw-BuildError -Id 'Build.Manifest.ForbiddenTrustTier' -Message "artifact '$id' trust tier '$trustTier' is not allowed."
        }

        $purpose = [string]$artifact.purpose
        if ([string]::IsNullOrWhiteSpace($purpose)) {
            Throw-BuildError -Id 'Build.Manifest.MissingPurpose' -Message "artifact '$id' purpose must be declared."
        }
        $purpose = $purpose.Trim()

        $installPolicy = [string]$artifact.installPolicy
        if ([string]::IsNullOrWhiteSpace($installPolicy)) {
            Throw-BuildError -Id 'Build.Manifest.MissingInstallPolicy' -Message "artifact '$id' installPolicy must be declared."
        }
        $installPolicy = $installPolicy.Trim()
        if (-not ($script:AllowedInstallPolicies -contains $installPolicy)) {
            Throw-BuildError -Id 'Build.Manifest.ForbiddenInstallPolicy' -Message "artifact '$id' install policy '$installPolicy' is not allowed."
        }

        $lifecycle = [string]$artifact.lifecycle
        if ([string]::IsNullOrWhiteSpace($lifecycle)) {
            Throw-BuildError -Id 'Build.Manifest.MissingLifecycle' -Message "artifact '$id' lifecycle must be declared."
        }
        $lifecycle = $lifecycle.Trim()
        if (-not ($script:AllowedLifecyclePolicies -contains $lifecycle)) {
            Throw-BuildError -Id 'Build.Manifest.ForbiddenLifecycle' -Message "artifact '$id' lifecycle '$lifecycle' is not allowed."
        }

        $destinationExtension = [System.IO.Path]::GetExtension($destination).ToLowerInvariant()
        $authenticode = $null
        $authenticodeField = $artifact.PSObject.Properties['authenticode']
        if ($null -ne $authenticodeField -and $null -ne $artifact.authenticode) {
            if ($artifact.authenticode -is [System.Array]) {
                Throw-BuildError -Id 'Build.Manifest.InvalidAuthenticodeObject' -Message "artifact '$id' authenticode must be an object."
            }

            Assert-AllowedFields -InputObject $artifact.authenticode -AllowedFields @('thumbprint', 'subject') -Context ("artifact '{0}'.authenticode" -f $id)

            if ([string]::IsNullOrWhiteSpace($destinationExtension)) {
                Throw-BuildError -Id 'Build.Manifest.AuthenticodeMissingDestinationExtension' -Message "artifact '$id' destination must include an extension when authenticode is declared."
            }

            if (-not ($script:AuthenticodeExtensions -contains $destinationExtension)) {
                Throw-BuildError -Id 'Build.Manifest.AuthenticodeUnsupportedDestinationExtension' -Message "artifact '$id' destination extension '$destinationExtension' is not supported for Authenticode validation."
            }

            $thumbprint = $null
            $subject = $null

            $thumbprintField = $artifact.authenticode.PSObject.Properties['thumbprint']
            if ($null -ne $thumbprintField -and -not [string]::IsNullOrWhiteSpace([string]$artifact.authenticode.thumbprint)) {
                $thumbprintText = ([string]$artifact.authenticode.thumbprint).Trim().ToUpperInvariant()
                if ($thumbprintText -notmatch '^[A-F0-9]{40}$') {
                    Throw-BuildError -Id 'Build.Manifest.InvalidAuthenticodeThumbprint' -Message "artifact '$id' authenticode.thumbprint must be a 40-character hex SHA-1 thumbprint."
                }
                $thumbprint = $thumbprintText
            }

            $subjectField = $artifact.authenticode.PSObject.Properties['subject']
            if ($null -ne $subjectField -and -not [string]::IsNullOrWhiteSpace([string]$artifact.authenticode.subject)) {
                $subject = ([string]$artifact.authenticode.subject).Trim()
            }

            if ($null -eq $thumbprint -and $null -eq $subject) {
                Throw-BuildError -Id 'Build.Manifest.EmptyAuthenticodeRequirements' -Message "artifact '$id' authenticode must declare thumbprint and/or subject."
            }

            $authenticode = [PSCustomObject]@{
                Thumbprint = $thumbprint
                Subject    = $subject
            }
        }

        $validatedArtifacts.Add([PSCustomObject]@{
                Index                = $artifactIndex
                Id                   = $id
                Version              = $version
                Url                  = $uri.AbsoluteUri
                SourceHost           = $sourceHost
                Destination          = $destination
                DestinationExtension = $destinationExtension
                Size                 = $size
                Sha256               = $sha256
                License              = $license
                TrustTier            = $trustTier
                Purpose              = $purpose
                InstallPolicy        = $installPolicy
                Lifecycle            = $lifecycle
                Authenticode         = $authenticode
            }) | Out-Null

        $artifactIndex += 1
    }

    return [PSCustomObject]@{
        ManifestPath       = (Resolve-Path -LiteralPath $ManifestPath).Path
        SchemaVersion      = $schemaVersion
        OfficialHosts      = $officialHosts.ToArray()
        OfficialHostLookup = $officialHostLookup
        Artifacts          = $validatedArtifacts.ToArray()
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
        ManifestPath  = $validated.ManifestPath
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
        Throw-BuildError -Id 'Build.VerifySource.MissingRepoRoot' -Message "RepoRoot '$RepoRoot' was not found." -Category ObjectNotFound
    }

    $manifest = Read-JsonObject -ManifestPath $ManifestPath
    Assert-AllowedFields -InputObject $manifest -AllowedFields @('schemaVersion', 'scopeRoot', 'files') -Context 'VerifySource manifest'
    Assert-RequiredFields -InputObject $manifest -RequiredFields @('schemaVersion', 'scopeRoot', 'files') -Context 'VerifySource manifest'

    $schemaVersion = Convert-ToStrictInt64 -Value $manifest.schemaVersion -FieldName 'schemaVersion' -AllowZero
    if ($schemaVersion -ne 1) {
        Throw-BuildError -Id 'Build.VerifySource.UnsupportedSchemaVersion' -Message "schemaVersion '$schemaVersion' is not supported. Expected value: 1."
    }

    if (-not ($manifest.files -is [System.Array])) {
        Throw-BuildError -Id 'Build.VerifySource.InvalidFilesCollection' -Message "VerifySource manifest field 'files' must be an array."
    }

    if ($manifest.files.Count -eq 0) {
        Throw-BuildError -Id 'Build.VerifySource.EmptyFilesCollection' -Message "VerifySource manifest field 'files' must contain at least one file."
    }

    $scopeRoot = Resolve-SafeChildPath -BasePath $repoInfo.FullPath -RelativePath ([string]$manifest.scopeRoot) -FieldName 'scopeRoot'
    if (-not (Test-Path -LiteralPath $scopeRoot.FullPath -PathType Container)) {
        Throw-BuildError -Id 'Build.VerifySource.MissingScopeRoot' -Message "scopeRoot '$($scopeRoot.RelativePath)' was not found under RepoRoot." -Category ObjectNotFound
    }

    Assert-NoReparsePointsInExistingChain -BasePath $repoInfo.FullPath -TargetPath $scopeRoot.FullPath -FieldName 'scopeRoot' -ErrorId 'Build.VerifySource.ReparsePoint'
    Assert-NoReparsePointsInTree -RootPath $scopeRoot.FullPath -Context 'scopeRoot' -ErrorId 'Build.VerifySource.ReparsePoint'
    $scopeInfo = Get-PathInfo -BasePath $scopeRoot.FullPath -FieldName 'scopeRoot'

    $expectedByPath = New-CaseInsensitiveDictionary
    $manifestFileCount = 0

    $index = 0
    foreach ($fileEntry in $manifest.files) {
        if ($fileEntry -is [System.Array]) {
            Throw-BuildError -Id 'Build.VerifySource.InvalidFileObject' -Message "files[$index] must be a JSON object."
        }

        Assert-AllowedFields -InputObject $fileEntry -AllowedFields @('path', 'size', 'sha256') -Context ("files[{0}]" -f $index)
        Assert-RequiredFields -InputObject $fileEntry -RequiredFields @('path', 'size', 'sha256') -Context ("files[{0}]" -f $index)

        $resolvedFile = Resolve-SafeChildPath -BasePath $repoInfo.FullPath -RelativePath ([string]$fileEntry.path) -FieldName ("files[{0}].path" -f $index)
        $isInScope = $resolvedFile.FullPath.Equals($scopeInfo.FullPath, [System.StringComparison]::OrdinalIgnoreCase) -or
            $resolvedFile.FullPath.StartsWith($scopeInfo.WithSeparator, [System.StringComparison]::OrdinalIgnoreCase)
        if (-not $isInScope) {
            Throw-BuildError -Id 'Build.VerifySource.PathOutsideScope' -Message "files[$index].path '$($resolvedFile.RelativePath)' is outside scopeRoot '$($scopeRoot.RelativePath)'."
        }

        if ($expectedByPath.ContainsKey($resolvedFile.RelativePath)) {
            Throw-BuildError -Id 'Build.VerifySource.DuplicateExpectedPath' -Message "VerifySource manifest contains duplicate path '$($resolvedFile.RelativePath)'."
        }

        $size = Convert-ToStrictInt64 -Value $fileEntry.size -FieldName ("files[{0}].size" -f $index) -AllowZero
        $sha256 = Normalize-Sha256 -Value ([string]$fileEntry.sha256) -FieldName ("files[{0}].sha256" -f $index)

        $expectedByPath.Add($resolvedFile.RelativePath, [PSCustomObject]@{
                Path   = $resolvedFile.RelativePath
                Size   = $size
                Sha256 = $sha256
            })

        $manifestFileCount += 1
        $index += 1
    }

    if ($expectedByPath.Count -ne $manifestFileCount) {
        Throw-BuildError -Id 'Build.VerifySource.ExpectedPathCollision' -Message "VerifySource expected file map collision detected: manifest declared $manifestFileCount files but resolved to $($expectedByPath.Count) unique paths."
    }

    $actualByPath = New-CaseInsensitiveDictionary
    $actualEnumeratedCount = 0
    foreach ($file in (Get-ChildItem -LiteralPath $scopeInfo.FullPath -File -Recurse -Force)) {
        if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-BuildError -Id 'Build.VerifySource.ReparsePoint' -Message "scopeRoot contains reparse point '$($file.FullName)'."
        }

        $relativePath = Convert-ToRepoRelativePath -RootPathInfo $repoInfo -FullPath $file.FullName
        Assert-PathSegmentsAreNfc -PathValue $relativePath -FieldName 'actual file path'

        if ($actualByPath.ContainsKey($relativePath)) {
            $collisionKey = Get-OrdinalPathKey -RelativePath $relativePath
            Throw-BuildError -Id 'Build.VerifySource.ActualPathCollision' -Message "VerifySource found case/normalization collision for path key '$collisionKey' on disk."
        }

        $actualByPath.Add($relativePath, [PSCustomObject]@{
                Path     = $relativePath
                FullPath = $file.FullName
                Size     = [Int64]$file.Length
            })
        $actualEnumeratedCount += 1
    }

    if ($actualByPath.Count -ne $actualEnumeratedCount) {
        Throw-BuildError -Id 'Build.VerifySource.ActualPathCollision' -Message "VerifySource actual file map collision detected: enumerated $actualEnumeratedCount files but resolved to $($actualByPath.Count) unique paths."
    }

    $issues = New-Object System.Collections.Generic.List[string]
    if ($expectedByPath.Count -ne $actualByPath.Count) {
        $issues.Add("file count mismatch: expected $($expectedByPath.Count), got $($actualByPath.Count).")
    }

    foreach ($expectedPath in ($expectedByPath.Keys | Sort-Object)) {
        if (-not $actualByPath.ContainsKey($expectedPath)) {
            $issues.Add("Missing file '$($expectedByPath[$expectedPath].Path)'.")
            continue
        }

        $expected = $expectedByPath[$expectedPath]
        $actual = $actualByPath[$expectedPath]

        if ($actual.Size -ne $expected.Size) {
            $issues.Add(("size mismatch for '{0}': expected {1}, got {2}." -f $expected.Path, $expected.Size, $actual.Size))
            continue
        }

        $actualHash = (Get-FileHash -LiteralPath $actual.FullPath -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($actualHash -ne $expected.Sha256) {
            $issues.Add(("hash mismatch for '{0}': expected {1}, got {2}." -f $expected.Path, $expected.Sha256, $actualHash))
        }
    }

    foreach ($actualPath in ($actualByPath.Keys | Sort-Object)) {
        if (-not $expectedByPath.ContainsKey($actualPath)) {
            $issues.Add("Unexpected file '$($actualByPath[$actualPath].Path)'.")
        }
    }

    if ($issues.Count -gt 0) {
        Throw-BuildError -Id 'Build.VerifySource.Mismatch' -Message ("VerifySource manifest mismatch:`n - " + [string]::Join("`n - ", $issues))
    }

    return [PSCustomObject]@{
        ScopeRoot = $scopeRoot.RelativePath
        FileCount = $expectedByPath.Count
    }
}

function Invoke-Hydrate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,
        [Parameter(Mandatory = $true)]
        [string]$StagingDirectory,
        [string]$ReceiptPath = 'hydrate-receipt.json',
        [scriptblock]$Downloader
    )

    if ([string]::IsNullOrWhiteSpace($ReceiptPath)) {
        Throw-BuildError -Id 'Build.Hydrate.EmptyReceiptPath' -Message "ReceiptPath must be a non-empty relative path."
    }

    $validated = Validate-HydrateManifest -ManifestPath $ManifestPath

    if (-not (Test-Path -LiteralPath $StagingDirectory)) {
        [System.IO.Directory]::CreateDirectory($StagingDirectory) | Out-Null
    }

    $stagingInfo = Get-PathInfo -BasePath $StagingDirectory -FieldName 'StagingDirectory'
    if (-not (Test-Path -LiteralPath $stagingInfo.FullPath -PathType Container)) {
        Throw-BuildError -Id 'Build.Hydrate.InvalidStagingDirectory' -Message "StagingDirectory '$StagingDirectory' is not a directory."
    }

    Assert-NoReparsePointsInExistingChain -BasePath $stagingInfo.FullPath -TargetPath $stagingInfo.FullPath -FieldName 'StagingDirectory' -ErrorId 'Build.Hydrate.ReparsePoint'

    $destinationLookup = New-CaseInsensitiveDictionary
    $planned = New-Object System.Collections.Generic.List[object]

    foreach ($artifact in $validated.Artifacts) {
        $destination = Resolve-SafeChildPath -BasePath $stagingInfo.FullPath -RelativePath $artifact.Destination -FieldName ("artifact '{0}' destination" -f $artifact.Id)
        if ($destinationLookup.ContainsKey($destination.RelativePath)) {
            Throw-BuildError -Id 'Build.Hydrate.DuplicateDestination' -Message "artifacts contains duplicate destination '$($destination.RelativePath)'."
        }

        foreach ($existingDestination in $destinationLookup.Values) {
            if (Test-RelativePathPrefixCollision -LeftPath $destination.RelativePath -RightPath ([string]$existingDestination)) {
                Throw-BuildError -Id 'Build.Hydrate.DestinationPrefixCollision' -Message "Destination collision between '$($destination.RelativePath)' and '$existingDestination'."
            }
        }

        $destinationLookup.Add($destination.RelativePath, $destination.RelativePath)
        $planned.Add([PSCustomObject]@{
                Artifact    = $artifact
                Destination = $destination
            }) | Out-Null
    }

    $receiptLocation = Resolve-SafeChildPath -BasePath $stagingInfo.FullPath -RelativePath $ReceiptPath -FieldName 'ReceiptPath'
    if ($destinationLookup.ContainsKey($receiptLocation.RelativePath)) {
        Throw-BuildError -Id 'Build.Hydrate.ReceiptPathCollision' -Message "ReceiptPath '$($receiptLocation.RelativePath)' collides with artifact destination '$($receiptLocation.RelativePath)'."
    }

    foreach ($existingDestination in $destinationLookup.Values) {
        if (Test-RelativePathPrefixCollision -LeftPath $receiptLocation.RelativePath -RightPath ([string]$existingDestination)) {
            Throw-BuildError -Id 'Build.Hydrate.ReceiptPathCollision' -Message "ReceiptPath '$($receiptLocation.RelativePath)' collides by prefix with artifact destination '$existingDestination'."
        }
    }

    $receiptDirectory = Split-Path -Parent $receiptLocation.FullPath
    Assert-NoReparsePointsInExistingChain -BasePath $stagingInfo.FullPath -TargetPath $receiptDirectory -FieldName 'ReceiptPath' -ErrorId 'Build.Hydrate.ReceiptPathReparsePoint'

    if (-not (Test-Path -LiteralPath $receiptDirectory)) {
        [System.IO.Directory]::CreateDirectory($receiptDirectory) | Out-Null
    }

    $receiptDirectoryItem = Get-Item -LiteralPath $receiptDirectory -Force
    if (($receiptDirectoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-BuildError -Id 'Build.Hydrate.ReceiptPathReparsePoint' -Message "ReceiptPath directory '$receiptDirectory' is a reparse point."
    }

    if (Test-Path -LiteralPath $receiptLocation.FullPath) {
        Throw-BuildError -Id 'Build.Hydrate.ReceiptExists' -Message "ReceiptPath '$($receiptLocation.RelativePath)' already exists."
    }

    $receiptRecords = New-Object System.Collections.Generic.List[object]
    foreach ($item in $planned) {
        $artifact = $item.Artifact
        $destination = $item.Destination
        $destinationDirectory = Split-Path -Parent $destination.FullPath

        Assert-NoReparsePointsInExistingChain -BasePath $stagingInfo.FullPath -TargetPath $destinationDirectory -FieldName ("artifact '{0}' destination" -f $artifact.Id) -ErrorId 'Build.Hydrate.ReparsePoint'

        if (-not (Test-Path -LiteralPath $destinationDirectory)) {
            [System.IO.Directory]::CreateDirectory($destinationDirectory) | Out-Null
        }

        $destinationDirectoryItem = Get-Item -LiteralPath $destinationDirectory -Force
        if (($destinationDirectoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-BuildError -Id 'Build.Hydrate.ReparsePoint' -Message "artifact '$($artifact.Id)' destination directory '$destinationDirectory' is a reparse point."
        }

        if (Test-Path -LiteralPath $destination.FullPath) {
            Throw-BuildError -Id 'Build.Hydrate.DestinationExists' -Message "Destination collision: '$($destination.RelativePath)' already exists."
        }

        $tempFile = Join-Path $destinationDirectory ("{0}.download.tmp.{1}" -f ([System.IO.Path]::GetFileName($destination.FullPath)), ([Guid]::NewGuid().ToString('N')))
        try {
            $resolvedUri = Invoke-ArtifactDownload -Artifact $artifact -TempFilePath $tempFile -Downloader $Downloader
            if ($resolvedUri.Scheme -ne 'https') {
                Throw-BuildError -Id 'Build.Hydrate.NonHttpsResolvedUrl' -Message "artifact '$($artifact.Id)' resolved URL must remain HTTPS."
            }

            $resolvedHost = Normalize-HostName -HostValue $resolvedUri.Host -FieldName ("artifact '{0}' resolved host" -f $artifact.Id)
            if (-not $resolvedHost.Equals($artifact.SourceHost, [System.StringComparison]::Ordinal)) {
                Throw-BuildError -Id 'Build.Hydrate.RedirectHostMismatch' -Message "artifact '$($artifact.Id)' redirected to host '$resolvedHost', expected '$($artifact.SourceHost)'. Cross-host redirects are forbidden."
            }

            if (-not $validated.OfficialHostLookup.ContainsKey($resolvedHost)) {
                Throw-BuildError -Id 'Build.Hydrate.ResolvedHostNotOfficial' -Message "artifact '$($artifact.Id)' resolved host '$resolvedHost' is not official."
            }

            $fileLength = (Get-Item -LiteralPath $tempFile -Force).Length
            if ($fileLength -ne $artifact.Size) {
                Throw-BuildError -Id 'Build.Hydrate.SizeMismatch' -Message "artifact '$($artifact.Id)' size mismatch: expected $($artifact.Size), got $fileLength."
            }

            $actualSha256 = (Get-FileHash -LiteralPath $tempFile -Algorithm SHA256).Hash.ToUpperInvariant()
            if ($actualSha256 -ne $artifact.Sha256) {
                Throw-BuildError -Id 'Build.Hydrate.HashMismatch' -Message "artifact '$($artifact.Id)' hash mismatch: expected $($artifact.Sha256), got $actualSha256."
            }

            if ($null -ne $artifact.Authenticode) {
                Assert-AuthenticodeSignature -FilePath $tempFile -DeclaredExtension $artifact.DestinationExtension -Requirement $artifact.Authenticode -ArtifactId $artifact.Id
            }

            if (Test-Path -LiteralPath $destination.FullPath) {
                Throw-BuildError -Id 'Build.Hydrate.DestinationExists' -Message "Destination collision: '$($destination.RelativePath)' already exists."
            }

            [System.IO.File]::Move($tempFile, $destination.FullPath)

            $receiptRecords.Add([PSCustomObject]@{
                    id              = $artifact.Id
                    version         = $artifact.Version
                    sourceUrl       = $artifact.Url
                    resolvedUrl     = $resolvedUri.AbsoluteUri
                    destination     = $destination.RelativePath
                    size            = $fileLength
                    sha256          = $actualSha256
                    downloadedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
                }) | Out-Null
        }
        finally {
            if (Test-Path -LiteralPath $tempFile) {
                Remove-Item -LiteralPath $tempFile -Force
            }
        }
    }

    $receiptPayload = [PSCustomObject]@{
        schemaVersion    = 1
        manifestPath     = $validated.ManifestPath
        generatedAtUtc   = (Get-Date).ToUniversalTime().ToString('o')
        stagingDirectory = $stagingInfo.FullPath
        artifacts        = $receiptRecords
    }

    $receiptTempPath = Join-Path $receiptDirectory ("{0}.tmp.{1}" -f ([System.IO.Path]::GetFileName($receiptLocation.FullPath)), ([Guid]::NewGuid().ToString('N')))
    try {
        Set-Content -LiteralPath $receiptTempPath -Value (ConvertTo-Json -InputObject $receiptPayload -Depth 8) -Encoding UTF8

        if (Test-Path -LiteralPath $receiptLocation.FullPath) {
            Throw-BuildError -Id 'Build.Hydrate.ReceiptExists' -Message "ReceiptPath '$($receiptLocation.RelativePath)' already exists."
        }

        [System.IO.File]::Move($receiptTempPath, $receiptLocation.FullPath)
    }
    finally {
        if (Test-Path -LiteralPath $receiptTempPath) {
            Remove-Item -LiteralPath $receiptTempPath -Force
        }
    }

    return [PSCustomObject]@{
        ReceiptPath   = $receiptLocation.FullPath
        ArtifactCount = $receiptRecords.Count
    }
}

Export-ModuleMember -Function Invoke-VerifySource, Invoke-Hydrate, Invoke-AuditManifest

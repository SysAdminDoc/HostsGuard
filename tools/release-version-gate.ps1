param(
    [switch]$RequireArtifacts
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$errors = [System.Collections.Generic.List[string]]::new()

function Add-Error([string]$Message) {
    $errors.Add($Message) | Out-Null
}

function Read-Text([string]$Path) {
    Get-Content -LiteralPath (Join-Path $repo $Path) -Raw
}

function Require-Contains([string]$Path, [string]$Needle, [string]$Label) {
    $text = Read-Text $Path
    if (-not $text.Contains($Needle)) {
        Add-Error "$Label missing '$Needle' in $Path"
    }
}

function Get-Sha256([string]$Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            -join ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('X2') })
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Join-RepoPath([string]$Path) {
    Join-Path $repo ($Path -replace '/', '\')
}

function Get-PngSize([string]$Path) {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if (($bytes.Length -lt 24) -or
        ($bytes[0] -ne 0x89) -or
        ($bytes[1] -ne 0x50) -or
        ($bytes[2] -ne 0x4E) -or
        ($bytes[3] -ne 0x47)) {
        Add-Error "screenshot is not a PNG: $Path"
        return [pscustomobject]@{ width = 0; height = 0 }
    }

    [pscustomobject]@{
        width = (([int]$bytes[16] -shl 24) -bor ([int]$bytes[17] -shl 16) -bor ([int]$bytes[18] -shl 8) -bor [int]$bytes[19])
        height = (([int]$bytes[20] -shl 24) -bor ([int]$bytes[21] -shl 16) -bor ([int]$bytes[22] -shl 8) -bor [int]$bytes[23])
    }
}

function Version-Matches([string]$Actual, [string]$Expected) {
    -not [string]::IsNullOrWhiteSpace($Actual) -and (
        $Actual -eq $Expected -or
        $Actual -eq "$Expected.0" -or
        $Actual.StartsWith("$Expected+", [StringComparison]::OrdinalIgnoreCase) -or
        $Actual.StartsWith("$Expected.", [StringComparison]::OrdinalIgnoreCase))
}

function Test-ScreenshotManifest([string]$Version) {
    $manifestRel = 'docs/img/visual-smoke-manifest.json'
    $manifestPath = Join-RepoPath $manifestRel
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        Add-Error "visual smoke screenshot manifest missing: $manifestRel"
        return
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schemaVersion -ne 4) {
        Add-Error "visual smoke manifest schemaVersion must be 4"
    }

    if ($manifest.version -ne $Version) {
        Add-Error "visual smoke manifest version '$($manifest.version)' does not match $Version"
    }

    foreach ($binaryName in @('app', 'service')) {
        $binary = $manifest.$binaryName
        if ($null -eq $binary) {
            Add-Error "visual smoke manifest missing $binaryName binary version"
            continue
        }

        if (-not (Version-Matches ([string]$binary.fileVersion) $Version)) {
            Add-Error "visual smoke $binaryName fileVersion '$($binary.fileVersion)' does not match $Version"
        }
    }

    $expectedTabs = @('Hosts Activity', 'Alerts', 'Hosts File', 'Firewall Activity', 'Firewall Rules', 'Tools')
    $expectedLandmarks = @{
        'Hosts Activity' = 'ActivityGrid'
        'Alerts' = 'AlertsGrid'
        'Hosts File' = 'DomainsGrid'
        'Firewall Activity' = 'ConnectionsGrid'
        'Firewall Rules' = 'FwRulesGrid'
        'Tools' = 'ToolsSurface'
    }
    foreach ($theme in @('dark', 'light', 'contrast-aquatic', 'contrast-desert', 'contrast-dusk', 'contrast-night-sky')) {
        $primary = @($manifest.primaryCaptures | Where-Object { $_.theme -eq $theme })
        if ($primary.Count -ne $expectedTabs.Count) {
            Add-Error "visual smoke manifest has $($primary.Count) $theme primary captures; expected $($expectedTabs.Count)"
            continue
        }

        foreach ($tab in $expectedTabs) {
            $capture = @($primary | Where-Object { $_.tab -eq $tab })
            if ($capture.Count -ne 1) {
                Add-Error "visual smoke $theme must capture '$tab' exactly once"
                continue
            }
            if ($capture[0].landmark -ne $expectedLandmarks[$tab]) {
                Add-Error "visual smoke $theme '$tab' landmark '$($capture[0].landmark)' is not '$($expectedLandmarks[$tab])'"
            }
            if ([string]::IsNullOrWhiteSpace([string]$capture[0].sha256)) {
                Add-Error "visual smoke $theme '$tab' has no pixel hash"
            }
        }

        $distinctHashes = @($primary.sha256 | Select-Object -Unique)
        if ($distinctHashes.Count -ne $primary.Count) {
            Add-Error "visual smoke $theme primary pages contain identical pixel hashes"
        }

        $disconnected = @($manifest.stateCaptures | Where-Object {
            $_.theme -eq $theme -and $_.state -eq 'disconnected'
        })
        if ($disconnected.Count -ne 1 -or $disconnected[0].landmark -ne 'DisconnectedOverlay') {
            Add-Error "visual smoke $theme lacks one separate disconnected recovery capture"
        }
    }

    $readme = Read-Text 'README.md'
    $expectedThemes = @('dark', 'light')
    $screenshots = @($manifest.readmeScreenshots)
    foreach ($theme in $expectedThemes) {
        $shot = $screenshots | Where-Object { $_.theme -eq $theme } | Select-Object -First 1
        if ($null -eq $shot) {
            Add-Error "visual smoke manifest missing $theme README screenshot"
            continue
        }

        $path = [string]$shot.path
        if ([string]::IsNullOrWhiteSpace($path)) {
            Add-Error "visual smoke $theme screenshot path is empty"
            continue
        }

        $fullPath = Join-RepoPath $path
        if (-not (Test-Path -LiteralPath $fullPath)) {
            Add-Error "visual smoke $theme screenshot file missing: $path"
            continue
        }

        if (-not $readme.Contains($path)) {
            Add-Error "README does not reference visual smoke $theme screenshot $path"
        }

        $hash = Get-Sha256 $fullPath
        if ($hash -ne $shot.sha256) {
            Add-Error "visual smoke $theme screenshot SHA256 changed without manifest update"
        }

        $size = Get-PngSize $fullPath
        if ($size.width -ne $shot.width -or $size.height -ne $shot.height) {
            Add-Error "visual smoke $theme screenshot dimensions changed without manifest update"
        }

        if ($size.width -ne 1600 -or $size.height -ne 1000) {
            Add-Error "visual smoke $theme screenshot is $($size.width)x$($size.height); expected 1600x1000"
        }

        if ((Get-Item -LiteralPath $fullPath).Length -lt 50000) {
            Add-Error "visual smoke $theme screenshot is unexpectedly small: $path"
        }

        $average = [double]$shot.averageLuminance
        $range = [double]$shot.luminanceRange
        $opaque = [double]$shot.opaqueRatio
        $bottomOpaque = [double]$shot.bottomOpaqueRatio
        $contentTiles = [double]$shot.contentTileRatio
        if ($opaque -lt 0.995 -or $bottomOpaque -lt 0.995) {
            Add-Error "visual smoke $theme screenshot contains transparent/blank pixels (opaque=$opaque, bottom=$bottomOpaque)"
        }
        if ($range -lt 60 -or $contentTiles -lt 0.10) {
            Add-Error "visual smoke $theme screenshot lacks rendered detail (range=$range, tiles=$contentTiles)"
        }
        if (($theme -eq 'dark' -and ($average -lt 5 -or $average -gt 100)) -or
            ($theme -eq 'light' -and ($average -lt 100 -or $average -gt 250))) {
            Add-Error "visual smoke $theme average luminance is outside theme bounds: $average"
        }
    }
}

[xml]$props = Read-Text 'Directory.Build.props'
$version = $props.Project.PropertyGroup.Version | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($version)) {
    Add-Error 'Directory.Build.props does not define <Version>'
}

$iss = Read-Text 'installer-dotnet.iss'
if ($iss -notmatch "#define\s+MyAppVersion\s+`"$([regex]::Escape($version))`"") {
    Add-Error "installer-dotnet.iss MyAppVersion does not match $version"
}
if ($iss -notmatch "#define\s+MyAppVersionInfo\s+`"$([regex]::Escape($version))\.0`"") {
    Add-Error "installer-dotnet.iss MyAppVersionInfo does not match $version.0"
}
if (-not $iss.Contains('Source: "dist\dotnet\{#TargetRid}\migrator\*"; DestDir: "{app}\migrator"')) {
    Add-Error 'installer-dotnet.iss does not package the runtime-specific migrator'
}

Require-Contains 'README.md' "version-$version-blue" 'README badge'
$readme = Read-Text 'README.md'
foreach ($rid in @('win-x64', 'win-arm64')) {
    $currentName = "HostsGuard-v$version-$rid-dotnet-Setup.exe"
    $templateName = "HostsGuard-v<version>-$rid-dotnet-Setup.exe"
    if (-not $readme.Contains($currentName) -and -not $readme.Contains($templateName)) {
        Add-Error "README $rid artifact must use the current or explicit <version> filename template"
    }
}
Require-Contains 'CHANGELOG.md' "## [$version] -" 'CHANGELOG heading'
Test-ScreenshotManifest $version

$wingetManifests = @(
    'winget/SysAdminDoc.HostsGuard.yaml',
    'winget/SysAdminDoc.HostsGuard.locale.en-US.yaml',
    'winget/SysAdminDoc.HostsGuard.installer.yaml'
)
$wingetRoot = Read-Text $wingetManifests[0]
$wingetMatch = [regex]::Match($wingetRoot, '(?m)^PackageVersion:\s*(\S+)\s*$')
$wingetVersion = if ($wingetMatch.Success) { $wingetMatch.Groups[1].Value } else { '' }
if ([string]::IsNullOrWhiteSpace($wingetVersion)) {
    Add-Error 'winget root manifest has no PackageVersion'
}
foreach ($manifest in $wingetManifests) {
    Require-Contains $manifest "PackageVersion: $wingetVersion" "winget package version"
}
if ($RequireArtifacts -and $wingetVersion -ne $version) {
    Add-Error "winget package version '$wingetVersion' must match release artifact version $version"
}

$installerManifest = Read-Text 'winget/SysAdminDoc.HostsGuard.installer.yaml'
foreach ($rid in @('win-x64', 'win-arm64')) {
    $wingetFileName = "HostsGuard-v$wingetVersion-$rid-dotnet-Setup.exe"
    $url = "https://github.com/SysAdminDoc/HostsGuard/releases/download/v$wingetVersion/$wingetFileName"
    if (-not $installerManifest.Contains("InstallerUrl: $url")) {
        Add-Error "winget installer URL missing $url"
    }

    $fileName = "HostsGuard-v$version-$rid-dotnet-Setup.exe"
    $artifact = Join-Path $repo "installer_output\$fileName"
    if ($RequireArtifacts -and (Test-Path -LiteralPath $artifact)) {
        $hash = Get-Sha256 $artifact
        if (-not $installerManifest.Contains("InstallerSha256: $hash")) {
            Add-Error "winget $rid SHA256 does not match $hash"
        }
    }
    elseif ($RequireArtifacts) {
        Add-Error "required artifact missing: $artifact"
    }

    if ($RequireArtifacts) {
        $migrator = Join-Path $repo "dist\dotnet\$rid\migrator\HostsGuard.Migrator.exe"
        if (-not (Test-Path -LiteralPath $migrator)) {
            Add-Error "required migrator artifact missing: $migrator"
        }
        else {
            $migratorVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($migrator).FileVersion
            if (-not (Version-Matches $migratorVersion $version)) {
                Add-Error "published $rid migrator fileVersion '$migratorVersion' does not match $version"
            }
        }
    }
}

if ($errors.Count -ne 0) {
    $errors | ForEach-Object { [Console]::Error.WriteLine("Release gate: $_") }
    exit 1
}

Write-Host "Release version gate: OK (v$version)"

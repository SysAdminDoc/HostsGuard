[CmdletBinding()]
param(
    [string]$Solution = "HostsGuard.sln"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$deferredTransitive = @{
    "Microsoft.Diagnostics.NETCore.Client" = "Transitive through Microsoft.Diagnostics.Tracing.TraceEvent 3.2.4; the direct TraceEvent package is current, so avoid graph surgery unless a CVE or upstream release requires it."
    "Microsoft.Extensions.DependencyInjection" = "Transitive through TraceEvent's Microsoft.Extensions 6.x graph; owned direct Microsoft.Extensions references are pinned to 10.0.9 where the app/service owns them."
    "Microsoft.Extensions.DependencyInjection.Abstractions" = "Transitive through TraceEvent/grpc/UI support packages; owned direct Microsoft.Extensions references are pinned to 10.0.9 where the app/service owns them."
    "Microsoft.Extensions.Logging" = "Transitive through TraceEvent's Microsoft.Extensions 6.x graph; direct lifting is deferred until TraceEvent updates or a vulnerability appears."
    "Microsoft.Extensions.Logging.Abstractions" = "Transitive through TraceEvent/UI support packages; owned direct Microsoft.Extensions references are pinned to 10.0.9 where the app/service owns them."
    "Microsoft.Extensions.Options" = "Transitive through TraceEvent's Microsoft.Extensions 6.x graph; direct lifting is deferred until TraceEvent updates or a vulnerability appears."
    "Microsoft.Extensions.Primitives" = "Transitive through TraceEvent's Microsoft.Extensions 6.x graph; direct lifting is deferred until TraceEvent updates or a vulnerability appears."
    "Newtonsoft.Json" = "Test-only transitive through xUnit runner support; direct xUnit packages are current and the vulnerability ratchet remains clean."
    "SourceGear.sqlite3" = "Transitive through SQLitePCLRaw.bundle_e_sqlite3 3.0.3; the direct bundle package is current and CVE-clean, so wait for the bundle to expose the newer native payload."
    "xunit.analyzers" = "Test-only transitive through xunit 2.9.3; keep direct xUnit packages current and defer analyzer policy changes to a focused warnings sweep."
}

function Invoke-DotNetJson {
    param(
        [string[]]$Arguments
    )

    $output = & dotnet @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $output | ForEach-Object { Write-Host $_ }
        throw "dotnet $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }

    $text = ($output | Out-String).Trim()
    $start = $text.IndexOf("{")
    $end = $text.LastIndexOf("}")
    if ($start -lt 0 -or $end -lt $start) {
        throw "dotnet $($Arguments -join ' ') did not return JSON."
    }

    return $text.Substring($start, $end - $start + 1) | ConvertFrom-Json
}

function Get-RelativePath {
    param(
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path).Replace("/", "\")
    $root = [System.IO.Path]::GetFullPath($repoRoot).TrimEnd("\") + "\"
    if ($fullPath.ToUpperInvariant().StartsWith($root.ToUpperInvariant())) {
        return $fullPath.Substring($root.Length)
    }

    return $fullPath
}

function Get-PackageRows {
    param(
        [object]$Report
    )

    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($project in @($Report.projects)) {
        if (-not ($project.PSObject.Properties.Name -contains "frameworks")) {
            continue
        }

        $projectPath = Get-RelativePath $project.path
        foreach ($framework in @($project.frameworks)) {
            $topLevelPackages = @()
            if ($framework.PSObject.Properties.Name -contains "topLevelPackages") {
                $topLevelPackages = @($framework.topLevelPackages)
            }

            $transitivePackages = @()
            if ($framework.PSObject.Properties.Name -contains "transitivePackages") {
                $transitivePackages = @($framework.transitivePackages)
            }

            foreach ($entry in @(
                    @{ Level = "Direct"; Packages = $topLevelPackages },
                    @{ Level = "Transitive"; Packages = $transitivePackages }
                )) {
                foreach ($package in @($entry.Packages)) {
                    if ($null -eq $package) {
                        continue
                    }

                    $vulnerabilities = @()
                    if ($package.PSObject.Properties.Name -contains "vulnerabilities") {
                        $vulnerabilities = @($package.vulnerabilities)
                    }

                    $rows.Add([pscustomobject]@{
                            Project          = $projectPath
                            Framework        = $framework.framework
                            Level            = $entry.Level
                            Id               = $package.id
                            RequestedVersion = if ($package.PSObject.Properties.Name -contains "requestedVersion") { $package.requestedVersion } else { "" }
                            ResolvedVersion  = $package.resolvedVersion
                            LatestVersion    = if ($package.PSObject.Properties.Name -contains "latestVersion") { $package.latestVersion } else { "" }
                            Vulnerabilities  = $vulnerabilities
                        })
                }
            }
        }
    }

    return $rows.ToArray()
}

function Write-Rows {
    param(
        [object[]]$Rows
    )

    foreach ($row in $Rows | Sort-Object Id, Project, Framework) {
        $versionText = if ([string]::IsNullOrWhiteSpace($row.LatestVersion)) {
            $row.ResolvedVersion
        }
        else {
            "$($row.ResolvedVersion) -> $($row.LatestVersion)"
        }

        Write-Host ("  {0} [{1}] {2} {3}: {4}" -f $row.Project, $row.Framework, $row.Level, $row.Id, $versionText)
    }
}

Push-Location $repoRoot
try {
    $vulnerableReport = Invoke-DotNetJson @("list", $Solution, "package", "--vulnerable", "--include-transitive", "--format", "json", "--output-version", "1")
    $outdatedReport = Invoke-DotNetJson @("list", $Solution, "package", "--outdated", "--include-transitive", "--format", "json", "--output-version", "1")

    $vulnerableRows = @(Get-PackageRows $vulnerableReport)
    $outdatedRows = @(Get-PackageRows $outdatedReport)
    $outdatedDirect = @($outdatedRows | Where-Object { $_.Level -eq "Direct" })
    $outdatedTransitive = @($outdatedRows | Where-Object { $_.Level -eq "Transitive" })
    $undeferredTransitive = @($outdatedTransitive | Where-Object { -not $deferredTransitive.ContainsKey($_.Id) })

    if ($vulnerableRows.Count -gt 0) {
        Write-Host "Vulnerable packages found:"
        Write-Rows $vulnerableRows
        throw "Dependency hygiene failed: vulnerable packages are not allowed."
    }

    Write-Host "Vulnerable packages: none"

    if ($outdatedDirect.Count -gt 0) {
        Write-Host "Outdated direct packages found:"
        Write-Rows $outdatedDirect
        throw "Dependency hygiene failed: direct package updates must be applied or intentionally deferred in this script."
    }

    Write-Host "Outdated direct packages: none"

    if ($undeferredTransitive.Count -gt 0) {
        Write-Host "Undeferred outdated transitive packages found:"
        Write-Rows $undeferredTransitive
        throw "Dependency hygiene failed: add a source-backed deferral or update the owning direct dependency."
    }

    if ($outdatedTransitive.Count -gt 0) {
        Write-Host "Deferred outdated transitive packages:"
        foreach ($id in ($outdatedTransitive.Id | Sort-Object -Unique)) {
            Write-Host ("  {0}: {1}" -f $id, $deferredTransitive[$id])
        }
    }
    else {
        Write-Host "Outdated transitive packages: none"
    }

    Write-Host "Dependency hygiene: OK"
}
finally {
    Pop-Location
}

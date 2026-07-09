[CmdletBinding()]
param(
    [string]$Solution = "HostsGuard.sln"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot

function New-TransitiveDeferral {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Owner,
        [Parameter(Mandatory = $true)]
        [string]$Reason,
        [Parameter(Mandatory = $true)]
        [string]$Revisit
    )

    [pscustomobject]@{
        Owner   = $Owner
        Reason  = $Reason
        Revisit = $Revisit
    }
}

$deferredTransitive = @{
    "Microsoft.Diagnostics.NETCore.Client" = New-TransitiveDeferral `
        -Owner "Microsoft.Diagnostics.Tracing.TraceEvent 3.2.4" `
        -Reason "Direct TraceEvent is current; adding an override would be graph surgery for a helper client TraceEvent owns." `
        -Revisit "Upgrade when TraceEvent ships a newer dependency graph or this package receives a CVE."
    "Microsoft.Extensions.DependencyInjection" = New-TransitiveDeferral `
        -Owner "Microsoft.Diagnostics.Tracing.TraceEvent 3.2.4" `
        -Reason "TraceEvent still carries the Microsoft.Extensions 6.x graph; HostsGuard-owned DI references are pinned directly to 10.0.9." `
        -Revisit "Upgrade when TraceEvent lifts Microsoft.Extensions or a vulnerability requires direct override."
    "Microsoft.Extensions.DependencyInjection.Abstractions" = New-TransitiveDeferral `
        -Owner "Microsoft.Diagnostics.Tracing.TraceEvent 3.2.4 / Grpc.Net.Client 2.80.0 / Hardcodet.NotifyIcon.Wpf 2.0.1" `
        -Reason "Multiple supported packages own this abstraction transitively; HostsGuard-owned Microsoft.Extensions references are pinned directly to 10.0.9." `
        -Revisit "Upgrade when owning packages lift the abstraction or a vulnerability requires direct override."
    "Microsoft.Extensions.Logging" = New-TransitiveDeferral `
        -Owner "Microsoft.Diagnostics.Tracing.TraceEvent 3.2.4" `
        -Reason "TraceEvent owns the older logging dependency; direct lifting would not change HostsGuard logging APIs." `
        -Revisit "Upgrade when TraceEvent lifts Microsoft.Extensions.Logging or a vulnerability appears."
    "Microsoft.Extensions.Logging.Abstractions" = New-TransitiveDeferral `
        -Owner "Microsoft.Diagnostics.Tracing.TraceEvent 3.2.4 / Grpc.Net.Client 2.80.0 / Hardcodet.NotifyIcon.Wpf 2.0.1" `
        -Reason "The app/service-owned Microsoft.Extensions references are already pinned to 10.0.9; remaining drift is dependency-owned." `
        -Revisit "Upgrade when owning packages lift the abstraction or a vulnerability appears."
    "Microsoft.Extensions.Options" = New-TransitiveDeferral `
        -Owner "Microsoft.Diagnostics.Tracing.TraceEvent 3.2.4" `
        -Reason "TraceEvent owns the older options dependency; direct lifting would add override-only package references." `
        -Revisit "Upgrade when TraceEvent lifts Microsoft.Extensions.Options or a vulnerability appears."
    "Microsoft.Extensions.Primitives" = New-TransitiveDeferral `
        -Owner "Microsoft.Diagnostics.Tracing.TraceEvent 3.2.4" `
        -Reason "TraceEvent owns the older primitives dependency; direct lifting would add override-only package references." `
        -Revisit "Upgrade when TraceEvent lifts Microsoft.Extensions.Primitives or a vulnerability appears."
    "Newtonsoft.Json" = New-TransitiveDeferral `
        -Owner "xunit.runner.visualstudio 3.1.5" `
        -Reason "Test-runner-only transitive package; production projects do not reference Newtonsoft.Json and the vulnerability ratchet is clean." `
        -Revisit "Upgrade when xUnit runner lifts Newtonsoft.Json or a test-only vulnerability appears."
    "SourceGear.sqlite3" = New-TransitiveDeferral `
        -Owner "SQLitePCLRaw.bundle_e_sqlite3 3.0.3" `
        -Reason "Direct SQLitePCLRaw bundle is current and CVE-clean; the native SourceGear payload version is controlled by the bundle." `
        -Revisit "Upgrade when SQLitePCLRaw.bundle_e_sqlite3 exposes a newer native payload or a SQLite CVE appears."
    "xunit.analyzers" = New-TransitiveDeferral `
        -Owner "xunit 2.9.3" `
        -Reason "Test-analyzer-only transitive package; changing analyzer policy can introduce warnings-as-errors churn unrelated to runtime hygiene." `
        -Revisit "Upgrade during a focused analyzer sweep or when xUnit lifts the analyzer."
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

function Format-ObservedVersions {
    param(
        [object[]]$Rows
    )

    $versions = @($Rows | ForEach-Object {
            if ([string]::IsNullOrWhiteSpace($_.LatestVersion)) {
                $_.ResolvedVersion
            }
            else {
                "$($_.ResolvedVersion) -> $($_.LatestVersion)"
            }
        } | Sort-Object -Unique)
    return $versions -join ", "
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
            $deferral = $deferredTransitive[$id]
            $rows = @($outdatedTransitive | Where-Object { $_.Id -eq $id })
            $observed = Format-ObservedVersions $rows
            Write-Host ("  {0}: owner {1}; observed {2}; reason: {3}; revisit: {4}" -f `
                    $id, $deferral.Owner, $observed, $deferral.Reason, $deferral.Revisit)
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

# HostsGuard .NET publish pipeline (NET-050 / NET-142).
# Single-file, self-contained Windows builds of the service, WPF app, CLI, and
# Python-profile migrator into dist\dotnet\<rid>\. Trimming is deliberately OFF (WPF, gRPC
# codegen, and COM interop depend on reflection the trimmer cannot prove) and so
# is ReadyToRun (crossgen2 rejects TraceEvent's duplicate Dia2Lib assets; the
# start-time gain is irrelevant for a long-running service). Run from anywhere;
# paths resolve relative to this script.
param(
    [string]$Configuration = 'Release',
    [string[]]$RuntimeIdentifier = @('win-x64'),
    [switch]$AllRuntimes,
    [switch]$SkipSmoke
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$outRoot = Join-Path $root 'dist\dotnet'
$supportedRuntimeIds = @('win-x64', 'win-arm64')
$runtimeIds = if ($AllRuntimes) { $supportedRuntimeIds } else { $RuntimeIdentifier }
$runtimeIds = @($runtimeIds | Select-Object -Unique)
foreach ($rid in $runtimeIds) {
    if ($supportedRuntimeIds -notcontains $rid) {
        throw "Unsupported runtime identifier '$rid'. Supported: $($supportedRuntimeIds -join ', ')"
    }
}

# Clean before build. Stale artifacts never ship next to fresh ones.
if (Test-Path $outRoot) {
    Remove-Item $outRoot -Recurse -Force
}

$projects = @(
    @{ Name = 'HostsGuard.Service'; Dir = 'service' },
    @{ Name = 'HostsGuard.App';     Dir = 'app' },
    @{ Name = 'HostsGuard.Cli';     Dir = 'cli' },
    @{ Name = 'HostsGuard.Migrator'; Dir = 'migrator' }
)

function Test-CanRunRuntime([string]$Rid) {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    if ($Rid -eq 'win-arm64') {
        return $arch -eq 'Arm64'
    }

    return $arch -in @('X64', 'Arm64')
}

function Invoke-MigratorSmoke([string]$Executable) {
    $smokeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("hostsguard-migrator-smoke-" + [guid]::NewGuid().ToString('N'))
    $source = Join-Path $smokeRoot 'python-profile'
    $target = Join-Path $smokeRoot 'dotnet-profile'
    try {
        New-Item -ItemType Directory -Path $source -Force | Out-Null

        # GZip-compressed minimal Python-era SQLite database with two domains.
        # Embedded bytes keep the release smoke independent of sqlite3/Python.
        $databaseGzipBase64 = 'H4sIAAAAAAACCu3YTUvDMBgH8KQT5wStICiygxEPKmxjUzx5sWoVcYrOCu40siXTYNfgmvpyFE9+Lk9+AL+AZz+AR7utviOedhD+P5o0eZqXtrcnhwdlZSRr6naLG7ZExgilZJUxQkgqKW9oXAa+9f+SIoWLuxH7hVijT2T0yX4gAAAAAAAAAH1xI2h6Mpult9OG130pdIurIExu1nrFdTyXec5a2WVJcH6YdfW6zHOPPbZf2d51KlW241ZzLDTcRGHvwYa76RyVPTZX93XjTIq5HGtwI090+7o7IJcsFuqo3ZC9EBPxiBoXQorPgZYWqqneYsm8U2VqDR0Fhm3vee6WW3nfsZhjgTay9x4LeWtw0slSogIhr8JzX3V2iIzu9mvJl9VKSaOT1w91/s5IXCz7htj3cQUAAAAAAAAA/bFqZUqzZGpmZohw39eXhaa6MlFbFuLM3lzG2b/0VWikaPEg4v5icXE5XyzF10drhWby2c4KlHARfpmfnEn8Pjc93M3/H4n9HFcAAAAAAAAA8H9MpEr052GCNZ7KZ76fELwCqOmoUwAwAAA='
        $compressed = [System.IO.MemoryStream]::new([Convert]::FromBase64String($databaseGzipBase64))
        $database = [System.IO.File]::Create((Join-Path $source 'hostsguard.db'))
        try {
            $gzip = [System.IO.Compression.GZipStream]::new($compressed, [System.IO.Compression.CompressionMode]::Decompress)
            try { $gzip.CopyTo($database) } finally { $gzip.Dispose() }
        }
        finally {
            $database.Dispose()
            $compressed.Dispose()
        }

        Set-Content -LiteralPath (Join-Path $source 'config.json') -Encoding utf8 -Value @'
{
  "schedules": [{"target":"fixture.test","days":[1],"start":"09:00","end":"17:00"}],
  "allowlist_subscriptions": ["https://lists.example/allow.txt"]
}
'@

        $output = (& $Executable --source $source --target $target --dry-run 2>&1 | Out-String)
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            throw "migrator --dry-run failed (exit $exitCode): $output"
        }
        if ($output -notmatch '(?m)^\s*domains:\s+2\s*$' -or
            $output -notmatch '(?m)^\s*schedules:\s+1\s*$' -or
            $output -notmatch '(?m)^\s*allowlist subscriptions:\s*1\s*$') {
            throw "migrator --dry-run did not report the packaged DB/config fixture: $output"
        }
        if (Test-Path -LiteralPath $target) {
            throw "migrator --dry-run mutated the target directory: $target"
        }
    }
    finally {
        Remove-Item -LiteralPath $smokeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

foreach ($rid in $runtimeIds) {
    $out = Join-Path $outRoot $rid
    foreach ($project in $projects) {
        $name = $project.Name
        Write-Host "publishing $name ($rid) ..." -ForegroundColor Cyan
        dotnet publish (Join-Path $root "src\$name\$name.csproj") `
            -c $Configuration -r $rid --self-contained true `
            -p:PublishSingleFile=true `
            -p:IncludeNativeLibrariesForSelfExtract=true `
            -p:EnableCompressionInSingleFile=true `
            -o (Join-Path $out $project.Dir) `
            --nologo -v minimal
        if ($LASTEXITCODE -ne 0) {
            throw "dotnet publish failed for $name ($rid, exit $LASTEXITCODE)"
        }
    }

    if (-not $SkipSmoke -and (Test-CanRunRuntime $rid)) {
        Write-Host "`nrelease-smoke ($rid):" -ForegroundColor Cyan
        & (Join-Path $out 'cli\HostsGuard.Cli.exe') release-smoke
        if ($LASTEXITCODE -ne 0) {
            throw "release-smoke failed for $rid (exit $LASTEXITCODE)"
        }

        Write-Host "migrator --dry-run smoke ($rid):" -ForegroundColor Cyan
        Invoke-MigratorSmoke (Join-Path $out 'migrator\HostsGuard.Migrator.exe')
    }
    elseif (-not $SkipSmoke) {
        Write-Host "`nrelease-smoke ($rid): skipped on $([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture)" -ForegroundColor Yellow
    }
}

Get-ChildItem $outRoot -Recurse -Include *.exe | Sort-Object FullName | ForEach-Object {
    '{0,10:n1} MB  {1}' -f ($_.Length / 1MB), $_.FullName.Substring($outRoot.Length + 1)
}

using FluentAssertions;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Data.Tests;

/// <summary>
/// The direct bundle/native pins keep both the 2025 security fixes and SQLite's
/// later WAL-reset corruption fix. This gate validates the engine that actually
/// loads, not merely the NuGet graph.
/// </summary>
public class SqliteVersionPinTests
{
    [Fact]
    public void Native_sqlite_is_at_or_above_the_fixed_floor()
    {
        using var conn = new SqliteConnection("Data Source=:memory:;Pooling=False");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT sqlite_version()";
        var version = (string)cmd.ExecuteScalar()!;

        var parts = version.Split('.');
        var major = int.Parse(parts[0]);
        var minor = int.Parse(parts[1]);
        var patch = parts.Length > 2 ? int.Parse(parts[2]) : 0;

        // >= 3.53.3 includes the WAL-reset corruption fix and all earlier floors.
        (major, minor, patch).Should().BeGreaterThanOrEqualTo((3, 53, 3),
            $"the bundled SQLite ({version}) must stay >= 3.53.3 to retain the WAL-reset corruption fix");
    }

    [Fact]
    public void Engine_version_is_surfaced_for_diagnostics()
    {
        var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "hg_sqlver_" + System.Guid.NewGuid().ToString("N") + ".db");
        try
        {
            using var db = new HostsDatabase(path);
            var reported = db.SqliteEngineVersion();
            reported.Should().MatchRegex(@"^\d+\.\d+\.\d+");
        }
        finally
        {
            try { System.IO.File.Delete(path); } catch (System.IO.IOException) { }
        }
    }

    [Fact]
    public void Parallel_test_teardown_never_clears_process_wide_pools()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "HostsGuard.sln")))
        {
            root = root.Parent;
        }

        root.Should().NotBeNull();
        var forbidden = "SqliteConnection.Clear" + "AllPools()";
        var offenders = Directory.EnumerateFiles(
                Path.Combine(root!.FullName, "tests"), "*.cs", SearchOption.AllDirectories)
            .Where(path => File.ReadAllText(path).Contains(forbidden, StringComparison.Ordinal))
            .Select(path => Path.GetRelativePath(root.FullName, path))
            .ToArray();

        offenders.Should().BeEmpty(
            "HostsDatabase disables pooling, and a process-wide clear in parallel teardown can invalidate another fixture's live connection");
    }

    [Theory]
    [InlineData("win-x64")]
    [InlineData("win-arm64")]
    public void Native_package_contains_each_release_runtime_asset(string runtimeIdentifier)
    {
        var packages = Environment.GetEnvironmentVariable("NUGET_PACKAGES");
        if (string.IsNullOrWhiteSpace(packages))
        {
            packages = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");
        }

        var native = Path.Combine(packages, "sourcegear.sqlite3", "3.53.3", "runtimes",
            runtimeIdentifier, "native", "e_sqlite3.dll");
        File.Exists(native).Should().BeTrue($"SourceGear.sqlite3 3.53.3 must ship {runtimeIdentifier} e_sqlite3.dll");
        new FileInfo(native).Length.Should().BeGreaterThan(1_000_000);
    }
}

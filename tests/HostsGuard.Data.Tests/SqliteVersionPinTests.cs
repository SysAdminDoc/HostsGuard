using FluentAssertions;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Data.Tests;

/// <summary>
/// NET-122: the entire basis for GHSA-2m69-gcr7-jv3q (CVE-2025-6965) not applying
/// is that the direct SQLitePCLRaw.bundle_e_sqlite3 3.0.3 pin overrides the
/// vulnerable 2.1.11 transitive (SQLite ~3.44). This gate fails the build if the
/// resolved native SQLite ever regresses below the fixed 3.50.2 floor.
/// </summary>
public class SqliteVersionPinTests
{
    [Fact]
    public void Native_sqlite_is_at_or_above_the_fixed_floor()
    {
        using var conn = new SqliteConnection("Data Source=:memory:");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT sqlite_version()";
        var version = (string)cmd.ExecuteScalar()!;

        var parts = version.Split('.');
        var major = int.Parse(parts[0]);
        var minor = int.Parse(parts[1]);
        var patch = parts.Length > 2 ? int.Parse(parts[2]) : 0;

        // >= 3.50.2 closes CVE-2025-6965 (and 3.49.1 closed CVE-2025-29087).
        (major, minor, patch).Should().BeGreaterThanOrEqualTo((3, 50, 2),
            $"the bundled SQLite ({version}) must stay >= 3.50.2 — a drop to the 2.1.x bundle reopens CVE-2025-6965");
    }
}

using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>NET-169: GetStatus carries runtime-health + silent-drop signals.</summary>
[SupportedOSPlatform("windows")]
public sealed class DiagnosticsHealthTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;

    public DiagnosticsHealthTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_diag_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _state = new ServiceState(new HostsEngine(hostsPath), new HostsDatabase(Path.Combine(_dir, "db.sqlite")),
            dataDir: _dir);
    }

    public void Dispose()
    {
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public async Task GetStatus_reports_schema_health_and_drop_signals()
    {
        var impl = new DiagnosticsServiceImpl(_state);

        var status = await impl.GetStatus(new Empty(), null!);

        // Schema health: a fresh DB is in sync with the compiled schema version.
        status.SchemaVersion.Should().Be(HostsDatabase.SchemaVersion);
        status.SchemaVersionOnDisk.Should().Be(HostsDatabase.SchemaVersion);

        // Silent-drop and liveness signals are present (default-clean on a fresh
        // service) — the point is that support can now read them at all.
        status.PersistenceDroppedWrites.Should().Be(0);
        status.PendingConsent.Should().Be(0);
        status.EchUnavailable.Should().Be(0);
        status.KillSwitchEngaged.Should().BeFalse();
        status.FilteringMode.Should().NotBeNullOrEmpty();
        status.ProcessWorkingSetBytes.Should().BeGreaterThan(0);
        status.ProcessPrivateBytes.Should().BeGreaterThan(0);
        status.GcHeapBytes.Should().BeGreaterThan(0);
        status.GcCommittedBytes.Should().BeGreaterThan(0);
        status.GcFragmentedBytes.Should().BeGreaterThanOrEqualTo(0);
        status.SniCaptureAdapters.Should().Be(0);
        status.FirewallCachedPackages.Should().Be(0);
    }

    [Fact]
    public async Task GetStatus_surfaces_persistence_drops_after_saturation()
    {
        // A saturating burst sheds writes; the dropped counter must be visible in
        // status so a support engineer can see the service is shedding work.
        for (var i = 0; i < 5000; i++)
        {
            _state.ActivityPersistence.EnqueueDnsSighting($"flood-{i}.example.com", "edge.exe", null, DateTime.Now);
        }

        var status = await new DiagnosticsServiceImpl(_state).GetStatus(new Empty(), null!);
        status.PersistenceDroppedWrites.Should().BeGreaterThan(0);
    }
}

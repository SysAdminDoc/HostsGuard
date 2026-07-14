using FluentAssertions;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;

namespace HostsGuard.Service.Tests;

public sealed class RemoteSessionMonitorTests : IDisposable
{
    private readonly string _dir = Path.Combine(
        Path.GetTempPath(), $"hg_rdp_monitor_{Guid.NewGuid():N}");
    private readonly HostsDatabase _db;

    public RemoteSessionMonitorTests()
    {
        Directory.CreateDirectory(_dir);
        _db = new HostsDatabase(Path.Combine(_dir, "db.sqlite"));
    }

    [Fact]
    public void Active_session_alerts_once_and_quick_reconnect_coalesces()
    {
        var now = new DateTime(2026, 7, 14, 12, 0, 0, DateTimeKind.Utc);
        var source = new MutableSource(Available(now, active: true));
        using var monitor = new RemoteSessionMonitor(source, _db, () => now);

        monitor.Poll();
        monitor.Poll();
        source.Value = Available(now.AddMinutes(5), active: false);
        now = now.AddMinutes(5);
        monitor.Poll();
        source.Value = Available(now.AddMinutes(1), active: true);
        now = now.AddMinutes(1);
        monitor.Poll();

        var alert = _db.GetAlerts(new AlertFilter(Type: "remote_session", SurfaceOnly: false))
            .Rows.Should().ContainSingle().Subject;
        alert.Subject.Should().Be("session 7");
        alert.Details.Should().Contain("203.0.113.44")
            .And.Contain("alert only, no posture was changed");
    }

    [Fact]
    public void Unavailable_observer_logs_one_stable_degradation_until_recovery()
    {
        var now = new DateTime(2026, 7, 14, 12, 0, 0, DateTimeKind.Utc);
        var source = new MutableSource(new RemoteSessionSnapshot(
            false, "wts_enumeration_failed", now, []));
        using var monitor = new RemoteSessionMonitor(source, _db, () => now);

        monitor.Poll();
        monitor.Poll();

        _db.GetLog(50).Where(row => row.Action == "rdp_observer_unavailable")
            .Should().ContainSingle().Which.Details.Should().Be("wts_enumeration_failed");
        _db.GetAlerts(new AlertFilter(Type: "remote_session", SurfaceOnly: false)).Rows
            .Should().BeEmpty("observation failure must not claim a live RDP session");
    }

    private static RemoteSessionSnapshot Available(DateTime now, bool active) => new(
        true,
        string.Empty,
        now,
        [new RemoteDesktopSession(
            7,
            active ? "active" : "disconnected",
            active,
            "OPS-LAPTOP",
            "203.0.113.44",
            now.AddHours(-1),
            active ? null : now)]);

    public void Dispose()
    {
        _db.Dispose();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    private sealed class MutableSource(RemoteSessionSnapshot value) : IRemoteSessionSource
    {
        public RemoteSessionSnapshot Value { get; set; } = value;
        public RemoteSessionSnapshot Snapshot() => Value;
    }
}

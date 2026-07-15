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
    private readonly FixedHyperVFirewall _hyperVFirewall = new();

    public DiagnosticsHealthTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_diag_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _state = new ServiceState(new HostsEngine(hostsPath), new HostsDatabase(Path.Combine(_dir, "db.sqlite")),
            dataDir: _dir,
            hyperVFirewallInventory: _hyperVFirewall);
    }

    public void Dispose()
    {
        _state.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public async Task GetStatus_reports_schema_health_and_drop_signals()
    {
        var tracker = new ObservationIntegrityTracker("dns_etw");
        tracker.Started();
        tracker.RecordLoss(2, "synthetic loss");
        _state.ObservationHealth = () => new[] { tracker.Snapshot() };
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
        status.ObservationSources.Should().ContainSingle();
        status.ObservationSources[0].Source.Should().Be("dns_etw");
        status.ObservationSources[0].State.Should().Be("degraded");
        status.ObservationSources[0].LossCount.Should().Be(2);
        status.ObservationSources[0].IncompleteSince.Should().NotBeNullOrEmpty();
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

    [Fact]
    public async Task GetStatus_surfaces_active_and_recent_remote_sessions()
    {
        var checkedAt = new DateTime(2026, 7, 14, 12, 0, 0, DateTimeKind.Utc);
        _state.RemoteSessions = new FixedRemoteSessions(new RemoteSessionSnapshot(
            true,
            string.Empty,
            checkedAt,
            [new RemoteDesktopSession(
                4,
                "active",
                true,
                "OPS-LAPTOP",
                "198.51.100.9",
                checkedAt.AddHours(-2),
                null)]));

        var status = await new DiagnosticsServiceImpl(_state).GetStatus(new Empty(), null!);

        status.RemoteSessionObservationAvailable.Should().BeTrue();
        status.RemoteSessionObservationError.Should().BeEmpty();
        status.RemoteSessionCheckedAt.Should().Be(checkedAt.ToString("o"));
        status.RemoteSessions.Should().ContainSingle().Which.Should().Match<RemoteSessionInfo>(session =>
            session.SessionId == 4 && session.Active &&
            session.SourceAddress == "198.51.100.9" && session.ClientName == "OPS-LAPTOP");
    }

    [Fact]
    public async Task HyperV_coverage_maps_effective_creator_and_profile_policy_without_guest_attribution()
    {
        var checkedAt = new DateTime(2026, 7, 14, 17, 0, 0, DateTimeKind.Utc);
        _hyperVFirewall.Snapshot = new HyperVFirewallSnapshot(
            true,
            string.Empty,
            checkedAt,
            [new HostsGuard.Windows.HyperVFirewallWorkload(
                "{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}",
                string.Empty,
                true,
                true,
                "Block",
                "Allow",
                true,
                false,
                [new HostsGuard.Windows.HyperVFirewallProfile("Public", true, "Block", "Allow", false)])]);

        var result = await new DiagnosticsServiceImpl(_state)
            .GetHyperVFirewallCoverage(new Empty(), null!);

        result.Available.Should().BeTrue();
        result.CheckedAt.Should().Be(checkedAt.ToString("o"));
        result.AttributionLimit.Should().Contain("inner-guest processes are not attributed");
        var workload = result.Workloads.Should().ContainSingle().Subject;
        workload.CreatorId.Should().Be("{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}");
        workload.AllowHostPolicyMerge.Should().BeTrue();
        workload.Profiles.Should().ContainSingle().Which.Should().Match<HostsGuard.Contracts.HyperVFirewallProfile>(
            profile => profile.Name == "Public" && profile.DefaultInboundAction == "Block" &&
                       profile.DefaultOutboundAction == "Allow" && !profile.AllowLocalFirewallRules);
    }

    private sealed class FixedRemoteSessions(RemoteSessionSnapshot snapshot) : IRemoteSessionSource
    {
        public RemoteSessionSnapshot Snapshot() => snapshot;
    }

    private sealed class FixedHyperVFirewall : IHyperVFirewallInventory
    {
        public HyperVFirewallSnapshot Snapshot { get; set; } = new(
            true,
            string.Empty,
            DateTime.UtcNow,
            []);

        public Task<HyperVFirewallSnapshot> SnapshotAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(Snapshot);
    }
}

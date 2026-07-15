using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service.Tests;

[SupportedOSPlatform("windows")]
public sealed class WfpFilterDriftMonitorTests : IDisposable
{
    private static readonly Guid FilterKey = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid LayerKey = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid SubLayerKey = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private readonly string _dir;
    private readonly HostsDatabase _db;
    private readonly FakeInventory _inventory = new();

    public WfpFilterDriftMonitorTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_wfp_drift_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _db = new HostsDatabase(Path.Combine(_dir, "db.sqlite"));
    }

    public void Dispose()
    {
        _db.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public void First_successful_capture_seeds_without_alerting_or_mutating_WFP()
    {
        _inventory.Filters = [Filter(FilterKey)];
        using var monitor = new WfpFilterDriftMonitor(_inventory, _db);

        var result = monitor.CheckNow();

        result.Available.Should().BeTrue();
        result.BaselineCreated.Should().BeTrue();
        result.AlertRaised.Should().BeFalse();
        _db.GetAlerts(new AlertFilter(Type: "wfp_filter_drift", IncludeRead: true)).Rows.Should().BeEmpty();
        _db.GetMeta(WfpFilterDriftMonitor.BaselineMetaKey).Should().Contain(FilterKey.ToString("D"));
        _inventory.SnapshotCalls.Should().Be(1, "the inventory interface exposes no mutation operation");
    }

    [Fact]
    public void Added_persistent_filter_raises_alert_with_layer_sublayer_and_action_evidence_once()
    {
        using var monitor = new WfpFilterDriftMonitor(_inventory, _db);
        monitor.CheckNow().BaselineCreated.Should().BeTrue();
        _inventory.Filters = [Filter(FilterKey)];

        var first = monitor.CheckNow();
        var repeated = monitor.CheckNow();

        first.AlertRaised.Should().BeTrue();
        first.Changes.Should().ContainSingle().Which.ChangeKind.Should().Be("added");
        repeated.AlertRaised.Should().BeFalse();
        var alert = _db.GetAlerts(new AlertFilter(Type: "wfp_filter_drift", IncludeRead: true))
            .Rows.Should().ContainSingle().Subject;
        alert.Title.Should().Be("Persistent WFP filter appeared");
        alert.Subject.Should().Be(FilterKey.ToString("D"));
        alert.Details.Should().Contain("lifetime=persistent")
            .And.Contain($"layer=ALE connect [{LayerKey:D}]")
            .And.Contain($"sublayer=Vendor inspection [{SubLayerKey:D}]")
            .And.Contain("action=callout-terminating");
    }

    [Fact]
    public void Diff_reports_changed_and_removed_filters_without_advancing_the_baseline()
    {
        _inventory.Filters = [Filter(FilterKey)];
        using var monitor = new WfpFilterDriftMonitor(_inventory, _db);
        monitor.CheckNow();

        _inventory.Filters = [Filter(FilterKey, action: "block")];
        monitor.Inspect().Changes.Should().ContainSingle(change =>
            change.ChangeKind == "changed" && change.Action == "block");

        _inventory.Filters = [];
        monitor.Inspect().Changes.Should().ContainSingle(change =>
            change.ChangeKind == "removed" && change.FilterKey == FilterKey);
        _db.GetMeta(WfpFilterDriftMonitor.BaselineMetaKey).Should().Contain("callout-terminating");
    }

    [Fact]
    public async Task Diagnostics_RPC_is_read_only_and_maps_drift_evidence()
    {
        _inventory.Filters = [Filter(FilterKey)];
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        using var state = new ServiceState(
            new HostsEngine(hostsPath),
            new HostsDatabase(Path.Combine(_dir, "rpc.sqlite")),
            dataDir: _dir,
            wfpFilterInventory: _inventory);
        state.WfpFilterDrift!.CheckNow();
        _inventory.Filters = [Filter(FilterKey), Filter(Guid.Parse("44444444-4444-4444-4444-444444444444"), action: "block")];

        var report = await new DiagnosticsServiceImpl(state).GetWfpFilterDrift(new Empty(), null!);

        report.Available.Should().BeTrue();
        report.BaselineExists.Should().BeTrue();
        report.CurrentFilterCount.Should().Be(2);
        report.AlertOnly.Should().BeTrue();
        report.Changes.Should().ContainSingle(change =>
            change.ChangeKind == "added" && change.LayerName == "ALE connect" &&
            change.SublayerName == "Vendor inspection" && change.Action == "block");
        state.Db.GetAlerts(new AlertFilter(Type: "wfp_filter_drift", IncludeRead: true)).Rows.Should().BeEmpty(
            "the diagnostics RPC inspects but does not alert or mutate the baseline");
    }

    private static WfpPersistentFilter Filter(Guid key, string action = "callout-terminating") => new(
        42,
        key,
        "Vendor persistent filter",
        "persistent",
        LayerKey,
        "ALE connect",
        SubLayerKey,
        "Vendor inspection",
        action,
        action.StartsWith("callout", StringComparison.Ordinal)
            ? Guid.Parse("55555555-5555-5555-5555-555555555555")
            : null,
        false);

    private sealed class FakeInventory : IWfpFilterInventory
    {
        public IReadOnlyList<WfpPersistentFilter> Filters { get; set; } = [];
        public int SnapshotCalls { get; private set; }

        public WfpFilterSnapshot Snapshot()
        {
            SnapshotCalls++;
            return new WfpFilterSnapshot(
                true,
                string.Empty,
                new DateTime(2026, 7, 15, 2, 0, 0, DateTimeKind.Utc),
                Filters);
        }
    }
}

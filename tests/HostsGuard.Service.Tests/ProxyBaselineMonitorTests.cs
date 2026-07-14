using System.Runtime.Versioning;
using System.Text.Json;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Service.Tests;

[SupportedOSPlatform("windows")]
public sealed class ProxyBaselineMonitorTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "hg_proxy_" + Guid.NewGuid().ToString("N"));
    private readonly HostsDatabase _db;
    private readonly FakeProxySnapshotSource _source = new();

    public ProxyBaselineMonitorTests()
    {
        Directory.CreateDirectory(_dir);
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
    }

    [Fact]
    public void First_check_seeds_per_sid_and_machine_baseline_without_alerting()
    {
        _source.Settings =
        [
            new("wininet", "S-1-5-21-100", "ProxyEnable", "1"),
            new("wininet", "S-1-5-21-100", "ProxyServer", "http://proxy.example:8080"),
            new("winhttp", "machine", "ProxyServer", null),
        ];
        using var monitor = new ProxyBaselineMonitor(_source, _db);

        var result = monitor.CheckNow();

        result.BaselineCreated.Should().BeTrue();
        result.AlertCreated.Should().BeFalse();
        _db.GetAlerts(new AlertFilter(Type: "proxy_tamper", SurfaceOnly: false)).Rows.Should().BeEmpty();
        var json = _db.GetMeta(ProxyBaselineMonitor.BaselineMetaKey);
        json.Should().Contain("S-1-5-21-100").And.Contain("machine");
    }

    [Fact]
    public void Changed_user_and_machine_values_emit_one_aggregate_before_after_alert_once()
    {
        _source.Settings = Baseline();
        using var monitor = new ProxyBaselineMonitor(_source, _db);
        monitor.CheckNow();
        _source.Settings =
        [
            new("wininet", "S-1-5-21-100", "ProxyEnable", "1"),
            new("wininet", "S-1-5-21-100", "AutoConfigURL", "https://pac.example/new.pac"),
            new("winhttp", "machine", "ProxyServer", "proxy.example:3128"),
        ];

        var first = monitor.CheckNow();
        var repeated = monitor.CheckNow();

        first.AlertCreated.Should().BeTrue();
        first.Changes.Should().HaveCount(3);
        repeated.AlertCreated.Should().BeFalse();
        var alerts = _db.GetAlerts(new AlertFilter(Type: "proxy_tamper", SurfaceOnly: false)).Rows;
        alerts.Should().ContainSingle();
        alerts.Single().Details.Should()
            .Contain("wininet/S-1-5-21-100/AutoConfigURL")
            .And.Contain("https://pac.example/old.pac")
            .And.Contain("https://pac.example/new.pac")
            .And.Contain("winhttp/machine/ProxyServer");
        _db.GetEvents(new EventLogFilter(Action: "proxy_baseline_changed")).Rows.Should().ContainSingle();
    }

    [Fact]
    public void A_different_drift_after_first_alert_emits_one_new_alert()
    {
        _source.Settings = Baseline();
        using var monitor = new ProxyBaselineMonitor(_source, _db);
        monitor.CheckNow();
        _source.Settings = [new("winhttp", "machine", "ProxyServer", "one.example:80")];
        monitor.CheckNow();
        _source.Settings = [new("winhttp", "machine", "ProxyServer", "two.example:80")];

        monitor.CheckNow().AlertCreated.Should().BeTrue();

        // Alerts with the same type/subject/action are intentionally coalesced by
        // the inbox, while the immutable event log retains both distinct drifts.
        _db.GetAlerts(new AlertFilter(Type: "proxy_tamper", SurfaceOnly: false)).Rows
            .Should().ContainSingle(a => a.Details.Contains("two.example:80", StringComparison.Ordinal));
        _db.GetEvents(new EventLogFilter(Action: "proxy_baseline_changed")).Rows.Should().HaveCount(2);
    }

    [Fact]
    public void Accept_current_advances_baseline_and_does_not_change_system_settings()
    {
        _source.Settings = Baseline();
        using var monitor = new ProxyBaselineMonitor(_source, _db);
        monitor.CheckNow();
        _source.Settings = [new("winhttp", "machine", "ProxyServer", "approved.example:8080")];
        monitor.CheckNow().AlertCreated.Should().BeTrue();

        monitor.AcceptCurrent().Should().Be(1);
        var after = monitor.CheckNow();

        after.Changes.Should().BeEmpty();
        after.AlertCreated.Should().BeFalse();
        _source.SnapshotCalls.Should().Be(4);
        _db.GetEvents(new EventLogFilter(Action: "proxy_baseline_accepted")).Rows.Should().ContainSingle();
    }

    [Fact]
    public void Inspect_is_side_effect_free_and_returns_all_baseline_and_current_rows()
    {
        _source.Settings = Baseline();
        using var monitor = new ProxyBaselineMonitor(_source, _db);
        var beforeSeed = monitor.Inspect();
        _db.GetMeta(ProxyBaselineMonitor.BaselineMetaKey).Should().BeNull();
        beforeSeed.BaselineExists.Should().BeFalse();
        beforeSeed.Changed.Should().BeFalse();

        monitor.CheckNow();
        _source.Settings =
        [
            new("wininet", "S-1-5-21-100", "ProxyEnable", "1"),
            new("winhttp", "machine", "ProxyServer", "proxy.example:8080"),
        ];

        var inspection = monitor.Inspect();

        inspection.BaselineExists.Should().BeTrue();
        inspection.Changed.Should().BeTrue();
        inspection.Entries.Should().HaveCount(3);
        inspection.Entries.Should().Contain(entry =>
            entry.Name == "ProxyEnable" && entry.BaselineValue == "0" && entry.CurrentValue == "1" && entry.Changed);
        inspection.Entries.Should().Contain(entry =>
            entry.Name == "AutoConfigURL" && entry.BaselinePresent && !entry.CurrentPresent && entry.Changed);
        _db.GetAlerts(new AlertFilter(Type: "proxy_tamper", SurfaceOnly: false)).Rows.Should().BeEmpty();
        _db.GetEvents(new EventLogFilter(Action: "proxy_baseline_changed")).Rows.Should().BeEmpty();
    }

    [Fact]
    public void Baseline_persists_across_monitor_instances()
    {
        _source.Settings = Baseline();
        using (var first = new ProxyBaselineMonitor(_source, _db))
        {
            first.CheckNow();
        }

        _source.Settings = [new("winhttp", "machine", "ProxyServer", "changed.example:80")];
        using var second = new ProxyBaselineMonitor(_source, _db);

        second.CheckNow().AlertCreated.Should().BeTrue();
    }

    [Fact]
    public void Persisted_state_and_alerts_redact_credentials_and_pac_tokens()
    {
        const string secret = "do-not-store-this-token";
        _source.Settings =
        [
            new("wininet", "S-1-5-21-100", "ProxyServer", $"http://user:{secret}@proxy.example:8080"),
            new("wininet", "S-1-5-21-100", "AutoConfigURL", $"https://pac.example/config.pac?token={secret}"),
        ];
        using var monitor = new ProxyBaselineMonitor(_source, _db);
        monitor.CheckNow();

        var persisted = _db.GetMeta(ProxyBaselineMonitor.BaselineMetaKey)!;
        persisted.Should().NotContain(secret).And.NotContain("user:");
        persisted.Should().Contain("http://proxy.example:8080").And.Contain("https://pac.example/config.pac");

        _source.Settings = [new("wininet", "S-1-5-21-100", "ProxyServer", $"http://user:new-{secret}@other.example:8080")];
        monitor.CheckNow();
        var alert = _db.GetAlerts(new AlertFilter(Type: "proxy_tamper", SurfaceOnly: false)).Rows.Single();
        alert.Details.Should().NotContain(secret).And.NotContain("user:");
    }

    [Fact]
    public void Null_and_empty_are_distinct_states()
    {
        var absent = ProxyBaselineMonitor.Normalize([new("wininet", "sid", "AutoConfigURL", null)]);
        var empty = ProxyBaselineMonitor.Normalize([new("wininet", "sid", "AutoConfigURL", string.Empty)]);

        var change = ProxyBaselineMonitor.Diff(absent, empty).Should().ContainSingle().Subject;
        change.Before.Should().Be("<absent>");
        change.After.Should().Be("<empty>");
    }

    [Fact]
    public void Duplicate_snapshot_identity_is_rejected()
    {
        var act = () => ProxyBaselineMonitor.Normalize(
        [
            new("wininet", "sid", "ProxyEnable", "0"),
            new("WININET", "SID", "ProxyEnable", "1"),
        ]);

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Trusted_fingerprint_detects_a_secret_only_change_without_persisting_the_secret()
    {
        _source.Settings = [new("wininet", "sid", "ProxyServer", "http://proxy.example:8080", new string('a', 64))];
        using var monitor = new ProxyBaselineMonitor(_source, _db);
        monitor.CheckNow();
        _source.Settings = [new("wininet", "sid", "ProxyServer", "http://proxy.example:8080", new string('b', 64))];

        var result = monitor.CheckNow();

        result.AlertCreated.Should().BeTrue();
        result.Changes.Should().ContainSingle(change =>
            change.Before == "http://proxy.example:8080/" && change.After == "http://proxy.example:8080/");
        _db.GetMeta(ProxyBaselineMonitor.BaselineMetaKey).Should().NotContain(new string('b', 64));
    }

    [Fact]
    public void Malformed_trusted_fingerprint_is_rejected()
    {
        var act = () => ProxyBaselineMonitor.Normalize(
            [new("wininet", "sid", "ProxyEnable", "1", new string('A', 64))]);

        act.Should().Throw<ArgumentException>().WithMessage("*lowercase SHA-256*");
    }

    [Fact]
    public async Task Start_polls_periodically_and_is_idempotent()
    {
        _source.Settings = Baseline();
        using var monitor = new ProxyBaselineMonitor(_source, _db, TimeSpan.FromMilliseconds(25));
        monitor.CheckNow();
        _source.Settings = [new("winhttp", "machine", "ProxyServer", "timer.example:8080")];

        monitor.Start();
        monitor.Start();
        var deadline = DateTime.UtcNow.AddSeconds(3);
        while (DateTime.UtcNow < deadline
               && _db.GetAlerts(new AlertFilter(Type: "proxy_tamper", SurfaceOnly: false)).Rows.Count == 0)
        {
            await Task.Delay(20);
        }

        _db.GetAlerts(new AlertFilter(Type: "proxy_tamper", SurfaceOnly: false)).Rows.Should().ContainSingle();
        _db.GetEvents(new EventLogFilter(Action: "proxy_baseline_changed")).Rows.Should().ContainSingle();
    }

    [Fact]
    public async Task Diagnostics_inspects_and_explicitly_accepts_the_current_baseline()
    {
        var stateDir = Path.Combine(_dir, "rpc");
        Directory.CreateDirectory(stateDir);
        var hostsPath = Path.Combine(stateDir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _source.Settings = Baseline();
        using var state = new ServiceState(
            new HostsEngine(hostsPath),
            new HostsDatabase(Path.Combine(stateDir, "state.db")),
            dataDir: stateDir,
            proxySnapshotSource: _source);
        state.ProxyBaseline!.CheckNow();
        _source.Settings = [new("winhttp", "machine", "ProxyServer", "rpc.example:8080")];
        var diagnostics = new DiagnosticsServiceImpl(state);

        var report = await diagnostics.InspectProxyBaseline(new Empty(), null!);

        report.BaselineExists.Should().BeTrue();
        report.Changed.Should().BeTrue();
        report.Entries.Should().Contain(entry =>
            entry.Scope == "winhttp" && entry.Sid.Length == 0 && entry.Setting == "ProxyServer" && entry.Changed);

        var accepted = await diagnostics.AcceptProxyBaseline(new Empty(), null!);
        accepted.Ok.Should().BeTrue();
        (await diagnostics.InspectProxyBaseline(new Empty(), null!)).Changed.Should().BeFalse();
    }

    private static IReadOnlyList<ProxyConfigurationSetting> Baseline() =>
    [
        new("wininet", "S-1-5-21-100", "ProxyEnable", "0"),
        new("wininet", "S-1-5-21-100", "AutoConfigURL", "https://pac.example/old.pac"),
        new("winhttp", "machine", "ProxyServer", null),
    ];

    public void Dispose()
    {
        _db.Dispose();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    private sealed class FakeProxySnapshotSource : IProxyConfigurationSnapshotSource
    {
        public IReadOnlyList<ProxyConfigurationSetting> Settings { get; set; } = Array.Empty<ProxyConfigurationSetting>();
        public int SnapshotCalls { get; private set; }

        public IReadOnlyList<ProxyConfigurationSetting> Snapshot()
        {
            SnapshotCalls++;
            return Settings;
        }
    }
}

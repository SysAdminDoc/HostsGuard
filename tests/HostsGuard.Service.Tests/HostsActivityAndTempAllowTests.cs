using System.Runtime.Versioning;
using FluentAssertions;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Ipc;
using HostsGuard.Windows;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-021 service surface: temp-allow with persisted expiry re-arm, the raw
/// hosts editor RPCs, hidden feed roots, the activity snapshot, and the live
/// WatchDns stream — all over the real pipe transport.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HostsActivityAndTempAllowTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private string _pipe = null!;
    private string _token = null!;
    private string _hostsPath = null!;
    private string _dbPath = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_ta_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _hostsPath = Path.Combine(_dir, "hosts");
        _dbPath = Path.Combine(_dir, "hostsguard.db");
        File.WriteAllText(_hostsPath, "# hosts\n");

        _state = new ServiceState(new HostsEngine(_hostsPath), new HostsDatabase(_dbPath));
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.TaTest." + Guid.NewGuid().ToString("N");
        _app = ServiceHost.Build(_state, _token, _pipe);
        await _app.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _app.DisposeAsync();
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private HostsControl.HostsControlClient Hosts(Grpc.Net.Client.GrpcChannel ch) => new(ch);

    [Fact]
    public async Task Sparkline_reports_24h_hourly_hits_for_a_domain_root()
    {
        // Sightings on the same root roll up hourly; GetSparkline returns 24 buckets.
        _state.RecordDns("ads.tracker.com");
        _state.RecordDns("cdn.tracker.com"); // same root
        _state.RecordDns("unrelated.net");
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var spark = await Hosts(channel).GetSparklineAsync(new DomainRequest { Domain = "ads.tracker.com" });

        spark.Hits.Should().HaveCount(24);
        spark.Hits[^1].Should().Be(2);      // current hour: both tracker.com sightings
        spark.Hits.Sum().Should().Be(2);    // unrelated.net excluded
    }

    [Fact]
    public async Task TempAllow_unblocks_now_and_lists_pending_window()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = Hosts(channel);
        await hosts.BlockAsync(new DomainRequest { Domain = "cdn.example.com" });

        var ack = await hosts.TempAllowAsync(new TempAllowRequest { Domain = "cdn.example.com", Minutes = 30 });

        ack.Ok.Should().BeTrue();
        _state.Hosts.GetBlocked().Should().NotContain("cdn.example.com");
        var pending = await hosts.ListTempAllowsAsync(new Empty());
        pending.Entries.Should().ContainSingle(e => e.Domain == "cdn.example.com");
        pending.Entries[0].Expires.ToDateTime().Should().BeAfter(DateTime.UtcNow.AddMinutes(25));
    }

    [Fact]
    public async Task TempAllow_rejects_invalid_duration()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var ack = await Hosts(channel).TempAllowAsync(new TempAllowRequest { Domain = "x.example.com", Minutes = 0 });

        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/invalid_duration");
    }

    [Fact]
    public void Expired_temp_allow_reverts_on_service_restart()
    {
        // Simulate: a temp-allow was persisted, then the service went down past
        // its expiry. On the next ServiceState construction it must re-block.
        _state.Db.AddDomain("late.example.com", "whitelisted", "temp_allow");
        _state.Db.SetTempAllow("late.example.com", DateTime.UtcNow.AddMinutes(-5));

        using var restarted = new ServiceState(new HostsEngine(_hostsPath), new HostsDatabase(_dbPath));

        restarted.Hosts.GetBlocked().Should().Contain("late.example.com");
        restarted.Db.GetTempAllows().Should().BeEmpty();
        restarted.Db.GetDomains(status: "blocked").Should().Contain(d => d.Domain == "late.example.com" && d.Source == "temp_reverted");
    }

    [Fact]
    public void Expired_temp_allow_does_not_override_a_manual_change()
    {
        _state.Db.AddDomain("manual.example.com", "whitelisted", "manual"); // user allowed it since
        _state.Db.SetTempAllow("manual.example.com", DateTime.UtcNow.AddMinutes(-5));

        using var restarted = new ServiceState(new HostsEngine(_hostsPath), new HostsDatabase(_dbPath));

        restarted.Hosts.GetBlocked().Should().NotContain("manual.example.com");
        restarted.Db.GetTempAllows().Should().BeEmpty();
    }

    [Fact]
    public async Task Raw_hosts_text_round_trips_through_the_engine()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = Hosts(channel);

        var before = await hosts.GetHostsTextAsync(new Empty());
        var edited = before.Text + "\n0.0.0.0 rawedit.example.com";
        var ack = await hosts.SetHostsTextAsync(new HostsText { Text = edited });

        ack.Ok.Should().BeTrue();
        _state.Hosts.GetBlocked().Should().Contain("rawedit.example.com");
        (await hosts.GetHostsTextAsync(new Empty())).Text.Should().Contain("rawedit.example.com");
    }

    [Fact]
    public async Task Hidden_roots_scope_the_activity_snapshot()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = Hosts(channel);
        _state.RecordDns("tracker.chatty.com", "chrome.exe");
        _state.RecordDns("api.useful.com", "app.exe");

        await hosts.HideRootAsync(new DomainRequest { Domain = "tracker.chatty.com" });

        var visible = await hosts.GetActivityAsync(new ActivityRequest());
        visible.Rows.Should().OnlyContain(r => r.Root != "chatty.com");
        visible.Rows.Should().Contain(r => r.Domain == "api.useful.com");

        var all = await hosts.GetActivityAsync(new ActivityRequest { IncludeHidden = true });
        all.Rows.Should().Contain(r => r.Domain == "tracker.chatty.com" && r.Hidden);

        await hosts.UnhideRootAsync(new DomainRequest { Domain = "sub.chatty.com" });
        var after = await hosts.GetActivityAsync(new ActivityRequest());
        after.Rows.Should().Contain(r => r.Domain == "tracker.chatty.com" && !r.Hidden);
    }

    [Fact]
    public async Task Activity_search_uses_the_shared_dsl()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        _state.RecordDns("ads.doubleclick.net", "chrome.exe");
        _state.RecordDns("clean.example.com", "app.exe");

        var byProcess = await Hosts(channel).GetActivityAsync(new ActivityRequest { Search = "process:chrome" });
        byProcess.Rows.Should().ContainSingle(r => r.Domain == "ads.doubleclick.net");

        var negated = await Hosts(channel).GetActivityAsync(new ActivityRequest { Search = "!doubleclick" });
        negated.Rows.Should().OnlyContain(r => !r.Domain.Contains("doubleclick"));
    }

    [Fact]
    public async Task WatchDns_streams_recorded_sightings_live()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var monitoring = new Monitoring.MonitoringClient(channel);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var call = monitoring.WatchDns(new Empty(), cancellationToken: cts.Token);

        // Give the stream a beat to subscribe before publishing.
        await Task.Delay(250, cts.Token);
        _state.RecordDns("live.example.com", "edge.exe", 1234, blocked: true);

        (await call.ResponseStream.MoveNext(cts.Token)).Should().BeTrue();
        var ev = call.ResponseStream.Current;
        ev.Domain.Should().Be("live.example.com");
        ev.Process.Should().Be("edge.exe");
        ev.Blocked.Should().BeTrue();

        // The sighting also landed in the persistent feed.
        _state.Db.GetFeed().Should().Contain(f => f.Domain == "live.example.com" && f.Hits == 1);
    }
}

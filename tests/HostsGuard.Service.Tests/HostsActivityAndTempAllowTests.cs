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
    public async Task Activity_rows_carry_reference_blocklist_membership()
    {
        _state.Db.ReplaceListIndex("HaGezi Ultimate", new[] { "flagged.example.com" });
        _state.Db.ReplaceListIndex("OISD Full", new[] { "flagged.example.com" });
        _state.RecordDns("flagged.example.com");
        _state.RecordDns("clean.example.org");
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var list = await Hosts(channel).GetActivityAsync(new ActivityRequest());

        list.Rows.Single(r => r.Domain == "flagged.example.com").Blocklists
            .Should().BeEquivalentTo(new[] { "HaGezi Ultimate", "OISD Full" });
        list.Rows.Single(r => r.Domain == "clean.example.org").Blocklists.Should().BeEmpty();
    }

    [Fact]
    public async Task Activity_rows_prefer_curated_purposes_and_fall_back_to_learned_ones()
    {
        // pagead2.googlesyndication.com is in the curated purpose table; the
        // learned entry must not override it. The unknown domain uses the
        // AI-researched knowledge.
        _state.Db.UpsertAiKnowledge("purpose", "pagead2.googlesyndication.com", "AI override attempt", "test");
        _state.Db.UpsertAiKnowledge("purpose", "obscure.example.com", "Obscure vendor telemetry", "test");
        _state.RecordDns("pagead2.googlesyndication.com");
        _state.RecordDns("obscure.example.com");
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var list = await Hosts(channel).GetActivityAsync(new ActivityRequest());

        list.Rows.Single(r => r.Domain == "pagead2.googlesyndication.com").Purpose
            .Should().NotBeEmpty().And.NotBe("AI override attempt");
        list.Rows.Single(r => r.Domain == "obscure.example.com").Purpose
            .Should().Be("Obscure vendor telemetry");
    }

    [Fact]
    public async Task Blocking_a_curated_domain_assigns_its_default_category()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        await Hosts(channel).BlockAsync(new DomainRequest { Domain = "pagead2.googlesyndication.com" });

        var list = await Hosts(channel).ListDomainsAsync(new ListDomainsRequest());

        list.Domains.Single(d => d.Domain == "pagead2.googlesyndication.com")
            .Category.Should().Be("Advertising");
    }

    [Fact]
    public async Task HideDomains_hides_exact_entries_but_leaves_new_subdomains_visible()
    {
        // Two subdomains of the same root are listed; hiding the group stores
        // both exact domains. A NEW subdomain later must still surface (unlike
        // a root hide, which would blanket it).
        _state.RecordDns("a.cdn.example.com");
        _state.RecordDns("b.cdn.example.com");
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = Hosts(channel);

        var req = new HideDomainsRequest();
        req.Domains.Add("a.cdn.example.com");
        req.Domains.Add("b.cdn.example.com");
        await hosts.HideDomainsAsync(req);

        var visible = await hosts.GetActivityAsync(new ActivityRequest());
        visible.Rows.Select(r => r.Domain).Should().NotContain("a.cdn.example.com").And.NotContain("b.cdn.example.com");

        // A brand-new subdomain of the same root is still shown.
        _state.RecordDns("c.cdn.example.com");
        var after = await hosts.GetActivityAsync(new ActivityRequest());
        after.Rows.Select(r => r.Domain).Should().Contain("c.cdn.example.com");

        // Show hidden reveals the hidden pair.
        var withHidden = await hosts.GetActivityAsync(new ActivityRequest { IncludeHidden = true });
        withHidden.Rows.Select(r => r.Domain).Should().Contain("a.cdn.example.com");
    }

    [Fact]
    public async Task HideDomains_hides_SRV_style_names_that_fail_registrable_domain_validation()
    {
        // Regression: SRV/underscore names (e.g. _ldap._tcp.dc._msdcs.home.arpa)
        // are real feed entries but fail LooksLikeDomain, so the hide RPC used to
        // drop them silently and they could never be hidden.
        const string srv = "_ldap._tcp.dc._msdcs.home.arpa";
        _state.RecordDns(srv);
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = Hosts(channel);

        var req = new HideDomainsRequest();
        req.Domains.Add(srv);
        var ack = await hosts.HideDomainsAsync(req);
        ack.Message.Should().Contain(srv);

        var visible = await hosts.GetActivityAsync(new ActivityRequest());
        visible.Rows.Select(r => r.Domain).Should().NotContain(srv);
        var withHidden = await hosts.GetActivityAsync(new ActivityRequest { IncludeHidden = true });
        withHidden.Rows.Select(r => r.Domain).Should().Contain(srv);
    }

    [Fact]
    public async Task Block_returns_a_typed_error_when_the_hosts_file_is_held()
    {
        // A scanner-style persistent hold (read handle, no delete share) must
        // surface as an actionable Ack, not an opaque handler exception.
        using var hold = new FileStream(_hostsPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var channel = NamedPipeChannel.Create(_token, _pipe);

        var ack = await Hosts(channel).BlockAsync(new DomainRequest { Domain = "locked.example.com" });

        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/hosts_locked");
        ack.Message.Should().Contain("locked");
    }

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

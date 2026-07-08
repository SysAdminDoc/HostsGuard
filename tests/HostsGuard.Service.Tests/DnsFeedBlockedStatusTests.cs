using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// The live DNS feed must carry the authoritative managed "blocked" status —
/// the ETW event can't know it, so RecordDns fills it from the DB. Without this
/// the UI's "Hide blocked" toggle never sticks (live events re-add blocked
/// domains as normal rows).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DnsFeedBlockedStatusTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;

    public DnsFeedBlockedStatusTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_feedblk_" + Guid.NewGuid().ToString("N"));
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
    public async Task RecordDns_marks_blocked_from_the_managed_status()
    {
        _state.Db.AddDomain("ads.tracker.com", "blocked", "manual");
        using var sub = _state.Bus.Subscribe<DnsEvent>();

        _state.RecordDns("ads.tracker.com");
        var blockedEv = await sub.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        blockedEv.Blocked.Should().BeTrue();

        _state.RecordDns("unmanaged.example.com");
        var plainEv = await sub.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        plainEv.Blocked.Should().BeFalse();
    }

    [Fact]
    public async Task Whitelisted_domains_are_not_reported_blocked()
    {
        _state.Db.AddDomain("safe.example.com", "whitelisted", "manual");
        using var sub = _state.Bus.Subscribe<DnsEvent>();

        _state.RecordDns("safe.example.com");
        var ev = await sub.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        ev.Blocked.Should().BeFalse();
    }

    [Fact]
    public async Task Live_events_carry_the_hidden_flag_so_hides_do_not_bounce_back()
    {
        // Seed a feed row, hide the exact domain, then re-sight it: the live
        // event must report Hidden=true (the "coming back" bug).
        _state.RecordDns("cdn.example.com");
        await _state.FlushActivityPersistenceAsync();
        _state.Db.HideDomains(new[] { "cdn.example.com" });
        using var sub = _state.Bus.Subscribe<DnsEvent>();

        _state.RecordDns("cdn.example.com");
        var ev = await sub.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        ev.Hidden.Should().BeTrue();
    }

    [Fact]
    public async Task Hidden_root_marks_every_subdomain_hidden_in_the_live_feed()
    {
        _state.Db.HideRoot("tracker.com");
        using var sub = _state.Bus.Subscribe<DnsEvent>();

        _state.RecordDns("a.tracker.com");
        var ev = await sub.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        ev.Hidden.Should().BeTrue();
    }
}

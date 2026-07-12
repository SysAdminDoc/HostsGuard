using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-188: when the user hand-edits the hosts file, the coordinator dedupes and
/// organizes the file, curated-categorizes entries, and adopts the newly-added
/// sink-block domains as managed "manual" rows.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HostsAdoptionCoordinatorTests : IDisposable
{
    private readonly string _dir;
    private readonly string _hostsPath;
    private readonly HostsDatabase _db;
    private readonly HostsEngine _hosts;
    private readonly HostsAdoptionCoordinator _adopt;

    public HostsAdoptionCoordinatorTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_adopt_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(_hostsPath, "# hosts\n");
        _db = new HostsDatabase(Path.Combine(_dir, "db.sqlite"));
        _hosts = new HostsEngine(_hostsPath);
        _adopt = new HostsAdoptionCoordinator(_hosts, _db);
    }

    public void Dispose()
    {
        _db.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private void WriteHosts(params string[] lines) => File.WriteAllText(_hostsPath, string.Join('\n', lines) + "\n");

    [Fact]
    public void Enabled_defaults_on_and_persists_the_toggle()
    {
        _adopt.Enabled.Should().BeTrue("adoption is on unless explicitly disabled");
        _adopt.SetEnabled(false);
        _adopt.Enabled.Should().BeFalse();
        _adopt.SetEnabled(true);
        _adopt.Enabled.Should().BeTrue();
    }

    [Fact]
    public void Hand_added_block_entries_are_adopted_as_manual_rows()
    {
        WriteHosts("0.0.0.0 ads.example.com", "127.0.0.1 tracker.test");

        var outcome = _adopt.AdoptNow("test");

        outcome.Adopted.Should().Be(2);
        outcome.HasSuspiciousRedirect.Should().BeFalse();
        var rows = _db.GetDomains();
        rows.Should().Contain(r => r.Domain == "ads.example.com" && r.Status == "blocked" && r.Source == "manual");
        rows.Should().Contain(r => r.Domain == "tracker.test" && r.Source == "manual");
    }

    [Fact]
    public void Second_pass_adopts_nothing_new_and_is_idempotent()
    {
        WriteHosts("0.0.0.0 ads.example.com");
        _adopt.AdoptNow("first").Adopted.Should().Be(1);

        var again = _adopt.AdoptNow("second");
        again.Adopted.Should().Be(0);
        again.Organized.Should().Be(0, "an already-organized file is a fixed point");
    }

    [Fact]
    public void Duplicate_entries_are_deduped_on_organize()
    {
        WriteHosts("0.0.0.0 dup.example.com", "0.0.0.0 dup.example.com", "0.0.0.0 dup.example.com");

        _adopt.AdoptNow("test");

        var blockLines = File.ReadAllLines(_hostsPath)
            .Count(l => l.Trim() == "0.0.0.0 dup.example.com");
        blockLines.Should().Be(1, "the organize pass keeps one entry per domain");
    }

    [Fact]
    public void Curated_categories_are_assigned_to_adopted_domains()
    {
        // doubleclick.net is in the curated ad-network table.
        WriteHosts("0.0.0.0 doubleclick.net");

        _adopt.AdoptNow("test");

        var row = _db.GetDomains().Single(r => r.Domain == "doubleclick.net");
        row.Category.Should().NotBeNullOrEmpty("a curated domain gets its category without any AI call");
    }

    [Fact]
    public void A_domain_redirected_to_a_real_ip_is_flagged_suspicious_and_not_adopted()
    {
        WriteHosts("93.184.216.34 www.bank.example");

        var outcome = _adopt.AdoptNow("test");

        outcome.HasSuspiciousRedirect.Should().BeTrue();
        outcome.Adopted.Should().Be(0, "a redirect to a routable IP is not a block");
        _db.GetDomains().Should().NotContain(r => r.Domain == "www.bank.example");
    }

    [Fact]
    public void Sink_and_broadcast_prefixes_are_never_treated_as_redirects()
    {
        var lines = new[]
        {
            "0.0.0.0 a.example.com",
            "127.0.0.1 b.example.com",
            ":: c.example.com",
            "255.255.255.255 d.example.com",
            "# a comment",
        };

        HostsAdoptionCoordinator.CountSuspiciousRedirects(lines).Should().Be(0);
    }

    [Fact]
    public void An_existing_managed_domain_is_not_re_adopted()
    {
        _db.AddDomain("already.example.com", "blocked", "cli");
        WriteHosts("0.0.0.0 already.example.com", "0.0.0.0 fresh.example.com");

        var outcome = _adopt.AdoptNow("test");

        outcome.Adopted.Should().Be(1, "only the domain not already in the DB is adopted");
        _db.GetDomainSource("already.example.com").Should().Be("cli", "an existing row keeps its provenance");
    }

    [Fact]
    public void Count_unadopted_reflects_hand_added_backlog()
    {
        WriteHosts("0.0.0.0 one.example.com", "0.0.0.0 two.example.com");
        _adopt.CountUnadopted().Should().Be(2);

        _adopt.AdoptNow("test");
        _adopt.CountUnadopted().Should().Be(0);
    }
}

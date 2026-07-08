using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-108: per-(PID, remote-IP) byte tallies are attributed to the resolved
/// domain, so a domain row can show its requesting process and data volume.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DomainBandwidthTests : IDisposable
{
    private sealed class FakeEndpointSource : IBandwidthSource
    {
        public bool Active => true;

        public Dictionary<(int, string), (long Sent, long Recv)> Endpoints { get; } = new();

        public IReadOnlyDictionary<int, (long Sent, long Recv)> Drain()
            => new Dictionary<int, (long, long)>();

        public IReadOnlyDictionary<(int Pid, string RemoteAddress), (long Sent, long Recv)> DrainByEndpoint()
        {
            var snapshot = new Dictionary<(int, string), (long, long)>(Endpoints);
            Endpoints.Clear();
            return snapshot;
        }
    }

    private readonly string _dir;
    private readonly HostsDatabase _db;

    public DomainBandwidthTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_dombw_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
    }

    [Fact]
    public void Endpoint_bytes_attribute_to_the_resolved_domain()
    {
        var source = new FakeEndpointSource();
        source.Endpoints[(1234, "203.0.113.5")] = (1000, 4000);
        source.Endpoints[(1234, "198.51.100.9")] = (50, 50);

        // Resolver maps one IP to a domain; the other IP is a bare-IP dial (no name).
        string ResolveHost(string ip) => ip == "203.0.113.5" ? "cdn.example.com" : string.Empty;

        using var agg = new HostsGuard.Service.BandwidthAggregator(
            _db, source, resolveProcess: _ => "chrome", resolveHost: ResolveHost);
        agg.FlushOnce(new DateTime(2026, 7, 4, 12, 0, 0));

        _db.GetDomainUsageTotals(new[] { "cdn.example.com" })["cdn.example.com"].Should().Be(5000);
        _db.GetDomainUsage("cdn.example.com").Should().ContainSingle()
            .Which.Should().Be(("cdn.example.com", "chrome", 1000L, 4000L));
        _db.GetUsageRollups(new DateTime(2026, 7, 4), domain: "cdn.example.com").Should().ContainSingle()
            .Which.Should().BeEquivalentTo(new
            {
                Day = "2026-07-04",
                Process = "chrome",
                Domain = "cdn.example.com",
                Sent = 1000L,
                Recv = 4000L,
            });
        // The unresolved bare-IP endpoint contributes to no domain.
        _db.GetDomainUsageTotals(new[] { "198.51.100.9" }).Should().BeEmpty();
    }

    [Fact]
    public void Usage_accumulates_across_flushes()
    {
        var source = new FakeEndpointSource();
        using var agg = new HostsGuard.Service.BandwidthAggregator(
            _db, source, resolveProcess: _ => "app", resolveHost: _ => "site.example.com");

        source.Endpoints[(1, "203.0.113.1")] = (100, 0);
        agg.FlushOnce(new DateTime(2026, 7, 4, 12, 0, 0));
        source.Endpoints[(1, "203.0.113.1")] = (0, 300);
        agg.FlushOnce(new DateTime(2026, 7, 4, 12, 1, 0));

        _db.GetDomainUsageTotals(new[] { "site.example.com" })["site.example.com"].Should().Be(400);
        _db.GetUsageRollups(new DateTime(2026, 7, 4), domain: "site.example.com").Should().ContainSingle()
            .Which.Should().BeEquivalentTo(new { Sent = 100L, Recv = 300L });
    }

    public void Dispose()
    {
        _db.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}

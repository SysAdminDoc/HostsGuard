using System.IO;
using FluentAssertions;
using HostsGuard.Data;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Data.Tests;

public sealed class ResolvedHostsTests : IDisposable
{
    private readonly string _dir;
    private readonly HostsDatabase _db;

    public ResolvedHostsTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_rh_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _db = new HostsDatabase(Path.Combine(_dir, "db.sqlite"));
    }

    public void Dispose()
    {
        _db.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public void Resolved_host_round_trips_and_upsert_replaces()
    {
        _db.UpsertResolvedHost("203.0.113.9", "Server-99.CloudFront.net", "ptr");
        _db.GetResolvedHost("203.0.113.9").Should().Be("server-99.cloudfront.net");

        _db.UpsertResolvedHost("203.0.113.9", "cdn.example.com", "dns");
        _db.GetResolvedHost("203.0.113.9").Should().Be("cdn.example.com");

        _db.GetResolvedHost("198.51.100.1").Should().BeEmpty();
        _db.GetResolvedHost("").Should().BeEmpty();
    }

    [Fact]
    public void Batch_upsert_persists_all_pairs_and_skips_blanks()
    {
        _db.UpsertResolvedHosts(new[]
        {
            ("203.0.113.1", "a.example.com"),
            ("203.0.113.2", "b.example.com"),
            ("203.0.113.3", ""),      // no host — skipped
            ("", "c.example.com"),    // no ip — skipped
        }, "dns");

        _db.GetResolvedHost("203.0.113.1").Should().Be("a.example.com");
        _db.GetResolvedHost("203.0.113.2").Should().Be("b.example.com");
        _db.GetResolvedHost("203.0.113.3").Should().BeEmpty();
    }

    [Fact]
    public void Resolved_hosts_survive_reopening_the_database()
    {
        var path = Path.Combine(_dir, "persist.sqlite");
        using (var db = new HostsDatabase(path))
        {
            db.UpsertResolvedHost("203.0.113.9", "remembered.example.com", "ptr");
        }

        SqliteConnection.ClearAllPools();
        using var reopened = new HostsDatabase(path);
        reopened.GetResolvedHost("203.0.113.9").Should().Be("remembered.example.com");
    }
}

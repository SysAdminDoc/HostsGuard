using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public sealed class ResolvedIpCacheTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 12, 0, 0);

    [Fact]
    public void Lookup_returns_the_domain_an_ip_resolved_as()
    {
        var cache = new ResolvedIpCache();
        cache.Record("www.Example.com", new[] { "203.0.113.9", "203.0.113.10" }, T0);

        cache.Lookup("203.0.113.9", T0.AddMinutes(5)).Should().Be("www.example.com");
        cache.Lookup("203.0.113.10", T0.AddMinutes(5)).Should().Be("www.example.com");
        cache.Lookup("203.0.113.99", T0).Should().BeEmpty();
    }

    [Fact]
    public void Entries_expire_after_the_ttl()
    {
        var cache = new ResolvedIpCache(TimeSpan.FromMinutes(10));
        cache.Record("a.example.com", new[] { "203.0.113.9" }, T0);

        cache.Lookup("203.0.113.9", T0.AddMinutes(9)).Should().Be("a.example.com");
        cache.Lookup("203.0.113.9", T0.AddMinutes(11)).Should().BeEmpty();
    }

    [Fact]
    public void Later_resolutions_win_and_junk_is_ignored()
    {
        var cache = new ResolvedIpCache();
        cache.Record("old.example.com", new[] { "203.0.113.9" }, T0);
        cache.Record("new.example.com", new[] { "203.0.113.9", "not-an-ip" }, T0.AddMinutes(1));
        cache.Record("", new[] { "203.0.113.50" }, T0);

        cache.Lookup("203.0.113.9", T0.AddMinutes(2)).Should().Be("new.example.com");
        cache.Lookup("203.0.113.50", T0).Should().BeEmpty();
        cache.Lookup("not-an-ip", T0).Should().BeEmpty();
    }
}

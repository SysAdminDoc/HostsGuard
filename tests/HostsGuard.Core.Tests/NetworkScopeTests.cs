using System.Net;
using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>NET-076: network-scope classification, address sets, and the direct-IP heuristic.</summary>
public class NetworkScopeTests
{
    [Theory]
    [InlineData("127.0.0.1", NetworkScope.Localhost)]
    [InlineData("::1", NetworkScope.Localhost)]
    [InlineData("10.1.2.3", NetworkScope.Lan)]
    [InlineData("192.168.0.5", NetworkScope.Lan)]
    [InlineData("172.16.9.9", NetworkScope.Lan)]
    [InlineData("172.32.0.1", NetworkScope.Internet)]  // just outside RFC1918
    [InlineData("169.254.1.1", NetworkScope.Lan)]
    [InlineData("100.64.0.1", NetworkScope.Lan)]        // CGNAT
    [InlineData("8.8.8.8", NetworkScope.Internet)]
    [InlineData("1.1.1.1", NetworkScope.Internet)]
    [InlineData("fe80::1", NetworkScope.Lan)]
    [InlineData("fc00::1", NetworkScope.Lan)]
    [InlineData("2606:4700::1111", NetworkScope.Internet)]
    public void Classify_buckets_addresses(string ip, NetworkScope expected) =>
        NetworkScopes.Classify(ip).Should().Be(expected);

    [Fact]
    public void Classify_returns_null_for_garbage() =>
        NetworkScopes.Classify("not-an-ip").Should().BeNull();

    [Theory]
    [InlineData("internet", NetworkScope.Internet)]
    [InlineData("LAN", NetworkScope.Lan)]
    [InlineData("localhost", NetworkScope.Localhost)]
    [InlineData("inbound", NetworkScope.Inbound)]
    public void TryParse_accepts_known_tokens(string token, NetworkScope expected)
    {
        NetworkScopes.TryParse(token, out var scope).Should().BeTrue();
        scope.Should().Be(expected);
    }

    [Fact]
    public void TryParse_rejects_unknown_tokens() =>
        NetworkScopes.TryParse("mars", out _).Should().BeFalse();

    [Fact]
    public void RemoteAddresses_are_valid_cidr_lists_for_addressed_scopes()
    {
        foreach (var scope in new[] { NetworkScope.Internet, NetworkScope.Lan, NetworkScope.Localhost })
        {
            var set = NetworkScopes.RemoteAddresses(scope);
            set.Should().NotBe("Any");
            foreach (var cidr in set.Split(','))
            {
                var slash = cidr.IndexOf('/');
                slash.Should().BeGreaterThan(0);
                IPAddress.TryParse(cidr[..slash], out _).Should().BeTrue($"'{cidr}' should have a valid network address");
            }
        }

        NetworkScopes.RemoteAddresses(NetworkScope.Inbound).Should().Be("Any");
    }

    [Fact]
    public void Internet_set_excludes_private_ranges()
    {
        // Sanity: a private /8 like 10.0.0.0 must not appear as an Internet range.
        NetworkScopes.Internet.Split(',').Should().NotContain(c => c.StartsWith("10.") || c.StartsWith("192.168") || c.StartsWith("127."));
    }

    [Theory]
    // Public unicast — every one of these MUST be inside a block rule (regression
    // for the 172.x gap where 172.0–15 and 172.32–255 escaped the Internet set).
    [InlineData("1.1.1.1", true)]
    [InlineData("8.8.8.8", true)]
    [InlineData("172.0.5.5", true)]
    [InlineData("172.15.255.255", true)]
    [InlineData("172.32.0.1", true)]
    [InlineData("172.200.1.1", true)]
    [InlineData("100.0.0.5", true)]     // 100.x public (below CGNAT)
    [InlineData("100.200.1.1", true)]   // 100.x public (above CGNAT)
    [InlineData("169.1.1.1", true)]     // 169.x public (not link-local)
    [InlineData("223.255.255.255", true)]
    [InlineData("2606:4700::1111", true)]
    // Non-Internet — must NOT be covered (matches IsLan/IsLocalhost + reserved).
    [InlineData("10.0.0.1", false)]
    [InlineData("172.16.5.5", false)]
    [InlineData("172.31.255.255", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("100.64.0.1", false)]   // CGNAT
    [InlineData("169.254.1.1", false)]  // link-local
    [InlineData("127.0.0.1", false)]    // loopback
    [InlineData("224.0.0.1", false)]    // multicast
    [InlineData("240.0.0.1", false)]    // reserved
    [InlineData("0.1.2.3", false)]      // "this network"
    public void Internet_set_covers_public_space_with_no_gaps(string ip, bool expectedCovered)
    {
        var nets = NetworkScopes.Internet.Split(',').Select(IPNetwork.Parse).ToList();
        var addr = IPAddress.Parse(ip);

        nets.Any(n => n.Contains(addr)).Should().Be(expectedCovered);
    }

    [Fact]
    public void Internet_firewall_set_agrees_with_IsLan_classifier()
    {
        // The generated firewall set and the runtime classifier derive from one
        // source, so an IPv4 the set covers must classify as Internet and vice versa.
        var nets = NetworkScopes.Internet.Split(',').Where(c => !c.Contains(':')).Select(IPNetwork.Parse).ToList();
        foreach (var s in new[] { "8.8.8.8", "172.32.1.1", "10.1.1.1", "192.168.0.1", "100.64.1.1", "169.254.1.1" })
        {
            var addr = IPAddress.Parse(s);
            var covered = nets.Any(n => n.Contains(addr));
            covered.Should().Be(NetworkScopes.IsInternet(addr), $"{s}: firewall coverage must match IsInternet");
        }
    }

    [Fact]
    public void DirectIp_flags_unresolved_public_ips_only()
    {
        var now = new DateTime(2026, 7, 2, 12, 0, 0);
        var h = new DirectIpHeuristic(TimeSpan.FromMinutes(10));
        h.RecordResolved("93.184.216.34", now);

        h.IsDirect("93.184.216.34", now).Should().BeFalse();     // resolved → not direct
        h.IsDirect("203.0.113.7", now).Should().BeTrue();        // public, never resolved → direct
        h.IsDirect("10.0.0.5", now).Should().BeFalse();          // LAN → never direct
        h.IsDirect("127.0.0.1", now).Should().BeFalse();         // localhost → never direct
    }

    [Fact]
    public void DirectIp_expires_stale_resolutions()
    {
        var now = new DateTime(2026, 7, 2, 12, 0, 0);
        var h = new DirectIpHeuristic(TimeSpan.FromMinutes(10));
        h.RecordResolved("203.0.113.7", now);

        h.IsDirect("203.0.113.7", now.AddMinutes(5)).Should().BeFalse();  // within window
        h.IsDirect("203.0.113.7", now.AddMinutes(20)).Should().BeTrue();  // stale → direct again
    }

    [Fact]
    public void ExtractAddresses_pulls_ips_and_skips_cnames()
    {
        var raw = "type: 5 cdn.example.net;93.184.216.34;2606:2800:220:1:248:1893:25c8:1946";
        var addrs = DnsQueryResults.ExtractAddresses(raw);

        addrs.Should().Contain("93.184.216.34");
        addrs.Should().Contain("2606:2800:220:1:248:1893:25c8:1946");
        addrs.Should().NotContain("cdn.example.net");
    }
}

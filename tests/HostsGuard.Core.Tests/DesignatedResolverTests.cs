using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>NET-173: SVCB/HTTPS (RFC 9460) + DDR (RFC 9462/9461) wire parse.</summary>
public class DesignatedResolverTests
{
    // Build SVCB RDATA: priority, target name (labels + 0), then SvcParams.
    private static byte[] Build(int priority, string[] targetLabels, params (int Key, byte[] Value)[] svcParams)
    {
        var bytes = new List<byte> { (byte)(priority >> 8), (byte)(priority & 0xFF) };
        foreach (var label in targetLabels)
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }

        bytes.Add(0); // root label terminates the name
        foreach (var (key, value) in svcParams)
        {
            bytes.Add((byte)(key >> 8));
            bytes.Add((byte)(key & 0xFF));
            bytes.Add((byte)(value.Length >> 8));
            bytes.Add((byte)(value.Length & 0xFF));
            bytes.AddRange(value);
        }

        return bytes.ToArray();
    }

    private static byte[] AlpnValue(params string[] protocols)
    {
        var bytes = new List<byte>();
        foreach (var p in protocols)
        {
            bytes.Add((byte)p.Length);
            bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(p));
        }

        return bytes.ToArray();
    }

    [Fact]
    public void Parses_a_doh_designated_resolver_record()
    {
        var rdata = Build(
            1,
            new[] { "dns", "example", "net" },
            (1, AlpnValue("h2", "h3")),                                    // alpn
            (3, new byte[] { 0x01, 0xBB }),                                // port 443
            (7, System.Text.Encoding.ASCII.GetBytes("/dns-query{?dns}"))); // dohpath (RFC 9461)

        var rec = DesignatedResolver.ParseSvcb(rdata);

        rec.Should().NotBeNull();
        rec!.Priority.Should().Be(1);
        rec.TargetName.Should().Be("dns.example.net");
        rec.Alpn.Should().BeEquivalentTo(new[] { "h2", "h3" });
        rec.Port.Should().Be(443);
        rec.DohPath.Should().Be("/dns-query{?dns}");
        rec.IsEncrypted.Should().BeTrue();
        rec.DohEndpoint.Should().Be("https://dns.example.net/dns-query");
    }

    [Fact]
    public void Malformed_rdata_returns_null_rather_than_throwing()
    {
        DesignatedResolver.ParseSvcb(new byte[] { 0x00 }).Should().BeNull();           // too short
        DesignatedResolver.ParseSvcb(new byte[] { 0x00, 0x01, 0x05, 0x61 }).Should().BeNull(); // label overruns
        // SvcParam declares length 5 but only 1 value byte follows → overrun → null.
        DesignatedResolver.ParseSvcb(new byte[] { 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xFF }).Should().BeNull();
    }

    [Fact]
    public void Alpn_without_encrypted_transport_is_not_flagged_encrypted()
    {
        var rdata = Build(1, new[] { "resolver", "arpa" }, (1, AlpnValue("dns")));
        var rec = DesignatedResolver.ParseSvcb(rdata);
        rec.Should().NotBeNull();
        rec!.IsEncrypted.Should().BeFalse();
        rec.DohEndpoint.Should().BeNull(); // no dohpath
    }
}

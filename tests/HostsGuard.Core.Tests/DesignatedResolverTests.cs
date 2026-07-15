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
    public void Parses_every_registered_parameter_and_preserves_unknown_extensions()
    {
        var mandatory = new byte[] { 0, 1, 0xff, 0x78 };
        var rdata = Build(
            2,
            new[] { "resolver", "example" },
            (0, mandatory),
            (1, AlpnValue("h2", "h3-29")),
            (2, Array.Empty<byte>()),
            (3, new byte[] { 0x20, 0xfb }),
            (4, new byte[] { 192, 0, 2, 1, 198, 51, 100, 9 }),
            (5, new byte[] { 0, 3, 1, 2, 3 }),
            (6, System.Net.IPAddress.Parse("2001:db8::1").GetAddressBytes()),
            (7, System.Text.Encoding.UTF8.GetBytes("/dns-query{?dns}")),
            (0xff78, new byte[] { 0xde, 0xad }));

        var record = DesignatedResolver.ParseSvcb(rdata);

        record.Should().NotBeNull();
        record!.MandatoryKeys.Should().Equal((ushort)1, (ushort)0xff78);
        record.HasUnsupportedMandatoryKeys.Should().BeTrue();
        record.Alpn.Should().Equal("h2", "h3-29");
        record.NoDefaultAlpn.Should().BeTrue();
        record.Port.Should().Be(8443);
        record.Ipv4Hints.Should().Equal("192.0.2.1", "198.51.100.9");
        record.Ech.Should().Equal(0, 3, 1, 2, 3);
        record.EchAdvertised.Should().BeTrue();
        record.Ipv6Hints.Should().Equal("2001:db8::1");
        record.UnknownParameters.Should().ContainSingle()
            .Which.Should().BeEquivalentTo(new SvcbUnknownParameter(0xff78, new byte[] { 0xde, 0xad }));
    }

    [Fact]
    public void Parses_alias_mode_and_root_target_service_mode()
    {
        DesignatedResolver.ParseSvcb(Build(0, new[] { "alias", "example" }))
            .Should().Match<DesignatedResolverRecord>(record =>
                record.Priority == 0 && record.TargetName == "alias.example");
        DesignatedResolver.ParseSvcb(Build(1, Array.Empty<string>()))
            .Should().Match<DesignatedResolverRecord>(record => record.TargetName == ".");
    }

    [Fact]
    public void Escapes_non_presentation_octets_in_target_labels_without_losing_bytes()
    {
        var rdata = new byte[] { 0, 1, 4, (byte)'a', (byte)'.', (byte)'\\', 0, 0 };

        DesignatedResolver.ParseSvcb(rdata)!.TargetName.Should().Be("a\\046\\092\\000");
    }

    [Fact]
    public void Malformed_rdata_returns_null_rather_than_throwing()
    {
        DesignatedResolver.ParseSvcb(new byte[] { 0x00 }).Should().BeNull();           // too short
        DesignatedResolver.ParseSvcb(new byte[] { 0x00, 0x01, 0x05, 0x61 }).Should().BeNull(); // label overruns
        // SvcParam declares length 5 but only 1 value byte follows → overrun → null.
        DesignatedResolver.ParseSvcb(new byte[] { 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xFF }).Should().BeNull();
    }

    public static IEnumerable<object[]> MalformedRecords()
    {
        yield return new object[] { Build(0, Array.Empty<string>()) }; // AliasMode cannot target root.
        yield return new object[] { Build(0, new[] { "alias" }, (1, AlpnValue("h2"))) }; // AliasMode has params.
        yield return new object[] { Build(1, new[] { "x" }, (3, new byte[] { 0, 80 }), (1, AlpnValue("h2"))) }; // unordered.
        yield return new object[] { Build(1, new[] { "x" }, (1, AlpnValue("h2")), (1, AlpnValue("h3"))) }; // duplicate.
        yield return new object[] { Build(1, new[] { "x" }, (0, Array.Empty<byte>())) };
        yield return new object[] { Build(1, new[] { "x" }, (0, new byte[] { 0, 1, 0 })) };
        yield return new object[] { Build(1, new[] { "x" }, (0, new byte[] { 0, 0 })) }; // mandatory names itself.
        yield return new object[] { Build(1, new[] { "x" }, (0, new byte[] { 0, 3 })) }; // missing mandatory param.
        yield return new object[] { Build(1, new[] { "x" }, (1, Array.Empty<byte>())) };
        yield return new object[] { Build(1, new[] { "x" }, (1, new byte[] { 0 })) };
        yield return new object[] { Build(1, new[] { "x" }, (1, new byte[] { 3, (byte)'h' })) };
        yield return new object[] { Build(1, new[] { "x" }, (2, new byte[] { 1 })) };
        yield return new object[] { Build(1, new[] { "x" }, (2, Array.Empty<byte>())) }; // requires alpn.
        yield return new object[] { Build(1, new[] { "x" }, (3, new byte[] { 80 })) };
        yield return new object[] { Build(1, new[] { "x" }, (3, new byte[] { 0, 80, 0 })) };
        yield return new object[] { Build(1, new[] { "x" }, (4, Array.Empty<byte>())) };
        yield return new object[] { Build(1, new[] { "x" }, (4, new byte[] { 1, 2, 3 })) };
        yield return new object[] { Build(1, new[] { "x" }, (5, Array.Empty<byte>())) };
        yield return new object[] { Build(1, new[] { "x" }, (6, new byte[15])) };
        yield return new object[] { Build(1, new[] { "x" }, (7, Array.Empty<byte>())) };
        yield return new object[] { Build(1, new[] { "x" }, (7, new byte[] { 0xff })) };
        yield return new object[] { Build(1, new[] { "x" }, (7, System.Text.Encoding.UTF8.GetBytes("https://example/dns"))) };
        yield return new object[] { new byte[] { 0, 1, 0xc0, 0x0c } }; // compressed target forbidden.
        yield return new object[] { new byte[] { 0, 1, 64, 0 } }; // label exceeds 63 octets.
        yield return new object[] { Build(1, new[] { "x" }).Concat(new byte[] { 0, 1, 0 }).ToArray() }; // partial header.
    }

    [Theory]
    [MemberData(nameof(MalformedRecords))]
    public void Rejects_rfc_invalid_or_truncated_records(byte[] rdata)
        => DesignatedResolver.ParseSvcb(rdata).Should().BeNull();

    [Fact]
    public void Alpn_without_encrypted_transport_is_not_flagged_encrypted()
    {
        var rdata = Build(1, new[] { "resolver", "arpa" }, (1, AlpnValue("dns")));
        var rec = DesignatedResolver.ParseSvcb(rdata);
        rec.Should().NotBeNull();
        rec!.IsEncrypted.Should().BeFalse();
        rec.DohEndpoint.Should().BeNull(); // no dohpath
    }

    [Fact]
    public void Parses_multiple_dhcpv4_dnr_instances_and_preserves_priority()
    {
        var first = BuildDnrV4Instance(
            0,
            new[] { "doh", "example" },
            new byte[] { 192, 0, 2, 53 },
            (1, AlpnValue("h2")),
            (3, new byte[] { 0x01, 0xbb }),
            (7, System.Text.Encoding.ASCII.GetBytes("/dns-query{?dns}")));
        var second = BuildDnrV4Instance(20, new[] { "resolver", "example" });

        var records = DesignatedResolver.ParseDnrV4Option(first.Concat(second).ToArray());

        records.Should().HaveCount(2);
        records![0].Resolver.Priority.Should().Be(0);
        records[0].Resolver.TargetName.Should().Be("doh.example");
        records[0].Resolver.IsEncrypted.Should().BeTrue();
        records[0].Addresses.Should().Equal("192.0.2.53");
        records[0].AdnOnly.Should().BeFalse();
        records[1].Resolver.Priority.Should().Be(20);
        records[1].AdnOnly.Should().BeTrue();
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Rejects_forbidden_dnr_addresses_and_hint_parameters(bool loopback, bool hint)
    {
        var address = loopback ? new byte[] { 127, 0, 0, 1 } : new byte[] { 192, 0, 2, 53 };
        var parameters = hint
            ? new[] { (4, new byte[] { 192, 0, 2, 1 }) }
            : new[] { (1, AlpnValue("h2")) };

        DesignatedResolver.ParseDnrV4Option(
            BuildDnrV4Instance(1, new[] { "resolver", "example" }, address, parameters))
            .Should().BeNull();
    }

    [Fact]
    public void Rejects_truncated_dnr_instance_instead_of_returning_partial_data()
    {
        var valid = BuildDnrV4Instance(1, new[] { "resolver", "example" });
        var truncated = valid.Concat(new byte[] { 0, 9, 0, 1 }).ToArray();

        DesignatedResolver.ParseDnrV4Option(truncated).Should().BeNull();
    }

    [Fact]
    public void Parses_dhcpv6_dnr_and_rejects_multicast_address()
    {
        var valid = BuildDnrV6(
            7,
            new[] { "resolver", "example" },
            System.Net.IPAddress.Parse("2001:db8::53"),
            (1, AlpnValue("doq")));

        var record = DesignatedResolver.ParseDnrV6Option(valid);

        record.Should().NotBeNull();
        record!.Resolver.Priority.Should().Be(7);
        record.Resolver.TargetName.Should().Be("resolver.example");
        record.Resolver.Alpn.Should().Equal("doq");
        record.Addresses.Should().Equal("2001:db8::53");
        record.AdnOnly.Should().BeFalse();
        DesignatedResolver.ParseDnrV6Option(BuildDnrV6(
            7,
            new[] { "resolver", "example" },
            System.Net.IPAddress.Parse("ff02::53"),
            (1, AlpnValue("doq")))).Should().BeNull();
    }

    private static byte[] BuildDnrV4Instance(
        int priority,
        string[] targetLabels,
        byte[]? addresses = null,
        params (int Key, byte[] Value)[] svcParams)
    {
        var name = new List<byte>();
        foreach (var label in targetLabels)
        {
            name.Add((byte)label.Length);
            name.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        name.Add(0);

        var body = new List<byte>
        {
            (byte)(priority >> 8),
            (byte)priority,
            (byte)name.Count,
        };
        body.AddRange(name);
        if (addresses is not null)
        {
            body.Add((byte)addresses.Length);
            body.AddRange(addresses);
            foreach (var (key, value) in svcParams)
            {
                body.Add((byte)(key >> 8));
                body.Add((byte)key);
                body.Add((byte)(value.Length >> 8));
                body.Add((byte)value.Length);
                body.AddRange(value);
            }
        }

        return new[] { (byte)(body.Count >> 8), (byte)body.Count }.Concat(body).ToArray();
    }

    private static byte[] BuildDnrV6(
        int priority,
        string[] targetLabels,
        System.Net.IPAddress address,
        params (int Key, byte[] Value)[] svcParams)
    {
        var name = new List<byte>();
        foreach (var label in targetLabels)
        {
            name.Add((byte)label.Length);
            name.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        name.Add(0);
        var body = new List<byte>
        {
            (byte)(priority >> 8), (byte)priority,
            (byte)(name.Count >> 8), (byte)name.Count,
        };
        body.AddRange(name);
        var addresses = address.GetAddressBytes();
        body.Add((byte)(addresses.Length >> 8));
        body.Add((byte)addresses.Length);
        body.AddRange(addresses);
        foreach (var (key, value) in svcParams)
        {
            body.Add((byte)(key >> 8));
            body.Add((byte)key);
            body.Add((byte)(value.Length >> 8));
            body.Add((byte)value.Length);
            body.AddRange(value);
        }
        return body.ToArray();
    }
}

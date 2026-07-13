using System.Net;
using System.Net.NetworkInformation;
using FluentAssertions;
using HostsGuard.Windows;
using Microsoft.Win32;

namespace HostsGuard.Windows.Tests;

public sealed class DnsResolverHealthTests
{
    [Fact]
    public async Task CheckResolverHealthAsync_ReportsAdapterEndpointFamiliesRttAndTlsWithoutMutation()
    {
        var adapters = new FakeAdapterSource(
            new DnsAdapterCandidate(
                "ethernet",
                "Ethernet",
                "wired",
                NetworkInterfaceType.Ethernet,
                true,
                true,
                ["9.9.9.9"]));
        var registry = new CountingRegistryStore();
        var targets = new FakeTargetSource(
            new DnsResolverHealthTarget(
                "ethernet",
                "Ethernet",
                IPAddress.Parse("9.9.9.9"),
                DnsResolverProtocol.Doh,
                new Uri("https://dns.quad9.net/dns-query")));
        var transport = new FakeTransport(new DnsResolverTransportResult(
            new DnsResolverAddressResult(DnsResolverProbeStatus.Available, 2, "resolved"),
            new DnsResolverAddressResult(DnsResolverProbeStatus.Available, 1, "resolved"),
            TimeSpan.FromMilliseconds(17),
            DnsResolverTlsStatus.Valid,
            string.Empty));
        var config = new DnsConfig(
            adapters,
            registry,
            healthTargets: targets,
            healthTransport: transport);

        var results = await config.CheckResolverHealthAsync(
            "example.test",
            TimeSpan.FromSeconds(1),
            CancellationToken.None);

        var result = results.Should().ContainSingle().Subject;
        result.AdapterId.Should().Be("ethernet");
        result.AdapterName.Should().Be("Ethernet");
        result.ResolverEndpoint.Should().Be("https://dns.quad9.net/dns-query");
        result.Protocol.Should().Be(DnsResolverProtocol.Doh);
        result.Ipv4.Should().Be(new DnsResolverAddressResult(DnsResolverProbeStatus.Available, 2, "resolved"));
        result.Ipv6.Should().Be(new DnsResolverAddressResult(DnsResolverProbeStatus.Available, 1, "resolved"));
        result.RoundTrip.Should().Be(TimeSpan.FromMilliseconds(17));
        result.TlsStatus.Should().Be(DnsResolverTlsStatus.Valid);
        transport.Hosts.Should().Equal("example.test");
        registry.WriteCount.Should().Be(0);
        registry.DeleteCount.Should().Be(0);
    }

    [Fact]
    public async Task CheckResolverHealthAsync_PreservesExplicitUnavailableAndCertificateFailure()
    {
        var adapters = new FakeAdapterSource(
            new DnsAdapterCandidate("vpn", "VPN", "tunnel", NetworkInterfaceType.Tunnel, true, true, ["1.1.1.1"]));
        var result = new DnsResolverTransportResult(
            new DnsResolverAddressResult(DnsResolverProbeStatus.Unavailable, 0, "AuthenticationException"),
            new DnsResolverAddressResult(DnsResolverProbeStatus.Unavailable, 0, "AuthenticationException"),
            TimeSpan.FromMilliseconds(5),
            DnsResolverTlsStatus.CertificateFailure,
            "certificate_failure");
        var config = new DnsConfig(
            adapters,
            new CountingRegistryStore(),
            healthTargets: new FakeTargetSource(new DnsResolverHealthTarget(
                "vpn", "VPN", IPAddress.Parse("1.1.1.1"), DnsResolverProtocol.Doh,
                new Uri("https://cloudflare-dns.com/dns-query"))),
            healthTransport: new FakeTransport(result));

        var observation = (await config.CheckResolverHealthAsync(
            "example.test", TimeSpan.FromSeconds(1), CancellationToken.None)).Single();

        observation.Ipv4.Status.Should().Be(DnsResolverProbeStatus.Unavailable);
        observation.Ipv6.Status.Should().Be(DnsResolverProbeStatus.Unavailable);
        observation.TlsStatus.Should().Be(DnsResolverTlsStatus.CertificateFailure);
        observation.Error.Should().Be("certificate_failure");
    }

    [Fact]
    public void TargetSource_UsesDohTemplateWhenWindowsExposesOneAndUdpOtherwise()
    {
        var source = new WindowsDnsResolverHealthTargetSource((adapterId, address) =>
            adapterId == "doh" && address.Equals(IPAddress.Parse("1.1.1.1"))
                ? new Uri("https://cloudflare-dns.com/dns-query")
                : null);
        var adapters = new[]
        {
            State("doh", "Encrypted", "1.1.1.1"),
            State("plain", "Plain", "9.9.9.9"),
        };

        var targets = source.GetTargets(adapters);

        targets.Should().ContainSingle(target =>
            target.AdapterId == "doh" &&
            target.Protocol == DnsResolverProtocol.Doh &&
            target.Endpoint == "https://cloudflare-dns.com/dns-query");
        targets.Should().ContainSingle(target =>
            target.AdapterId == "plain" &&
            target.Protocol == DnsResolverProtocol.Udp &&
            target.Endpoint == "9.9.9.9");
    }

    [Fact]
    public async Task AdapterWithoutResolver_IsReportedAsExplicitlyUnavailable()
    {
        var source = new WindowsDnsResolverHealthTargetSource((_, _) => null);
        var probe = new DnsResolverHealthProbe(source, new SystemDnsResolverHealthTransport());
        var adapter = new DnsAdapterState(
            "offline", "Offline resolver", "none", true, false, true, [], []);

        var result = (await probe.CheckAsync(
            [adapter], "example.test", TimeSpan.FromSeconds(1), CancellationToken.None)).Single();

        result.ResolverEndpoint.Should().Be("unavailable");
        result.Protocol.Should().Be(DnsResolverProtocol.Unavailable);
        result.Ipv4.Status.Should().Be(DnsResolverProbeStatus.Unavailable);
        result.Ipv6.Status.Should().Be(DnsResolverProbeStatus.Unavailable);
        result.RoundTrip.Should().BeNull();
        result.TlsStatus.Should().Be(DnsResolverTlsStatus.Unavailable);
        result.Error.Should().Be("resolver_endpoint_unavailable");
    }

    [Fact]
    public void DohTemplateNormalizer_RemovesGetTemplateSuffixForPostProbe()
    {
        WindowsDnsResolverHealthTargetSource.NormalizeDohTemplate(
                "https://dns.example/dns-query{?dns}")
            .Should().Be(new Uri("https://dns.example/dns-query"));
        WindowsDnsResolverHealthTargetSource.NormalizeDohTemplate("http://dns.example/query")
            .Should().BeNull();
    }

    [Fact]
    public void DnsWireParser_CountsRequestedAddressAnswersAndRejectsTruncation()
    {
        var query = SystemDnsResolverHealthTransport.BuildQuery("example.test", 1);
        var response = BuildAddressResponse(query, 1, [192, 0, 2, 10]);

        var parsed = SystemDnsResolverHealthTransport.ParseResponse(query, response, 1);

        parsed.Should().Be(new DnsResolverAddressResult(DnsResolverProbeStatus.Available, 1, "resolved"));
        var act = () => SystemDnsResolverHealthTransport.ParseResponse(query, response[..^1], 1);
        act.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void DnsWireParser_ReportsTruncatedUdpResponseAsFailed()
    {
        var query = SystemDnsResolverHealthTransport.BuildQuery("example.test", 28);
        var response = query.ToArray();
        response[2] = 0x83;
        response[3] = 0x80;

        var result = SystemDnsResolverHealthTransport.ParseResponse(query, response, 28);

        result.Should().Be(new DnsResolverAddressResult(DnsResolverProbeStatus.Failed, 0, "truncated"));
    }

    [Fact]
    public void DnsWireBuilder_RejectsNamesLongerThanDnsWireLimit()
    {
        var oversized = string.Join('.', Enumerable.Repeat(new string('a', 63), 4));

        var act = () => SystemDnsResolverHealthTransport.BuildQuery(oversized, 1);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public async Task CheckResolverHealthAsync_RejectsUnboundedTimeoutBeforeTransport()
    {
        var transport = new FakeTransport(new DnsResolverTransportResult(
            new(DnsResolverProbeStatus.Available, 0, "no_records"),
            new(DnsResolverProbeStatus.Available, 0, "no_records"),
            TimeSpan.Zero,
            DnsResolverTlsStatus.NotApplicable,
            string.Empty));
        var config = new DnsConfig(
            new FakeAdapterSource(new DnsAdapterCandidate(
                "one", "One", "one", NetworkInterfaceType.Ethernet, true, true, ["9.9.9.9"])),
            new CountingRegistryStore(),
            healthTargets: new FakeTargetSource(new DnsResolverHealthTarget(
                "one", "One", IPAddress.Parse("9.9.9.9"), DnsResolverProtocol.Udp, null)),
            healthTransport: transport);

        var act = () => config.CheckResolverHealthAsync(
            "example.test", TimeSpan.FromMinutes(1), CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentOutOfRangeException>();
        transport.Hosts.Should().BeEmpty();
    }

    private static DnsAdapterState State(string id, string name, string resolver)
        => new(id, name, name, true, false, true, [], [resolver]);

    private static byte[] BuildAddressResponse(byte[] query, ushort type, byte[] address)
    {
        var response = new byte[query.Length + 16];
        query.CopyTo(response, 0);
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0;
        response[7] = 1;
        var offset = query.Length;
        response[offset++] = 0xC0;
        response[offset++] = 0x0C;
        response[offset++] = (byte)(type >> 8);
        response[offset++] = (byte)type;
        response[offset++] = 0;
        response[offset++] = 1;
        offset += 4;
        response[offset++] = 0;
        response[offset++] = (byte)address.Length;
        address.CopyTo(response, offset);
        return response;
    }

    private sealed class FakeAdapterSource(params DnsAdapterCandidate[] adapters) : IDnsAdapterSource
    {
        public IReadOnlyList<DnsAdapterCandidate> GetAdapters() => adapters;
    }

    private sealed class CountingRegistryStore : IDnsRegistryStore
    {
        public int WriteCount { get; private set; }
        public int DeleteCount { get; private set; }
        public DnsRegistryValue Read(string adapterId) => DnsRegistryValue.Absent;
        public void Write(string adapterId, object value, RegistryValueKind kind) => WriteCount++;
        public void Delete(string adapterId) => DeleteCount++;
    }

    private sealed class FakeTargetSource(params DnsResolverHealthTarget[] targets) : IDnsResolverHealthTargetSource
    {
        public IReadOnlyList<DnsResolverHealthTarget> GetTargets(IReadOnlyList<DnsAdapterState> adapters) => targets;
    }

    private sealed class FakeTransport(DnsResolverTransportResult result) : IDnsResolverHealthTransport
    {
        public List<string> Hosts { get; } = [];

        public Task<DnsResolverTransportResult> ProbeAsync(
            DnsResolverHealthTarget target,
            string host,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            Hosts.Add(host);
            return Task.FromResult(result);
        }
    }
}

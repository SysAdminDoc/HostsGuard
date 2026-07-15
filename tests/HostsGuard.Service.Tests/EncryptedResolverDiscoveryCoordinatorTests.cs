using FluentAssertions;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service.Tests;

public sealed class EncryptedResolverDiscoveryCoordinatorTests : IDisposable
{
    private readonly string _dir = Path.Combine(
        Path.GetTempPath(),
        "hg_encrypted_resolver_" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Baselines_then_alerts_on_synthetic_ddr_and_dnr_change_without_dns_mutation()
    {
        Directory.CreateDirectory(_dir);
        using var db = new HostsDatabase(Path.Combine(_dir, "state.db"));
        var dns = new FakeDnsConfig();
        dns.ResolverAdapters.Clear();
        dns.ResolverAdapters.Add(new DnsAdapterState(
            "ethernet-id", "Ethernet", "wired", true, false, true,
            [], ["192.0.2.53"], 17));
        var ddr = new MutableDdrQuery { Target = "doh.one.example" };
        var dnr = new MutableDnrSource { Target = "dnr.one.example" };
        var coordinator = new EncryptedResolverDiscoveryCoordinator(dns, ddr, dnr, db, new TestClock(DateTime.UtcNow));

        var initial = await coordinator.RunAsync(CancellationToken.None);

        initial.BaselinePresent.Should().BeTrue();
        initial.DriftDetected.Should().BeFalse();
        initial.Entries.Should().Contain(row => row.Source == "ddr" && row.Target == "doh.one.example");
        initial.Entries.Should().Contain(row => row.Source == "dnr_v4" && row.Target == "dnr.one.example");
        ddr.Targets.Should().ContainSingle().Which.Should().Be(new DnsQueryTarget("192.0.2.53", 17));
        dns.ResolverSets.Should().BeEmpty();
        dns.ResolverAdapterSets.Should().BeEmpty();

        ddr.Target = "doh.two.example";
        dnr.Target = "dnr.two.example";
        var changed = await coordinator.RunAsync(CancellationToken.None);

        changed.DriftDetected.Should().BeTrue();
        changed.Entries.Should().Contain(row => row.Drifted && row.Source == "ddr");
        changed.Entries.Should().Contain(row => row.Drifted && row.Source == "dnr_v4");
        db.GetAlerts(new AlertFilter(
                Limit: 10,
                IncludeRead: true,
                SurfaceOnly: false,
                Type: "encrypted_resolver_drift"))
            .Rows.Should().ContainSingle(row => row.Title == "Encrypted resolver designation changed");

        var accepted = coordinator.AcceptCurrentBaseline();
        accepted.DriftDetected.Should().BeFalse();
        (await coordinator.RunAsync(CancellationToken.None)).DriftDetected.Should().BeFalse();
    }

    [Fact]
    public async Task Malformed_dnr_is_rejected_and_alerted_without_replacing_valid_rows()
    {
        Directory.CreateDirectory(_dir);
        using var db = new HostsDatabase(Path.Combine(_dir, "malformed.db"));
        var dns = new FakeDnsConfig();
        dns.ResolverAdapters.Clear();
        dns.ResolverAdapters.Add(new DnsAdapterState(
            "ethernet-id", "Ethernet", "wired", true, false, true, [], ["192.0.2.53"]));
        var dnr = new MutableDnrSource { Raw = [0, 20, 0, 1] };
        var coordinator = new EncryptedResolverDiscoveryCoordinator(dns, null, dnr, db, new TestClock(DateTime.UtcNow));

        var snapshot = await coordinator.RunAsync(CancellationToken.None);

        snapshot.DriftDetected.Should().BeTrue();
        snapshot.BaselinePresent.Should().BeFalse();
        snapshot.Entries.Should().ContainSingle(row => row.Outcome == "malformed");
        db.GetAlerts(new AlertFilter(
                Limit: 10,
                IncludeRead: true,
                SurfaceOnly: false,
                Type: "encrypted_resolver_drift"))
            .Rows.Should().ContainSingle(row => row.Title == "Malformed encrypted resolver designation");

        var accepted = coordinator.AcceptCurrentBaseline();
        accepted.BaselinePresent.Should().BeFalse();
        accepted.DriftDetected.Should().BeTrue();
        accepted.Message.Should().Contain("cannot be trusted");

        await coordinator.RunAsync(CancellationToken.None);
        db.GetAlerts(new AlertFilter(
                Limit: 10,
                IncludeRead: true,
                SurfaceOnly: false,
                Type: "encrypted_resolver_drift"))
            .Rows.Should().ContainSingle("an unchanged malformed payload must not alert repeatedly");
    }

    [Fact]
    public async Task Ddr_alias_is_followed_on_the_same_adapter_and_resolver()
    {
        Directory.CreateDirectory(_dir);
        using var db = new HostsDatabase(Path.Combine(_dir, "alias.db"));
        var dns = new FakeDnsConfig();
        dns.ResolverAdapters.Clear();
        dns.ResolverAdapters.Add(new DnsAdapterState(
            "ethernet-id", "Ethernet", "wired", true, false, false,
            ["192.0.2.53"], ["192.0.2.53"], 17));
        var ddr = new MutableDdrQuery
        {
            AliasTarget = "_dns.alias.example",
            Target = "doh.alias.example",
        };
        var coordinator = new EncryptedResolverDiscoveryCoordinator(dns, ddr, null, db, new TestClock(DateTime.UtcNow));

        var snapshot = await coordinator.RunAsync(CancellationToken.None);

        snapshot.BaselinePresent.Should().BeTrue();
        snapshot.DriftDetected.Should().BeFalse();
        snapshot.Entries.Should().Contain(row => row.Priority == 0 && row.Target == "_dns.alias.example");
        snapshot.Entries.Should().Contain(row => row.Outcome == "encrypted" && row.Target == "doh.alias.example");
        ddr.Names.Should().Equal("_dns.resolver.arpa", "_dns.alias.example");
        ddr.Targets.Should().OnlyContain(target => target == new DnsQueryTarget("192.0.2.53", 17));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }

    private sealed class MutableDdrQuery : IDnsServiceBindingQuery
    {
        public string Target { get; set; } = string.Empty;
        public string? AliasTarget { get; set; }
        public List<DnsQueryTarget?> Targets { get; } = [];
        public List<string> Names { get; } = [];

        public Task<DnsRawQueryResult> QueryResourceRecordsAsync(
            string name,
            ushort recordType,
            TimeSpan timeout,
            CancellationToken cancellationToken,
            DnsQueryTarget? target = null)
        {
            Targets.Add(target);
            Names.Add(name);
            return Task.FromResult(new DnsRawQueryResult(
                DnsRawQueryOutcome.Success,
                [new DnsRawResourceRecord(
                    name,
                    recordType,
                    60,
                    AliasTarget is not null && name == "_dns.resolver.arpa"
                        ? BuildAliasSvcb(AliasTarget)
                        : BuildSvcb(Target))],
                0,
                string.Empty));
        }
    }

    private sealed class MutableDnrSource : IDnrOptionSource
    {
        public string Target { get; set; } = string.Empty;
        public byte[]? Raw { get; set; }

        public Task<DnrOptionResult> ReadV4Async(
            string adapterId,
            TimeSpan timeout,
            CancellationToken cancellationToken)
            => Task.FromResult(new DnrOptionResult(
                DnrOptionOutcome.Success,
                Raw ?? BuildDnr(Target),
                0,
                string.Empty));

        public Task<DnrOptionResult> ReadV6Async(
            string adapterId,
            TimeSpan timeout,
            CancellationToken cancellationToken) => Task.FromResult(new DnrOptionResult(
                DnrOptionOutcome.NoOption, [], 2, "option_not_present"));
    }

    private static byte[] BuildSvcb(string target)
    {
        var data = new List<byte> { 0, 1 };
        AddName(data, target);
        data.AddRange(new byte[] { 0, 1, 0, 3, 2, (byte)'h', (byte)'2' });
        data.AddRange(new byte[] { 0, 7, 0, 16 });
        data.AddRange(System.Text.Encoding.ASCII.GetBytes("/dns-query{?dns}"));
        return data.ToArray();
    }

    private static byte[] BuildAliasSvcb(string target)
    {
        var data = new List<byte> { 0, 0 };
        AddName(data, target);
        return data.ToArray();
    }

    private static byte[] BuildDnr(string target)
    {
        var body = new List<byte> { 0, 5 };
        var name = new List<byte>();
        AddName(name, target);
        body.Add((byte)name.Count);
        body.AddRange(name);
        body.Add(4);
        body.AddRange(new byte[] { 192, 0, 2, 54 });
        body.AddRange(new byte[] { 0, 1, 0, 3, 2, (byte)'h', (byte)'2' });
        return new[] { (byte)(body.Count >> 8), (byte)body.Count }.Concat(body).ToArray();
    }

    private static void AddName(List<byte> destination, string name)
    {
        foreach (var label in name.Split('.'))
        {
            destination.Add((byte)label.Length);
            destination.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        destination.Add(0);
    }
}

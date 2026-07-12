using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using FluentAssertions;
using HostsGuard.Windows;

namespace HostsGuard.Windows.Tests;

public sealed class DnsConfigTransactionTests
{
    [Fact]
    public void ListResolverAdapters_IncludesActiveTunnelAndReportsPriorState()
    {
        var adapters = new FakeAdapterSource(
            Adapter("ethernet", "Ethernet", NetworkInterfaceType.Ethernet, ["192.0.2.53"]),
            Adapter("vpn", "WireGuard Tunnel", NetworkInterfaceType.Tunnel, ["2001:db8::53"]),
            Adapter("loopback", "Loopback", NetworkInterfaceType.Loopback, []),
            Adapter("down", "Down", NetworkInterfaceType.Ethernet, [], isUp: false),
            Adapter("empty", "No address", NetworkInterfaceType.Ethernet, [], hasAddress: false));
        var registry = new FakeRegistryStore();
        registry.Seed("ethernet", "9.9.9.9,149.112.112.112", RegistryValueKind.ExpandString);

        var states = new DnsConfig(adapters, registry).ListResolverAdapters();

        states.Select(s => s.Id).Should().Equal("vpn", "ethernet");
        states[0].IsVpn.Should().BeTrue();
        states[0].UsesDhcp.Should().BeTrue();
        states[0].EffectiveResolvers.Should().Equal("2001:db8::53");
        states[1].ConfiguredResolvers.Should().Equal("9.9.9.9", "149.112.112.112");
        states[1].UsesDhcp.Should().BeFalse();
    }

    [Fact]
    public void SetAndRestoreResolvers_ChangesOnlySelectedAndRestoresExactValueAndKind()
    {
        var adapters = new FakeAdapterSource(
            Adapter("one", "One", NetworkInterfaceType.Ethernet, ["192.0.2.1"]),
            Adapter("two", "Two", NetworkInterfaceType.Ethernet, ["192.0.2.2"]));
        var registry = new FakeRegistryStore();
        registry.Seed("one", "9.9.9.9", RegistryValueKind.ExpandString);
        registry.Seed("two", "8.8.8.8", RegistryValueKind.String);
        var flushes = 0;
        var config = new DnsConfig(adapters, registry, () => { flushes++; return true; });

        var change = config.SetResolvers(["1.1.1.1", "2606:4700:4700::1111"], ["one"]);

        registry.Read("one").Should().Be(
            new DnsRegistryValue(true, "1.1.1.1,2606:4700:4700::1111", RegistryValueKind.String));
        registry.Read("two").Should().Be(
            new DnsRegistryValue(true, "8.8.8.8", RegistryValueKind.String));
        change.ChangedAdapters.Should().ContainSingle().Which.Id.Should().Be("one");
        change.Prior.RegistryValues["one"].Should().Be(
            new DnsRegistryValue(true, "9.9.9.9", RegistryValueKind.ExpandString));

        config.RestoreResolvers(change.Prior);

        registry.Read("one").Should().Be(
            new DnsRegistryValue(true, "9.9.9.9", RegistryValueKind.ExpandString));
        registry.Read("two").Should().Be(
            new DnsRegistryValue(true, "8.8.8.8", RegistryValueKind.String));
        flushes.Should().Be(2);
    }

    [Fact]
    public void Legacy_all_adapter_overload_never_changes_vpn_implicitly()
    {
        var adapters = new FakeAdapterSource(
            Adapter("ethernet", "Ethernet", NetworkInterfaceType.Ethernet, ["192.0.2.1"]),
            Adapter("vpn", "VPN", NetworkInterfaceType.Tunnel, ["192.0.2.2"]));
        var registry = new FakeRegistryStore();
        var config = new DnsConfig(adapters, registry);

        config.SetResolvers(["1.1.1.1"]);

        registry.Read("ethernet").Should().Be(
            new DnsRegistryValue(true, "1.1.1.1", RegistryValueKind.String));
        registry.Read("vpn").Should().Be(DnsRegistryValue.Absent);
    }

    [Fact]
    public void SetResolvers_WhenLaterWriteFails_RestoresAllSelectedAdaptersExactly()
    {
        var adapters = new FakeAdapterSource(
            Adapter("one", "One", NetworkInterfaceType.Ethernet, ["192.0.2.1"]),
            Adapter("two", "Two", NetworkInterfaceType.Tunnel, ["192.0.2.2"]));
        var registry = new FakeRegistryStore();
        registry.Seed("one", "9.9.9.9", RegistryValueKind.ExpandString);
        registry.FailNextWrite("two");
        var flushes = 0;
        var config = new DnsConfig(adapters, registry, () => { flushes++; return true; });

        var act = () => config.SetResolvers(["1.1.1.1"], ["one", "two"]);

        act.Should().Throw<IOException>().WithMessage("simulated write failure");
        registry.Read("one").Should().Be(
            new DnsRegistryValue(true, "9.9.9.9", RegistryValueKind.ExpandString));
        registry.Read("two").Should().Be(DnsRegistryValue.Absent);
        flushes.Should().Be(1);
    }

    [Fact]
    public void RestoreResolvers_WhenLaterWriteFails_RestoresPreRestoreState()
    {
        var adapters = new FakeAdapterSource(
            Adapter("one", "One", NetworkInterfaceType.Ethernet, ["192.0.2.1"]),
            Adapter("two", "Two", NetworkInterfaceType.Tunnel, ["192.0.2.2"]));
        var registry = new FakeRegistryStore();
        registry.Seed("one", "9.9.9.9", RegistryValueKind.ExpandString);
        registry.Seed("two", "8.8.8.8", RegistryValueKind.String);
        var config = new DnsConfig(adapters, registry);
        var change = config.SetResolvers(["1.1.1.1"], ["one", "two"]);
        registry.FailNextWrite("two");

        var act = () => config.RestoreResolvers(change.Prior);

        act.Should().Throw<IOException>().WithMessage("simulated write failure");
        registry.Read("one").Should().Be(
            new DnsRegistryValue(true, "1.1.1.1", RegistryValueKind.String));
        registry.Read("two").Should().Be(
            new DnsRegistryValue(true, "1.1.1.1", RegistryValueKind.String));
    }

    [Fact]
    public void RestoreResolvers_AllowsAdapterToBecomeInactiveAfterSnapshot()
    {
        var adapters = new FakeAdapterSource(
            Adapter("one", "One", NetworkInterfaceType.Tunnel, ["192.0.2.1"]));
        var registry = new FakeRegistryStore();
        registry.Seed("one", "9.9.9.9", RegistryValueKind.ExpandString);
        var config = new DnsConfig(adapters, registry);
        var change = config.SetResolvers(["1.1.1.1"], ["one"]);
        adapters.SetAdapters(
            Adapter("one", "One", NetworkInterfaceType.Tunnel, [], isUp: false));

        config.RestoreResolvers(change.Prior);

        registry.Read("one").Should().Be(
            new DnsRegistryValue(true, "9.9.9.9", RegistryValueKind.ExpandString));
    }

    [Fact]
    public void SetResolvers_EmptyServerListUsesDhcpAndSnapshotRestoresAbsentValue()
    {
        var adapters = new FakeAdapterSource(
            Adapter("one", "One", NetworkInterfaceType.Ethernet, ["192.0.2.1"]));
        var registry = new FakeRegistryStore();
        var config = new DnsConfig(adapters, registry);

        var staticChange = config.SetResolvers(["1.1.1.1"], ["one"]);
        config.RestoreResolvers(staticChange.Prior);

        registry.Read("one").Should().Be(DnsRegistryValue.Absent);
    }

    [Fact]
    public async Task ProbeAsync_ReportsAddressFamiliesAndUsesBoundedResolver()
    {
        var config = new DnsConfig(
            new FakeAdapterSource(),
            new FakeRegistryStore(),
            resolve: (_, _) => Task.FromResult(new[]
            {
                IPAddress.Parse("192.0.2.10"),
                IPAddress.Parse("2001:db8::10"),
            }));

        var result = await config.ProbeAsync("example.test", TimeSpan.FromSeconds(1), CancellationToken.None);

        result.Success.Should().BeTrue();
        result.Ipv4Count.Should().Be(1);
        result.Ipv6Count.Should().Be(1);
        result.Error.Should().BeEmpty();
    }

    [Fact]
    public async Task ProbeAsync_WhenResolverExceedsDeadline_ReturnsTimeout()
    {
        var config = new DnsConfig(
            new FakeAdapterSource(),
            new FakeRegistryStore(),
            resolve: async (_, token) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return Array.Empty<IPAddress>();
            });

        var result = await config.ProbeAsync(
            "example.test",
            TimeSpan.FromMilliseconds(20),
            CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Error.Should().Be("timeout");
    }

    private static DnsAdapterCandidate Adapter(
        string id,
        string name,
        NetworkInterfaceType type,
        IReadOnlyList<string> resolvers,
        bool isUp = true,
        bool hasAddress = true)
        => new(id, name, $"{name} description", type, isUp, hasAddress, resolvers);

    private sealed class FakeAdapterSource(params DnsAdapterCandidate[] adapters) : IDnsAdapterSource
    {
        private IReadOnlyList<DnsAdapterCandidate> _adapters = adapters;

        public IReadOnlyList<DnsAdapterCandidate> GetAdapters() => _adapters;

        public void SetAdapters(params DnsAdapterCandidate[] updated) => _adapters = updated;
    }

    private sealed class FakeRegistryStore : IDnsRegistryStore
    {
        private readonly Dictionary<string, DnsRegistryValue> _values =
            new(StringComparer.OrdinalIgnoreCase);
        private string? _failNextWrite;

        public void Seed(string adapterId, object value, RegistryValueKind kind)
            => _values[adapterId] = new DnsRegistryValue(true, value, kind);

        public void FailNextWrite(string adapterId) => _failNextWrite = adapterId;

        public DnsRegistryValue Read(string adapterId)
            => _values.TryGetValue(adapterId, out var value) ? value : DnsRegistryValue.Absent;

        public void Write(string adapterId, object value, RegistryValueKind kind)
        {
            if (string.Equals(_failNextWrite, adapterId, StringComparison.OrdinalIgnoreCase))
            {
                _failNextWrite = null;
                throw new IOException("simulated write failure");
            }

            _values[adapterId] = new DnsRegistryValue(true, value, kind);
        }

        public void Delete(string adapterId) => _values.Remove(adapterId);
    }
}

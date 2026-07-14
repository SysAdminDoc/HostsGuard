using System.IO;
using FluentAssertions;
using HostsGuard.App.Services;

namespace HostsGuard.App.Tests;

public sealed class NetworkAddressSortTests
{
    [Fact]
    public void Semantic_key_orders_sentinels_ipv4_ipv6_scopes_then_raw_values()
    {
        string[] values =
        [
            "not-an-address",
            "fe80::1%10",
            "10.0.0.2",
            "LocalSubnet",
            "2.0.0.10",
            "fe80::1%2",
            "Any",
            "2001:db8::2",
            "2001:db8::1",
            "fe80::1",
            "",
        ];

        var sorted = values
            .OrderBy(NetworkAddressSortKey.Create)
            .Select(NetworkAddressSortKey.Create)
            .Select(key => key.ToString())
            .ToArray();

        sorted.Should().Equal(
            "Any",
            "LocalSubnet",
            "2.0.0.10",
            "10.0.0.2",
            "2001:db8::1",
            "2001:db8::2",
            "fe80::1",
            "fe80::1%2",
            "fe80::1%10",
            "",
            "not-an-address");
    }

    [Fact]
    public void Equivalent_ipv6_forms_share_numeric_position_with_stable_raw_tie_break()
    {
        var expanded = NetworkAddressSortKey.Create("2001:0db8:0000:0000:0000:0000:0000:0001");
        var compressed = NetworkAddressSortKey.Create("2001:db8::1");

        Math.Sign(expanded.CompareTo(compressed)).Should().Be(
            Math.Sign(StringComparer.OrdinalIgnoreCase.Compare(expanded.ToString(), compressed.ToString())));
        expanded.ToString().Should().Be("2001:0db8:0000:0000:0000:0000:0000:0001");
        compressed.ToString().Should().Be("2001:db8::1");
    }

    [Fact]
    public void Every_address_grid_uses_the_shared_semantic_sort_key()
    {
        var path = Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", "..",
            "src", "HostsGuard.App", "MainWindow.xaml");
        var xaml = File.ReadAllText(path);

        xaml.Should().Contain("Binding=\"{Binding RemoteAddr}\" SortMemberPath=\"RemoteAddressSortKey\" Width=\"100\"")
            .And.Contain("Binding=\"{Binding RemoteAddress}\" SortMemberPath=\"RemoteAddressSortKey\"")
            .And.Contain("Binding=\"{Binding Endpoint}\" SortMemberPath=\"AddressSortKey\"")
            .And.Contain("Binding=\"{Binding RemoteAddr}\" SortMemberPath=\"RemoteAddressSortKey\" Width=\"*\"")
            .And.Contain("Binding=\"{Binding RemoteAddr}\" SortMemberPath=\"RemoteAddressSortKey\" Width=\"0.8*\"");
    }
}

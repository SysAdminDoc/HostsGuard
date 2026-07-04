using System.Net.NetworkInformation;
using FluentAssertions;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

/// <summary>
/// NET-119: the pure name/description matching and VPN-heuristic behind the
/// VPN-presence kill-switch adapter picker (the live enumeration is integration
/// territory; the matching logic is deterministic and unit-tested here).
/// </summary>
public class NetworkAdaptersTests
{
    [Theory]
    [InlineData("WireGuard Tunnel", "WireGuard Tunnel #1", "wireguard", true)]
    [InlineData("Mullvad", "Mullvad WireGuard Adapter", "mullvad", true)]
    [InlineData("Ethernet", "Realtek Gaming 2.5GbE", "vpn", false)]
    [InlineData("wg-mullvad", "WinTun Userspace Tunnel", "WINTUN", true)] // case-insensitive, desc match
    [InlineData("Ethernet", "Realtek", "", false)]                        // blank never matches
    public void Matches_is_a_case_insensitive_substring_over_name_or_description(
        string name, string description, string match, bool expected)
    {
        NetworkAdapters.Matches(name, description, match).Should().Be(expected);
    }

    [Fact]
    public void Matches_tolerates_null_name_and_description()
    {
        NetworkAdapters.Matches(null!, null!, "vpn").Should().BeFalse();
    }

    [Theory]
    [InlineData("ProtonVPN TUN", "ProtonVPN TUN Adapter", NetworkInterfaceType.Ethernet, true)]
    [InlineData("Ethernet", "Intel I219-V", NetworkInterfaceType.Ethernet, false)]
    [InlineData("Wi-Fi", "Intel AX211", NetworkInterfaceType.Wireless80211, false)]
    [InlineData("Any", "Some tunnel", NetworkInterfaceType.Tunnel, true)]   // type wins
    [InlineData("Dial", "PPP link", NetworkInterfaceType.Ppp, true)]        // ppp wins
    public void LooksLikeVpn_flags_tunnels_ppp_and_known_vendor_names(
        string name, string description, NetworkInterfaceType type, bool expected)
    {
        NetworkAdapters.LooksLikeVpn(name, description, type).Should().Be(expected);
    }
}

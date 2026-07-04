using FluentAssertions;
using HostsGuard.App.ViewModels;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>NET-118: firewall-rule provenance derived from the HG_ name prefix.</summary>
public class RuleOriginTests
{
    [Theory]
    [InlineData("HG_Consent_Allow_app_Out", "hostsguard", false, "consent")]
    [InlineData("HG_Learn_app_Out", "hostsguard", false, "learning")]
    [InlineData("HG_Base_svchost_Out", "hostsguard", false, "baseline")]
    [InlineData("HG_Child_child_Out_abc", "hostsguard", false, "child-allow")]
    [InlineData("HG_Once_Allow_x_Out_123", "hostsguard", false, "temporary")]
    [InlineData("HG_Scope_Internet_app", "hostsguard", false, "app-scope")]
    [InlineData("HG_DoH_IPs", "hostsguard", false, "DoH block")]
    [InlineData("HG_QUIC_UDP443", "hostsguard", false, "QUIC block")]
    [InlineData("HG_BlockApp_dummy_Out", "hostsguard", false, "manual")]
    [InlineData("CoreNet-DNS-Out", "system", true, "adopted")]
    [InlineData("CoreNet-DNS-Out", "system", false, "system")]
    public void OriginFor_maps_name_prefix(string name, string source, bool adopted, string expected)
        => FwRuleViewModel.OriginFor(name, source, adopted).Should().Be(expected);
}

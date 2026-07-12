using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public class FwRuleMapperTests
{
    [Theory]
    [InlineData(1, "In")]
    [InlineData(2, "Out")]
    [InlineData("1", "In")]
    [InlineData("Out", "Out")]
    [InlineData(null, "Out")]
    public void Direction_shapes(object? input, string expected) =>
        FwRuleMapper.MapDirection(input).Should().Be(expected);

    [Theory]
    [InlineData(0, "Block")]
    [InlineData(1, "Allow")]
    [InlineData("0", "Block")]
    [InlineData("Allow", "Allow")]
    [InlineData(null, "Block")]
    public void Action_shapes(object? input, string expected) =>
        FwRuleMapper.MapAction(input).Should().Be(expected);

    [Theory]
    [InlineData(true, true)]
    [InlineData(1, true)]
    [InlineData(0, false)]
    [InlineData("1", true)]
    [InlineData(null, false)]
    public void Enabled_shapes(object? input, bool expected) =>
        FwRuleMapper.MapBool(input).Should().Be(expected);

    [Theory]
    [InlineData("6", "TCP")]
    [InlineData("17", "UDP")]
    [InlineData("256", "Any")]
    [InlineData("", "Any")]
    [InlineData(null, "Any")]
    public void Protocol_shapes(object? input, string expected) =>
        FwRuleMapper.MapProtocol(input).Should().Be(expected);

    [Fact]
    public void Remote_single_string()
    {
        FwRuleMapper.MapRemote("1.2.3.4").Should().Be("1.2.3.4");
        FwRuleMapper.MapRemote("*").Should().Be("Any");
        FwRuleMapper.MapRemote("").Should().Be("Any");
    }

    [Fact]
    public void Remote_list_valued_is_joined()
    {
        FwRuleMapper.MapRemote(new[] { "1.1.1.1", "8.8.8.8" }).Should().Be("1.1.1.1,8.8.8.8");
    }

    [Fact]
    public void Interfaces_list_valued_is_joined_and_deduped()
    {
        FwRuleMapper.MapInterfaces(new[] { "Ethernet", "Wi-Fi", "ethernet" }).Should().Be("Ethernet,Wi-Fi");
        FwRuleMapper.MapInterfaces(null).Should().Be("Any");
        FwRuleMapper.MapInterfaces("*").Should().Be("Any");
    }

    [Theory]
    [InlineData(1, "Domain")]
    [InlineData(3, "Domain,Private")]
    [InlineData(7, "Domain,Private,Public")]
    [InlineData(0x7FFFFFFF, "Any")]
    [InlineData("public,domain", "Public,Domain")]
    [InlineData(null, "Any")]
    public void Profiles_are_normalized(object? input, string expected) =>
        FwRuleMapper.MapProfiles(input).Should().Be(expected);

    [Fact]
    public void Package_list_valued_is_joined_and_deduped()
    {
        FwRuleMapper.MapPackageList(new[] { @"C:\A\a.exe", @"C:\B\b.exe", @"c:\a\a.exe" })
            .Should().Be(@"C:\A\a.exe;C:\B\b.exe");
        FwRuleMapper.RuleToken("Contoso.Reader_123abc").Should().Be("Contoso_Reader_123abc");
        FwRuleMapper.RuleToken("   ").Should().Be("package");
    }

    [Fact]
    public void FromValues_full_rule_and_source_by_prefix()
    {
        var hg = FwRuleMapper.FromValues("HG_Block_x", 2, 0, 1, new[] { "1.1.1.1", "8.8.8.8" }, 6, @"C:\a.exe",
            interfaces: new[] { "Ethernet" },
            packageFamilyName: " Contoso.Reader_123abc ",
            packageSid: " S-1-15-2-123 ",
            packageDisplayName: " Contoso Reader ",
            packageFullName: " Contoso.Reader_1.0.0.0_x64__123abc ",
            packageBinaries: new[] { @"C:\Packages\reader.exe" },
            profiles: 5,
            localAddresses: " 10.0.0.5 ");
        hg.Should().Be(new FwRule("HG_Block_x", "Out", "Block", true, "1.1.1.1,8.8.8.8", "TCP", @"C:\a.exe", "hostsguard",
            Interfaces: "Ethernet",
            PackageFamilyName: "Contoso.Reader_123abc",
            PackageSid: "S-1-15-2-123",
            PackageDisplayName: "Contoso Reader",
            PackageFullName: "Contoso.Reader_1.0.0.0_x64__123abc",
            PackageBinaries: @"C:\Packages\reader.exe",
            Profiles: "Domain,Public",
            LocalAddresses: "10.0.0.5"));

        var sys = FwRuleMapper.FromValues("SomeSystemRule", 1, 1, 0, "Any", 256, "");
        sys.Direction.Should().Be("In");
        sys.Action.Should().Be("Allow");
        sys.Enabled.Should().BeFalse();
        sys.RemoteAddr.Should().Be("Any");
        sys.Protocol.Should().Be("Any");
        sys.Source.Should().Be("system");
    }

    [Fact]
    public void FromValues_missing_fields_default_safely()
    {
        var r = FwRuleMapper.FromValues("sparse", null, null, null, null, null, null);
        r.Name.Should().Be("sparse");
        r.Direction.Should().Be("Out");
        r.Action.Should().Be("Block");
        r.Enabled.Should().BeFalse();
        r.RemoteAddr.Should().Be("Any");
        r.Protocol.Should().Be("Any");
        r.Program.Should().BeEmpty();
    }
}

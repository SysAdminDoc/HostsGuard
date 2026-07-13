using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public sealed class WindowsConnectivityChecksTests
{
    [Theory]
    [InlineData("www.msftconnecttest.com", WindowsConnectivityProbeKind.Web, WindowsConnectivityProbeEra.Current)]
    [InlineData("ipv6.msftconnecttest.com", WindowsConnectivityProbeKind.Web, WindowsConnectivityProbeEra.Current)]
    [InlineData("dns.msftncsi.com", WindowsConnectivityProbeKind.Dns, WindowsConnectivityProbeEra.Current)]
    [InlineData("www.msftncsi.com", WindowsConnectivityProbeKind.Web, WindowsConnectivityProbeEra.Legacy)]
    [InlineData("ipv6.msftncsi.com", WindowsConnectivityProbeKind.Web, WindowsConnectivityProbeEra.Legacy)]
    public void Exact_documented_probe_hosts_warn(
        string domain,
        WindowsConnectivityProbeKind kind,
        WindowsConnectivityProbeEra era)
    {
        WindowsConnectivityChecks.TryGet(domain, out var dependency).Should().BeTrue();
        dependency.Should().Be(new WindowsConnectivityDependency(domain, kind, era));

        var warning = WindowsConnectivityChecks.FindBlocked([domain]).Should().ContainSingle().Subject;
        warning.Dependency.Should().Be(dependency);
        warning.Reason.Should().Contain("NCSI");
        WindowsConnectivityWarning.WarningCode.Should().Be("windows_ncsi_dependency");
    }

    [Theory]
    [InlineData("msftconnecttest.com")]
    [InlineData("msftncsi.com")]
    [InlineData("sub.www.msftconnecttest.com")]
    [InlineData("login.microsoftonline.com")]
    [InlineData("windowsupdate.microsoft.com")]
    [InlineData("4-c-0003.c-msedge.net")]
    [InlineData("example.com")]
    public void Related_suffixes_unrelated_microsoft_and_cdn_hosts_do_not_warn(string domain)
    {
        WindowsConnectivityChecks.TryGet(domain, out _).Should().BeFalse();
        WindowsConnectivityChecks.FindBlocked([domain]).Should().BeEmpty();
    }

    [Fact]
    public void Matching_is_dns_canonical_but_remains_exact()
    {
        WindowsConnectivityChecks.FindBlocked([
            " WWW.MSFTCONNECTTEST.COM. ",
            "www.msftconnecttest.com",
            "DNS.MSFTNCSI.COM.",
        ]).Select(static warning => warning.Dependency.Domain).Should().Equal(
            "dns.msftncsi.com",
            "www.msftconnecttest.com");
    }

    [Fact]
    public void Warning_is_evidence_only_and_preserves_the_complete_requested_set()
    {
        string[] requested = ["example.com", "www.msftconnecttest.com"];

        var warnings = WindowsConnectivityChecks.FindBlocked(requested);

        warnings.Should().ContainSingle();
        requested.Should().Equal("example.com", "www.msftconnecttest.com");
    }

    [Fact]
    public void Taxonomy_is_small_exact_and_source_traceable()
    {
        WindowsConnectivityChecks.Dependencies.Should().HaveCount(5);
        WindowsConnectivityChecks.Dependencies.Select(static dependency => dependency.Domain)
            .Should().OnlyHaveUniqueItems();
        WindowsConnectivityChecks.SourceUrl.Should().StartWith("https://learn.microsoft.com/");
    }
}

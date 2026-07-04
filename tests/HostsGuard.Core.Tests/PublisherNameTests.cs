using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>NET-113: extracting the publisher CN from an Authenticode signer subject.</summary>
public class PublisherNameTests
{
    [Theory]
    [InlineData("CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US", "Microsoft Corporation")]
    [InlineData("CN=Valve Corp., O=Valve, C=US", "Valve Corp.")]
    [InlineData("cn=lowercase tag, o=x", "lowercase tag")]
    [InlineData("O=NoCommonName, C=US", "O=NoCommonName, C=US")]
    [InlineData("", "")]
    [InlineData(null, "")]
    public void Of_extracts_the_cn(string? subject, string expected)
        => PublisherName.Of(subject).Should().Be(expected);

    [Fact]
    public void SamePublisher_is_case_insensitive_and_null_safe()
    {
        PublisherName.SamePublisher("CN=Acme, O=Acme", "CN=acme, O=other").Should().BeTrue();
        PublisherName.SamePublisher("CN=Acme", "CN=Globex").Should().BeFalse();
        PublisherName.SamePublisher(null, "CN=Acme").Should().BeFalse();
        PublisherName.SamePublisher("", "").Should().BeFalse();
    }
}

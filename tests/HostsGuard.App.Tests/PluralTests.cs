using FluentAssertions;
using HostsGuard.App.Services;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class PluralTests
{
    [Theory]
    [InlineData(0, "0 domains")]
    [InlineData(1, "1 domain")]
    [InlineData(2, "2 domains")]
    [InlineData(11, "11 domains")]
    public void Of_respects_the_singular(int count, string expected)
        => Plural.Of(count, "domain").Should().Be(expected);

    [Fact]
    public void Of_uses_an_explicit_plural_when_the_s_rule_does_not_fit()
        => Plural.Of(3, "entry", "entries").Should().Be("3 entries");

    [Fact]
    public void Of_singular_ignores_the_explicit_plural()
        => Plural.Of(1, "entry", "entries").Should().Be("1 entry");
}

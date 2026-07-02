using FluentAssertions;
using HostsGuard.App.Services;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class I18nTests
{
    [Fact]
    public void Known_key_resolves_from_resources()
        => I18n.T("Status.Ready", "different fallback").Should().Be("Ready");

    [Fact]
    public void Missing_key_falls_back_to_english()
        => I18n.T("No.Such.Key", "English default").Should().Be("English default");

    [Fact]
    public void Format_arguments_apply()
        => I18n.T("Status.Connected", "Connected — service v{0}", "1.2.3").Should().Contain("1.2.3");
}

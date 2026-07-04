using System.Globalization;
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

    // ─── NET-098: real satellite locale + markup extension ───────────────────

    [Fact]
    public void Spanish_locale_renders_a_real_translation()
    {
        var original = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("es");
            I18n.T("Tab_Tools", "Tools").Should().Be("Herramientas");
            I18n.T("Tab_FirewallRules", "Firewall Rules").Should().Be("Reglas del firewall");
            // A key the Spanish resx omits still falls back to English.
            I18n.T("Nope_Missing", "English fallback").Should().Be("English fallback");
        }
        finally
        {
            CultureInfo.CurrentUICulture = original;
        }
    }

    [Fact]
    public void LocExtension_provides_the_localized_value()
    {
        var original = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("es");
            new LocExtension { Key = "Tab_Blocklists", Default = "Blocklists" }
                .ProvideValue(null!).Should().Be("Listas de bloqueo");
        }
        finally
        {
            CultureInfo.CurrentUICulture = original;
        }
    }
}

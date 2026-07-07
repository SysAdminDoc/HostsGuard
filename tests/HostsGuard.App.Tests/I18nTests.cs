using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using System.Xml.Linq;
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

    [Fact]
    public void Pseudo_locale_marks_and_expands_strings_without_breaking_placeholders()
    {
        const string variable = "9.9.9";
        Environment.SetEnvironmentVariable("HOSTSGUARD_PSEUDO_LOCALE", "1");
        try
        {
            var value = I18n.T("Status.Connected", "Connected - service v{0}", variable);

            value.Should().StartWith("[!! ");
            value.Should().EndWith(" !!]");
            value.Should().Contain(variable);
            value.Should().Contain("Çóññéçtéd");
        }
        finally
        {
            Environment.SetEnvironmentVariable("HOSTSGUARD_PSEUDO_LOCALE", null);
        }
    }

    [Fact]
    public void Xaml_loc_keys_exist_in_neutral_resources()
    {
        var keys = NeutralResourceKeys();
        var missing = new List<string>();
        foreach (var file in LocalizedXamlFiles())
        {
            var text = File.ReadAllText(file);
            foreach (Match match in Regex.Matches(text, @"\{svc:Loc\s+Key=([^,\}\s]+)"))
            {
                if (!keys.Contains(match.Groups[1].Value))
                {
                    missing.Add($"{Path.GetFileName(file)}:{match.Groups[1].Value}");
                }
            }
        }

        missing.Should().BeEmpty();
    }

    [Fact]
    public void Xaml_has_no_new_literal_english_on_localizable_attributes()
    {
        var offenders = new List<string>();
        var pattern = new Regex(
            "(?<attr>\\b(?:Header|Content|Text|ToolTip|AutomationProperties\\.Name|Title)\\s*=\\s*)\"(?<value>[^\"]*)\"",
            RegexOptions.Compiled);
        foreach (var file in LocalizedXamlFiles())
        {
            var text = File.ReadAllText(file);
            foreach (Match match in pattern.Matches(text))
            {
                var value = System.Net.WebUtility.HtmlDecode(match.Groups["value"].Value);
                if (IsHardCodedLocalizableText(value))
                {
                    offenders.Add($"{Path.GetFileName(file)}:{match.Groups["attr"].Value.Trim()}\"{value}\"");
                }
            }
        }

        offenders.Should().BeEmpty();
    }

    private static bool IsHardCodedLocalizableText(string value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.StartsWith("{", StringComparison.Ordinal) ||
            value.StartsWith("#", StringComparison.Ordinal) ||
            value.StartsWith("pack:", StringComparison.OrdinalIgnoreCase) ||
            !Regex.IsMatch(value, @"\p{L}"))
        {
            return false;
        }

        return true;
    }

    private static IReadOnlySet<string> NeutralResourceKeys()
    {
        var doc = XDocument.Load(Path.Combine(AppDir, "Resources", "Strings.resx"));
        return doc.Root!.Elements("data")
            .Select(e => e.Attribute("name")?.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => v!)
            .ToHashSet(StringComparer.Ordinal);
    }

    private static IEnumerable<string> LocalizedXamlFiles()
    {
        yield return Path.Combine(AppDir, "MainWindow.xaml");
        yield return Path.Combine(AppDir, "ConfirmDialog.xaml");
        yield return Path.Combine(AppDir, "InputDialog.xaml");
        yield return Path.Combine(AppDir, "ConsentWindow.xaml");
    }

    private static string AppDir
    {
        get
        {
            var dir = AppContext.BaseDirectory;
            while (dir is not null && !File.Exists(Path.Combine(dir, "HostsGuard.sln")))
            {
                dir = Path.GetDirectoryName(dir);
            }

            dir.Should().NotBeNull("tests must run from within the repo tree");
            return Path.Combine(dir!, "src", "HostsGuard.App");
        }
    }
}

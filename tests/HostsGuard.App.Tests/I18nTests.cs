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

    [Theory]
    [InlineData("es", "Herramientas", "Reglas del firewall")]
    [InlineData("de", "Werkzeuge", "Firewall-Regeln")]
    [InlineData("fr", "Outils", "Règles du pare-feu")]
    public void Satellite_locales_render_real_translations(string culture, string tools, string fwRules)
    {
        var original = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(culture);
            I18n.T("Tab_Tools", "Tools").Should().Be(tools);
            I18n.T("Tab_FirewallRules", "Firewall Rules").Should().Be(fwRules);
            // A neutral key intentionally omitted from the satellite falls
            // back through ResourceManager before the caller's default.
            I18n.T("Status.ConnectedLoading", "different fallback")
                .Should().Be("Connected - loading views...");
            // An entirely unknown key falls back to the caller's English.
            I18n.T("Nope_Missing", "English fallback").Should().Be("English fallback");
        }
        finally
        {
            CultureInfo.CurrentUICulture = original;
        }
    }

    /// <summary>
    /// NET-185: a satellite may translate a subset (fallback covers the rest),
    /// but every key it DOES define must exist in the neutral resources — a
    /// misspelled satellite key would silently never be used.
    /// </summary>
    [Theory]
    [InlineData("Strings.es.resx")]
    [InlineData("Strings.de.resx")]
    [InlineData("Strings.fr.resx")]
    public void Satellite_keys_are_a_subset_of_neutral_keys(string resourceFile)
    {
        var neutral = NeutralResourceKeys();
        var satellite = Regex.Matches(
                File.ReadAllText(Path.Combine(AppDir, "Resources", resourceFile)),
                "<data name=\"(?<key>[^\"]+)\"")
            .Select(m => m.Groups["key"].Value)
            .ToList();

        satellite.Should().NotBeEmpty();
        satellite.Where(k => !neutral.Contains(k)).Should().BeEmpty(
            $"every {resourceFile} key must exist in Strings.resx");
    }

    [Fact]
    public void No_resource_key_contains_non_ascii_characters()
    {
        // Guards the double-encoded-mojibake regression: an em-dash/ellipsis in
        // source text leaking into a generated resx key name (e.g. "Xaml_Normal_â_…")
        // forces every satellite to carry the mangled key and is easy to reintroduce.
        var offenders = new List<string>();
        foreach (var file in Directory.EnumerateFiles(Path.Combine(AppDir, "Resources"), "Strings*.resx"))
        {
            foreach (Match m in Regex.Matches(File.ReadAllText(file), "<data name=\"(?<key>[^\"]+)\""))
            {
                var key = m.Groups["key"].Value;
                if (key.Any(c => c > 127))
                {
                    offenders.Add($"{Path.GetFileName(file)}: {key}");
                }
            }
        }

        offenders.Should().BeEmpty("resx key names must be ASCII");
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
        var original = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("qps-ploc");
            var value = I18n.T("Status.Connected", "Connected - service v{0}", variable);

            value.Should().StartWith("[!! ");
            value.Should().EndWith(" !!]");
            value.Should().Contain(variable);
            value.Should().Contain("Çóññéçtéd");
        }
        finally
        {
            CultureInfo.CurrentUICulture = original;
        }
    }

    [Fact]
    public void Canonical_language_menu_exposes_every_shipped_locale_through_root_command_binding()
    {
        AppConfigStore.LanguageOptions.Select(option => option.Tag)
            .Should().Equal("", "en", "es", "de", "fr");
        AppConfigStore.LanguageOptions.Select(option => option.Name)
            .Should().Equal("System default", "English", "Espa\u00f1ol", "Deutsch", "Fran\u00e7ais");

        var xaml = File.ReadAllText(Path.Combine(AppDir, "MainWindow.xaml"));
        xaml.Should().Contain("ItemsSource=\"{x:Static svc:AppConfigStore.LanguageOptions}\"");
        xaml.Should().Contain("Event=\"Click\" Handler=\"OnLanguageMenuClick\"");
    }

    [Theory]
    [InlineData("Strings.es.resx")]
    [InlineData("Strings.de.resx")]
    [InlineData("Strings.fr.resx")]
    public void Critical_shell_menu_dialog_and_recovery_keys_have_full_satellite_coverage(string resourceFile)
    {
        var required = new HashSet<string>(StringComparer.Ordinal);
        foreach (var file in LocalizedXamlFiles().Where(file => !file.EndsWith("MainWindow.xaml", StringComparison.Ordinal)))
        {
            required.UnionWith(XamlKeys(file));
        }

        required.UnionWith(NeutralResourceKeys().Where(key =>
            key.StartsWith("Language_", StringComparison.Ordinal) ||
            key.StartsWith("Menu_", StringComparison.Ordinal) ||
            key.StartsWith("About_", StringComparison.Ordinal) ||
            key.StartsWith("Ncsi_", StringComparison.Ordinal) ||
            key.StartsWith("Recovery_", StringComparison.Ordinal)));

        var satellite = ResourceKeys(resourceFile);
        required.Where(key => !satellite.Contains(key)).Should().BeEmpty(
            $"{resourceFile} must fully translate language, menu, dialog, and critical recovery surfaces");
    }

    [Theory]
    [InlineData("Strings.es.resx", 676, 1978)]
    [InlineData("Strings.de.resx", 672, 1978)]
    [InlineData("Strings.fr.resx", 674, 1978)]
    public void Overall_used_string_coverage_is_measured_and_cannot_regress(
        string resourceFile,
        int minimumCovered,
        int expectedUsed)
    {
        var used = UsedLocalizationKeys();
        var neutral = ResourceValues("Strings.resx");
        var satellite = ResourceValues(resourceFile);
        var invariantKeys = new HashSet<string>(StringComparer.Ordinal)
        {
            "Language_English", "Language_Spanish", "Language_German", "Language_French",
            "Xaml_HostsGuard_bf992a7e", "Consent_Pid", "ListenerExposure_Package", "FwRules_PreviewPackage",
        };
        var covered = used.Count(key => satellite.TryGetValue(key, out var translated) &&
            (invariantKeys.Contains(key) || !neutral.TryGetValue(key, out var english) || translated != english));
        used.Count.Should().Be(expectedUsed, "the measured localization surface must change deliberately");
        covered.Should().BeGreaterThanOrEqualTo(minimumCovered,
            $"{resourceFile} must not regress below its measured translated-key baseline");
    }

    [Fact]
    public void Xaml_and_resources_have_no_utf8_mojibake_markers()
    {
        var markers = new[] { "Ã", "Â", "â€", "â€¦", "â€”", "ï¿½", "\uFFFD" };
        var offenders = LocalizedXamlFiles()
            .Concat(Directory.EnumerateFiles(Path.Combine(AppDir, "Resources"), "Strings*.resx"))
            .SelectMany(file => File.ReadLines(file).Select((line, index) => (file, line, index)))
            .Where(item => markers.Any(item.line.Contains))
            .Select(item => $"{Path.GetFileName(item.file)}:{item.index + 1}")
            .ToList();

        offenders.Should().BeEmpty("localized source must be clean UTF-8, not double-decoded text");
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
    public void Code_i18n_keys_exist_in_neutral_resources()
    {
        var keys = NeutralResourceKeys();
        var missing = new List<string>();
        var pattern = new Regex("I18n\\s*\\.\\s*T\\s*\\(\\s*\"(?<key>[^\"]+)\"", RegexOptions.Compiled);
        foreach (var file in Directory.EnumerateFiles(AppDir, "*.cs", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(file);
            foreach (Match match in pattern.Matches(text))
            {
                var key = match.Groups["key"].Value;
                if (!keys.Contains(key))
                {
                    missing.Add($"{Path.GetRelativePath(AppDir, file)}:{key}");
                }
            }
        }

        missing.Should().BeEmpty();
    }

    [Fact]
    public void App_runtime_actions_statuses_and_service_messages_are_localized()
    {
        var viewModelDir = Path.Combine(AppDir, "ViewModels");
        var serviceDir = Path.Combine(AppDir, "Services");
        var files = Directory.EnumerateFiles(viewModelDir, "*.cs")
            .Concat(Directory.EnumerateFiles(serviceDir, "*.cs"));
        var rawAction = new Regex("(?:RunServiceActionAsync|ServiceActionGuard\\.RunAsync|_confirm\\.Confirm|_prompt\\?\\.Ask)\\(\\s*\\$?\"", RegexOptions.Compiled);
        var rawStatus = new Regex(
            "\\b(?:StatusText|HistoryStatus|EventStatus|BandwidthStatus|UsageStatus|UsageQuotaStatus|TimelineStatus|DecisionSummary|FlowTeardownText|ListenerStatus|AnalysisStatus|LearnedStatus|InspectResult|ActiveProfile|EchPostureText|SecureRulesText)\\s*=\\s*\\$?\"",
            RegexOptions.Compiled);
        var rawServiceMessage = new Regex(
            "(?:\\breturn\\s+|Unavailable\\([^,\\r\\n]+,\\s*|Filter\\s*=\\s*(?:filter\\s*\\?\\?\\s*)?|^\\s*[?:]\\s*)\\$?\"(?=[^\"]*\\s)[^\"]+\"",
            RegexOptions.Compiled);
        var offenders = new List<string>();
        foreach (var file in files)
        {
            var isService = Path.GetDirectoryName(file)!.Equals(serviceDir, StringComparison.OrdinalIgnoreCase);
            var isVerificationOnly = Path.GetFileName(file).Equals("VisualSmokeRunner.cs", StringComparison.Ordinal);
            var inVisualFixture = false;
            foreach (var (line, index) in File.ReadLines(file).Select((line, index) => (line, index)))
            {
                if (Path.GetFileName(file).Equals("MainViewModel.cs", StringComparison.Ordinal))
                {
                    if (line.Contains("internal void PrepareVisualSmokeFixture()", StringComparison.Ordinal))
                    {
                        inVisualFixture = true;
                    }
                    else if (line.Contains("internal void PrepareVisualSmokeConnectionFixture()", StringComparison.Ordinal))
                    {
                        inVisualFixture = false;
                    }
                }

                if (inVisualFixture || isVerificationOnly)
                {
                    continue;
                }

                if (rawAction.IsMatch(line)
                    || rawStatus.IsMatch(line)
                    || (isService && rawServiceMessage.IsMatch(line)))
                {
                    offenders.Add($"{Path.GetRelativePath(AppDir, file)}:{index + 1}");
                }
            }
        }

        offenders.Should().BeEmpty(
            "every app-side service and view model must resource operator-visible runtime actions, statuses, and messages");
    }

    [Fact]
    public void Xaml_has_no_new_literal_english_on_localizable_attributes()
    {
        var offenders = new List<string>();
        var pattern = new Regex(
            "(?<attr>\\b(?:Header|Content|Text|ToolTip|AutomationProperties\\.Name|Title|Tag)\\s*=\\s*)\"(?<value>[^\"]*)\"",
            RegexOptions.Compiled);
        var targetNullPattern = new Regex(
            "\\bTargetNullValue\\s*=\\s*(?:'(?<value>[^']*)'|\"(?<value>[^\"]*)\"|(?<value>[^,}\\s]+))",
            RegexOptions.Compiled);
        var setterContentPattern = new Regex(
            "<Setter\\s+Property=\"Content\"\\s+Value=\"(?<value>[^\"]*)\"",
            RegexOptions.Compiled);
        foreach (var file in LocalizedXamlFiles())
        {
            var text = File.ReadAllText(file);
            foreach (Match match in pattern.Matches(text))
            {
                var value = System.Net.WebUtility.HtmlDecode(match.Groups["value"].Value);
                if (IsHardCodedLocalizableText(value, match.Groups["attr"].Value))
                {
                    offenders.Add($"{Path.GetFileName(file)}:{match.Groups["attr"].Value.Trim()}\"{value}\"");
                }
            }

            foreach (Match match in targetNullPattern.Matches(text))
            {
                var value = System.Net.WebUtility.HtmlDecode(match.Groups["value"].Value);
                if (IsHardCodedLocalizableText(value, "TargetNullValue"))
                {
                    offenders.Add($"{Path.GetFileName(file)}:TargetNullValue=\"{value}\"");
                }
            }

            foreach (Match match in setterContentPattern.Matches(text))
            {
                var value = System.Net.WebUtility.HtmlDecode(match.Groups["value"].Value);
                if (IsHardCodedLocalizableText(value, "Setter.Content"))
                {
                    offenders.Add($"{Path.GetFileName(file)}:Setter Content=\"{value}\"");
                }
            }
        }

        offenders.Should().BeEmpty();
    }

    [Fact]
    public void Xaml_has_no_new_literal_english_inside_nested_text_elements()
    {
        var offenders = new List<string>();
        var pattern = new Regex(
            @">(?<value>[^<>{}]*\p{L}[^<>{}]*)</(?<tag>Hyperlink|Run)>",
            RegexOptions.Compiled);
        foreach (var file in LocalizedXamlFiles())
        {
            var text = File.ReadAllText(file);
            foreach (Match match in pattern.Matches(text))
            {
                var value = System.Net.WebUtility.HtmlDecode(match.Groups["value"].Value).Trim();
                if (IsHardCodedLocalizableText(value, match.Groups["tag"].Value))
                {
                    offenders.Add($"{Path.GetFileName(file)}:<{match.Groups["tag"].Value}>{value}");
                }
            }
        }

        offenders.Should().BeEmpty();
    }

    [Theory]
    [InlineData("Strings.resx")]
    [InlineData("Strings.es.resx")]
    [InlineData("Strings.de.resx")]
    [InlineData("Strings.fr.resx")]
    public void Menu_resources_do_not_define_access_key_markers(string resourceFile)
    {
        var doc = XDocument.Load(Path.Combine(AppDir, "Resources", resourceFile));
        var offenders = doc.Root!.Elements("data")
            .Where(e => e.Attribute("name")?.Value.StartsWith("Menu_", StringComparison.Ordinal) == true)
            .Select(e => new
            {
                Name = e.Attribute("name")?.Value ?? string.Empty,
                Value = e.Element("value")?.Value ?? string.Empty,
            })
            .Where(item => item.Value.Contains('_', StringComparison.Ordinal))
            .Select(item => $"{resourceFile}:{item.Name}={item.Value}")
            .ToList();

        offenders.Should().BeEmpty("menus use visible labels only; HostsGuard does not define keyboard shortcuts");
    }

    [Fact]
    public void Consent_window_tab_order_has_no_duplicate_indices()
    {
        var xaml = File.ReadAllText(Path.Combine(AppDir, "ConsentWindow.xaml"));
        var indices = Regex.Matches(xaml, @"TabIndex=""(\d+)""")
            .Select(m => int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture))
            .ToList();

        indices.Should().NotBeEmpty();
        indices.Should().OnlyHaveUniqueItems("duplicate TabIndex values make keyboard order ambiguous");
    }

    [Fact]
    public void Consent_window_code_behind_keys_exist_in_neutral_and_spanish_resources()
    {
        var code = File.ReadAllText(Path.Combine(AppDir, "ConsentWindow.xaml.cs"));
        var keys = Regex.Matches(code, @"I18n\.T\(""(?<key>[^""]+)""")
            .Select(m => m.Groups["key"].Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        keys.Should().NotBeEmpty("the consent prompt's dynamic strings are localized through I18n.T");

        var neutral = NeutralResourceKeys();
        var spanish = XDocument.Load(Path.Combine(AppDir, "Resources", "Strings.es.resx")).Root!
            .Elements("data")
            .Select(e => e.Attribute("name")?.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => v!)
            .ToHashSet(StringComparer.Ordinal);

        keys.Should().OnlyContain(k => neutral.Contains(k), "every consent code-behind key needs a neutral resource");
        keys.Should().OnlyContain(k => spanish.Contains(k), "every consent code-behind key needs a Spanish translation");
    }

    private static bool IsHardCodedLocalizableText(string value, string attr)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.StartsWith("{", StringComparison.Ordinal) ||
            value.StartsWith("#", StringComparison.Ordinal) ||
            value.StartsWith("pack:", StringComparison.OrdinalIgnoreCase) ||
            !Regex.IsMatch(value, @"\p{L}"))
        {
            return false;
        }

        if (attr.Contains("Tag", StringComparison.Ordinal) &&
            Regex.IsMatch(value, "^[a-z0-9:-]+$", RegexOptions.CultureInvariant))
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

    private static IReadOnlySet<string> ResourceKeys(string resourceFile)
    {
        var doc = XDocument.Load(Path.Combine(AppDir, "Resources", resourceFile));
        return doc.Root!.Elements("data")
            .Select(element => element.Attribute("name")?.Value)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!)
            .ToHashSet(StringComparer.Ordinal);
    }

    private static IReadOnlyDictionary<string, string> ResourceValues(string resourceFile)
    {
        var doc = XDocument.Load(Path.Combine(AppDir, "Resources", resourceFile));
        return doc.Root!.Elements("data").ToDictionary(
            element => element.Attribute("name")!.Value,
            element => element.Element("value")?.Value ?? string.Empty,
            StringComparer.Ordinal);
    }

    private static IEnumerable<string> XamlKeys(string file) => Regex.Matches(
            File.ReadAllText(file), @"\{svc:Loc\s+Key=([^,\}\s]+)")
        .Select(match => match.Groups[1].Value);

    private static IReadOnlySet<string> UsedLocalizationKeys()
    {
        var keys = LocalizedXamlFiles().SelectMany(XamlKeys).ToHashSet(StringComparer.Ordinal);
        var pattern = new Regex("I18n\\s*\\.\\s*T\\s*\\(\\s*\"(?<key>[^\"]+)\"", RegexOptions.Compiled);
        foreach (var file in Directory.EnumerateFiles(AppDir, "*.cs", SearchOption.AllDirectories))
        {
            keys.UnionWith(pattern.Matches(File.ReadAllText(file)).Select(match => match.Groups["key"].Value));
        }

        return keys;
    }

    private static IEnumerable<string> LocalizedXamlFiles()
    {
        yield return Path.Combine(AppDir, "MainWindow.xaml");
        yield return Path.Combine(AppDir, "ConfirmDialog.xaml");
        yield return Path.Combine(AppDir, "InputDialog.xaml");
        yield return Path.Combine(AppDir, "ConsentWindow.xaml");
        yield return Path.Combine(AppDir, "AboutDialog.xaml");
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

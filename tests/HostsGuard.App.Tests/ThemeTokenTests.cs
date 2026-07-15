using System.IO;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Markup;
using System.Xml.Linq;
using FluentAssertions;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>
/// Headless guards for the theme system: Dark/Light/Contrast token dictionaries stay in
/// key parity, and every Hg.* token referenced by the styles/views resolves in
/// BOTH themes (a missing DynamicResource fails silently at runtime — this is
/// the test that catches it).
/// </summary>
public sealed class ThemeTokenTests
{
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

    private static ResourceDictionary LoadDictionary(string relativePath)
    {
        ResourceDictionary? result = null;
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                result = (ResourceDictionary)XamlReader.Parse(File.ReadAllText(Path.Combine(AppDir, relativePath)));
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        failure.Should().BeNull($"{relativePath} must parse: {failure}");
        return result!;
    }

    private static HashSet<string> Keys(ResourceDictionary dict)
        => dict.Keys.Cast<object>().Select(k => k.ToString()!).ToHashSet(StringComparer.Ordinal);

    [Fact]
    public void All_production_themes_define_identical_token_sets()
    {
        var dark = Keys(LoadDictionary(Path.Combine("Themes", "Dark.xaml")));
        var light = Keys(LoadDictionary(Path.Combine("Themes", "Light.xaml")));
        var contrast = Keys(LoadDictionary(Path.Combine("Themes", "Contrast.xaml")));

        dark.Should().NotBeEmpty();
        dark.Should().BeEquivalentTo(light);
        dark.Should().BeEquivalentTo(contrast);
        dark.Should().OnlyContain(k => k.StartsWith("Hg.", StringComparison.Ordinal));
    }

    [Fact]
    public void Every_referenced_token_exists_in_both_themes()
    {
        var dark = Keys(LoadDictionary(Path.Combine("Themes", "Dark.xaml")));
        var light = Keys(LoadDictionary(Path.Combine("Themes", "Light.xaml")));
        var contrast = Keys(LoadDictionary(Path.Combine("Themes", "Contrast.xaml")));

        var referenced = new HashSet<string>(StringComparer.Ordinal);
        foreach (var file in Directory.EnumerateFiles(AppDir, "*.xaml", SearchOption.AllDirectories))
        {
            if (file.Contains(Path.Combine("Themes", "Dark"), StringComparison.Ordinal) ||
                file.Contains(Path.Combine("Themes", "Light"), StringComparison.Ordinal) ||
                file.Contains(Path.Combine("Themes", "Contrast"), StringComparison.Ordinal) ||
                file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            {
                continue;
            }

            foreach (Match m in Regex.Matches(File.ReadAllText(file), @"DynamicResource\s+(Hg\.\w+)"))
            {
                referenced.Add(m.Groups[1].Value);
            }
        }

        referenced.Should().NotBeEmpty();
        referenced.Should().BeSubsetOf(dark);
        referenced.Should().BeSubsetOf(light);
        referenced.Should().BeSubsetOf(contrast);
    }

    [Fact]
    public void Styles_dictionary_parses_headless()
    {
        var styles = LoadDictionary(Path.Combine("Themes", "Styles.xaml"));
        styles.Keys.Cast<object>().Should().NotBeEmpty();
    }

    [Fact]
    public void Contrast_tokens_are_live_system_color_references()
    {
        XNamespace presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        var document = XDocument.Load(Path.Combine(AppDir, "Themes", "Contrast.xaml"));
        var brushes = document.Descendants(presentation + "SolidColorBrush").ToArray();

        brushes.Should().NotBeEmpty();
        brushes.Select(brush => (string?)brush.Attribute("Color")).Should().OnlyContain(value =>
            value != null && value.Contains("DynamicResource {x:Static SystemColors.", StringComparison.Ordinal),
            "contrast colors must follow the active Windows palette without an app restart");
    }

    [Fact]
    public void Keyboard_focus_does_not_replace_semantic_button_backgrounds()
    {
        XNamespace presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var document = XDocument.Load(Path.Combine(AppDir, "Themes", "Styles.xaml"));
        var buttonStyle = document.Descendants(presentation + "Style")
            .Single(element => (string?)element.Attribute("TargetType") == "Button"
                && element.Attribute(xaml + "Key") is null);

        buttonStyle.Descendants(presentation + "Trigger")
            .Where(trigger => (string?)trigger.Attribute("Property") == "IsKeyboardFocused")
            .SelectMany(trigger => trigger.Elements(presentation + "Setter"))
            .Should().NotContain(setter => (string?)setter.Attribute("Property") == "Background",
                "the template focus ring already exposes focus and allow/block actions must retain their meaning");
    }

    [Fact]
    public void Primary_shell_uses_open_sections_instead_of_nested_outlined_cards()
    {
        XNamespace presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var document = XDocument.Load(Path.Combine(AppDir, "Themes", "Styles.xaml"));

        XElement Style(string key) => document.Descendants(presentation + "Style")
            .Single(element => (string?)element.Attribute(xaml + "Key") == key);

        Style("Hg.Window").Elements(presentation + "Setter")
            .Single(setter => (string?)setter.Attribute("Property") == "FontSize")
            .Attribute("Value")!.Value.Should().Be("14");
        Style("Hg.RailTile").Elements(presentation + "Setter")
            .Single(setter => (string?)setter.Attribute("Property") == "BorderThickness")
            .Attribute("Value")!.Value.Should().Be("0,0,0,1");
        Style("Hg.CommandBar").Elements(presentation + "Setter")
            .Single(setter => (string?)setter.Attribute("Property") == "BorderThickness")
            .Attribute("Value")!.Value.Should().Be("0,0,0,1");
        Style("Hg.Inspector").Elements(presentation + "Setter")
            .Single(setter => (string?)setter.Attribute("Property") == "BorderThickness")
            .Attribute("Value")!.Value.Should().Be("1,0,0,0");
    }
}

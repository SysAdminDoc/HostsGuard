using System.IO;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Markup;
using FluentAssertions;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>
/// Headless guards for the theme system: Dark/Light token dictionaries stay in
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
    public void Dark_and_light_define_identical_token_sets()
    {
        var dark = Keys(LoadDictionary(Path.Combine("Themes", "Dark.xaml")));
        var light = Keys(LoadDictionary(Path.Combine("Themes", "Light.xaml")));

        dark.Should().NotBeEmpty();
        dark.Should().BeEquivalentTo(light);
        dark.Should().OnlyContain(k => k.StartsWith("Hg.", StringComparison.Ordinal));
    }

    [Fact]
    public void Every_referenced_token_exists_in_both_themes()
    {
        var dark = Keys(LoadDictionary(Path.Combine("Themes", "Dark.xaml")));
        var light = Keys(LoadDictionary(Path.Combine("Themes", "Light.xaml")));

        var referenced = new HashSet<string>(StringComparer.Ordinal);
        foreach (var file in Directory.EnumerateFiles(AppDir, "*.xaml", SearchOption.AllDirectories))
        {
            if (file.Contains(Path.Combine("Themes", "Dark"), StringComparison.Ordinal) ||
                file.Contains(Path.Combine("Themes", "Light"), StringComparison.Ordinal) ||
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
    }

    [Fact]
    public void Styles_dictionary_parses_headless()
    {
        var styles = LoadDictionary(Path.Combine("Themes", "Styles.xaml"));
        styles.Keys.Cast<object>().Should().NotBeEmpty();
    }
}

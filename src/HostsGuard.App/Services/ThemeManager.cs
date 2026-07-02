using System.Windows;

namespace HostsGuard.App.Services;

/// <summary>
/// Runtime theme switcher: swaps the Hg.* token dictionary (Dark/Light) in the
/// application's merged resources. Control styles bind tokens via
/// DynamicResource, so the swap restyles the live UI without a restart.
/// Headless-safe: with no <see cref="Application.Current"/> it only tracks state.
/// </summary>
public sealed class ThemeManager
{
    public string Current { get; private set; } = "dark";

    public void Apply(string theme)
    {
        Current = theme == "light" ? "light" : "dark";
        var app = Application.Current;
        if (app is null)
        {
            return;
        }

        var replacement = new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/Themes/{(Current == "light" ? "Light" : "Dark")}.xaml"),
        };

        var dicts = app.Resources.MergedDictionaries;
        for (var i = 0; i < dicts.Count; i++)
        {
            var src = dicts[i].Source?.OriginalString ?? string.Empty;
            if (src.EndsWith("Dark.xaml", StringComparison.OrdinalIgnoreCase) ||
                src.EndsWith("Light.xaml", StringComparison.OrdinalIgnoreCase))
            {
                dicts[i] = replacement;
                return;
            }
        }

        dicts.Insert(0, replacement);
    }
}

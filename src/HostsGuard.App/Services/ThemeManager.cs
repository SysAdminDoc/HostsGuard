using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Media;

namespace HostsGuard.App.Services;

/// <summary>
/// Runtime theme switcher: swaps the Hg.* token dictionary (Dark/Light) in the
/// application's merged resources. Control styles bind tokens via
/// DynamicResource, so the swap restyles the live UI without a restart.
/// Headless-safe: with no <see cref="Application.Current"/> it only tracks state.
/// </summary>
public sealed class ThemeManager : IDisposable
{
    public string Current { get; private set; } = "dark";

    public string Effective { get; private set; } = "dark";

    public bool IsHighContrast => Effective == "contrast";

    public event EventHandler? EffectiveThemeChanged;

    private bool _watching;
    private string? _contrastPreview;
    private ResourceDictionary? _contrastPreviewResources;

    public void Apply(string theme)
    {
        _contrastPreview = NormalizeContrastPreview(theme);
        Current = theme == "light" ? "light" : "dark";
        ApplyEffective(SystemParameters.HighContrast || _contrastPreview is not null);
    }

    public void StartWatching()
    {
        if (_watching)
        {
            return;
        }

        SystemParameters.StaticPropertyChanged += OnSystemParametersChanged;
        _watching = true;
        RefreshSystemContrast(SystemParameters.HighContrast || _contrastPreview is not null);
    }

    internal void RefreshSystemContrast(bool enabled) => ApplyEffective(enabled);

    private void ApplyEffective(bool highContrast)
    {
        var effective = highContrast ? "contrast" : Current;
        var app = Application.Current;
        if (app is null)
        {
            Effective = effective;
            return;
        }

        // Assembly-qualified so the URI resolves even when the entry assembly
        // is not HostsGuard.App (headless WPF smoke).
        var dictionaryName = effective switch
        {
            "contrast" => "Contrast",
            "light" => "Light",
            _ => "Dark",
        };
        var replacement = new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/HostsGuard.App;component/Themes/{dictionaryName}.xaml"),
        };

        var dicts = app.Resources.MergedDictionaries;
        if (_contrastPreviewResources is not null)
        {
            _ = dicts.Remove(_contrastPreviewResources);
            _contrastPreviewResources = null;
        }

        for (var i = 0; i < dicts.Count; i++)
        {
            var src = dicts[i].Source?.OriginalString ?? string.Empty;
            if (src.EndsWith("Dark.xaml", StringComparison.OrdinalIgnoreCase) ||
                src.EndsWith("Light.xaml", StringComparison.OrdinalIgnoreCase) ||
                src.EndsWith("Contrast.xaml", StringComparison.OrdinalIgnoreCase))
            {
                dicts[i] = replacement;
                AddContrastPreview(dicts, replacement);
                SetEffective(effective);
                return;
            }
        }

        dicts.Insert(0, replacement);
        AddContrastPreview(dicts, replacement);
        SetEffective(effective);
    }

    private void SetEffective(string effective)
    {
        var changed = Effective != effective;
        Effective = effective;
        if (changed)
        {
            EffectiveThemeChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    private void OnSystemParametersChanged(object? sender, PropertyChangedEventArgs e)
    {
        var app = Application.Current;
        if (app is null)
        {
            return;
        }

        _ = app.Dispatcher.BeginInvoke(() =>
            ApplyEffective(SystemParameters.HighContrast || _contrastPreview is not null));
    }

    private void AddContrastPreview(Collection<ResourceDictionary> dictionaries, ResourceDictionary contrast)
    {
        if (_contrastPreview is null)
        {
            return;
        }

        var palette = ContrastPreviewPalette.Create(_contrastPreview);
        var preview = new ResourceDictionary();
        foreach (var key in contrast.Keys.Cast<object>().Where(key => key.ToString()?.StartsWith("Hg.", StringComparison.Ordinal) == true))
        {
            preview[key] = Brush(palette.Text);
        }

        Set(preview, palette.Window,
            "Hg.Bg", "Hg.Base", "Hg.Panel", "Hg.SafeSoft", "Hg.SuccessSoft", "Hg.DangerSoft",
            "Hg.WarnSoft", "Hg.WarnRow", "Hg.DangerRow", "Hg.Mantle", "Hg.Crust", "Hg.OnDanger", "Hg.RowSelected");
        Set(preview, palette.Control, "Hg.PanelAlt", "Hg.Command", "Hg.S0");
        Set(preview, palette.Highlight,
            "Hg.RowHover", "Hg.AccentHover", "Hg.SuccessHover", "Hg.DangerSoftHover", "Hg.DangerHover",
            "Hg.Focus", "Hg.Sel", "Hg.Sky");
        Set(preview, palette.HighlightText, "Hg.OnSel");
        Set(preview, palette.Text, "Hg.OnRowSelected");
        Set(preview, palette.GrayText, "Hg.Disabled");
        Set(preview, palette.HotTrack, "Hg.Blue");

        _contrastPreviewResources = preview;
        dictionaries.Add(preview);
    }

    private static string? NormalizeContrastPreview(string theme)
    {
        var normalized = theme.Trim().ToLowerInvariant();
        return normalized is "contrast-aquatic" or "contrast-desert" or "contrast-dusk" or "contrast-night-sky"
            ? normalized["contrast-".Length..]
            : null;
    }

    private static void Set(ResourceDictionary resources, Color color, params string[] keys)
    {
        foreach (var key in keys)
        {
            resources[key] = Brush(color);
        }
    }

    private static SolidColorBrush Brush(Color color)
    {
        var brush = new SolidColorBrush(color);
        brush.Freeze();
        return brush;
    }

    private sealed record ContrastPreviewPalette(
        Color Window,
        Color Control,
        Color Text,
        Color Highlight,
        Color HighlightText,
        Color GrayText,
        Color HotTrack)
    {
        public static ContrastPreviewPalette Create(string name) => name switch
        {
            // Deterministic fixtures exercise the light/dark and warm/cool extremes of
            // Windows' four built-in themes. Production always uses live SystemColors.
            "aquatic" => New("#002B36", "#073642", "#FFFFFF", "#00FFFF", "#000000", "#C5D0D2", "#FFFF00"),
            "desert" => New("#FFF4D6", "#F3E4BC", "#302717", "#5B2C83", "#FFFFFF", "#625A4A", "#0000AA"),
            "dusk" => New("#2B173A", "#3D2350", "#FFFFFF", "#FFD75E", "#000000", "#C9B9D5", "#7FFFFF"),
            _ => New("#000000", "#101010", "#FFFFFF", "#00FFFF", "#000000", "#B3B3B3", "#FFFF00"),
        };

        private static ContrastPreviewPalette New(
            string window,
            string control,
            string text,
            string highlight,
            string highlightText,
            string grayText,
            string hotTrack) => new(
                Parse(window), Parse(control), Parse(text), Parse(highlight), Parse(highlightText), Parse(grayText), Parse(hotTrack));

        private static Color Parse(string value) => (Color)ColorConverter.ConvertFromString(value);
    }

    public void Dispose()
    {
        if (!_watching)
        {
            return;
        }

        SystemParameters.StaticPropertyChanged -= OnSystemParametersChanged;
        _watching = false;
    }
}

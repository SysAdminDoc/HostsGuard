using System.Windows.Markup;

namespace HostsGuard.App.Services;

/// <summary>
/// XAML localization markup extension (NET-098): <c>{svc:Loc Key=Tab_Tools,
/// Default=Tools}</c> resolves the key from the Strings resources for the current
/// UI culture, falling back to <see cref="Default"/> so an untranslated key never
/// blanks the UI. Resolved at load time — the culture is fixed before the window
/// is built, so a language change takes effect on the next launch.
/// </summary>
[MarkupExtensionReturnType(typeof(string))]
public sealed class LocExtension : MarkupExtension
{
    public LocExtension()
    {
    }

    public LocExtension(string key) => Key = key;

    public string Key { get; set; } = string.Empty;

    public string Default { get; set; } = string.Empty;

    public override object ProvideValue(IServiceProvider serviceProvider)
        => I18n.T(Key, Default.Length != 0 ? Default : Key);
}

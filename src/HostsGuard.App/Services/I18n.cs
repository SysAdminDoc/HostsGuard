using System.Globalization;
using System.Resources;

namespace HostsGuard.App.Services;

/// <summary>
/// i18n scaffolding — the <c>T(...)</c> equivalent. Strings resolve from
/// Resources/Strings.resx (satellite assemblies pick up future locales
/// automatically); a missing key falls back safely to the supplied English
/// default, so an incomplete translation can never crash or blank the UI.
/// </summary>
public static class I18n
{
    private static readonly ResourceManager Resources =
        new("HostsGuard.App.Resources.Strings", typeof(I18n).Assembly);

    /// <summary>Translate <paramref name="key"/>, falling back to <paramref name="english"/>.</summary>
    public static string T(string key, string english)
    {
        try
        {
            return Resources.GetString(key, CultureInfo.CurrentUICulture) ?? english;
        }
        catch (MissingManifestResourceException)
        {
            return english;
        }
    }

    /// <summary>Translate and format.</summary>
    public static string T(string key, string english, params object[] args)
        => string.Format(CultureInfo.CurrentCulture, T(key, english), args);
}

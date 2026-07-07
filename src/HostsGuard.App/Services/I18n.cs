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
        var value = english;
        try
        {
            value = Resources.GetString(key, CultureInfo.CurrentUICulture) ?? english;
        }
        catch (MissingManifestResourceException)
        {
            value = english;
        }

        return PseudoLocaleEnabled ? PseudoLocalize(value) : value;
    }

    /// <summary>Translate and format.</summary>
    public static string T(string key, string english, params object[] args)
        => string.Format(CultureInfo.CurrentCulture, T(key, english), args);

    public static string PseudoLocalize(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        var parts = System.Text.RegularExpressions.Regex.Split(value, @"(\{\d+(?::[^}]*)?\})");
        var builder = new System.Text.StringBuilder(value.Length + 8);
        builder.Append("[!! ");
        foreach (var part in parts)
        {
            if (part.Length == 0)
            {
                continue;
            }

            if (part.StartsWith('{') && part.EndsWith('}'))
            {
                builder.Append(part);
                continue;
            }

            foreach (var ch in part)
            {
                builder.Append(ch switch
                {
                    'A' => 'Â',
                    'a' => 'á',
                    'E' => 'É',
                    'e' => 'é',
                    'I' => 'Í',
                    'i' => 'í',
                    'O' => 'Ó',
                    'o' => 'ó',
                    'U' => 'Ú',
                    'u' => 'ú',
                    'C' => 'Ç',
                    'c' => 'ç',
                    'N' => 'Ñ',
                    'n' => 'ñ',
                    _ => ch,
                });
            }
        }

        builder.Append(" !!]");
        return builder.ToString();
    }

    private static bool PseudoLocaleEnabled =>
        string.Equals(Environment.GetEnvironmentVariable("HOSTSGUARD_PSEUDO_LOCALE"), "1", StringComparison.Ordinal) ||
        string.Equals(CultureInfo.CurrentUICulture.Name, "qps-ploc", StringComparison.OrdinalIgnoreCase);
}

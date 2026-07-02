namespace HostsGuard.Core;

/// <summary>
/// Normalizes and filters raw DNS query names from the ETW DNS-Client provider
/// (or the cache fallback). Mirrors the Python <c>_process_domain</c> filter:
/// lowercase, strip a trailing dot, and drop empty / IGNORED / dot-less names.
/// </summary>
public static class DnsEventNormalizer
{
    /// <summary>
    /// True if <paramref name="raw"/> is a reportable domain; the cleaned form is
    /// written to <paramref name="domain"/>.
    /// </summary>
    public static bool TryNormalize(string? raw, out string domain)
    {
        domain = string.Empty;
        var d = (raw ?? string.Empty).ToLowerInvariant().Trim().TrimEnd('.');
        if (d.Length == 0 || !d.Contains('.') || Domains.Ignored.Contains(d))
        {
            return false;
        }

        domain = d;
        return true;
    }
}

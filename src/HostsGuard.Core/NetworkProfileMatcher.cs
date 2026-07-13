using System.Text.Json;

namespace HostsGuard.Core;

/// <summary>Normalized signals describing the currently joined network.</summary>
public sealed record NetworkProfileIdentity(
    string Fingerprint,
    string GatewayMac,
    string Ssid,
    string InterfaceName,
    string DnsSuffix,
    bool VpnPresent);

/// <summary>A saved profile and the network predicates that must all match it.</summary>
public sealed record NetworkProfileMatchRule(
    string Profile,
    string Label,
    string Fingerprint = "",
    string GatewayMac = "",
    string Ssid = "",
    string InterfaceName = "",
    string DnsSuffix = "",
    bool? VpnPresent = null)
{
    public int PredicateCount =>
        Present(Fingerprint) + Present(GatewayMac) + Present(Ssid) +
        Present(InterfaceName) + Present(DnsSuffix) + (VpnPresent.HasValue ? 1 : 0);

    private static int Present(string value) => string.IsNullOrWhiteSpace(value) ? 0 : 1;
}

/// <summary>
/// Deterministically selects the most-specific matching network-profile rule.
/// Every populated predicate is conjunctive. More predicates win, followed by
/// gateway MAC, SSID, DNS suffix, interface, VPN presence, and finally profile
/// and label ordinal order. A legacy opaque fingerprint has gateway precedence.
/// </summary>
public static class NetworkProfileMatcher
{
    public static NetworkProfileMatchRule? Match(
        NetworkProfileIdentity identity,
        IEnumerable<NetworkProfileMatchRule> rules)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(rules);

        return rules
            .Where(HasPredicate)
            .Where(rule => Matches(identity, rule))
            .OrderByDescending(rule => rule.PredicateCount)
            .ThenByDescending(rule => Present(rule.GatewayMac) || Present(rule.Fingerprint))
            .ThenByDescending(rule => Present(rule.Ssid))
            .ThenByDescending(rule => Present(rule.DnsSuffix))
            .ThenByDescending(rule => Present(rule.InterfaceName))
            .ThenByDescending(rule => rule.VpnPresent.HasValue)
            .ThenBy(rule => rule.Profile, StringComparer.Ordinal)
            .ThenBy(rule => rule.Label, StringComparer.Ordinal)
            .FirstOrDefault();
    }

    public static bool Matches(NetworkProfileIdentity identity, NetworkProfileMatchRule rule)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(rule);

        return EqualIfSet(rule.Fingerprint, identity.Fingerprint, NormalizeOpaque)
            && EqualIfSet(rule.GatewayMac, identity.GatewayMac, NormalizeMac)
            && EqualIfSet(rule.Ssid, identity.Ssid, NormalizeText)
            && EqualIfSet(rule.InterfaceName, identity.InterfaceName, NormalizeText)
            && EqualIfSet(rule.DnsSuffix, identity.DnsSuffix, NormalizeDnsSuffix)
            && (!rule.VpnPresent.HasValue || rule.VpnPresent.Value == identity.VpnPresent);
    }

    private static bool HasPredicate(NetworkProfileMatchRule rule) => rule.PredicateCount > 0;

    private static bool EqualIfSet(string expected, string actual, Func<string, string> normalize) =>
        !Present(expected) || string.Equals(normalize(expected), normalize(actual), StringComparison.Ordinal);

    private static bool Present(string value) => !string.IsNullOrWhiteSpace(value);

    internal static string NormalizeMac(string value) =>
        string.Concat(value.Where(Uri.IsHexDigit)).ToUpperInvariant();

    internal static string NormalizeDnsSuffix(string value) =>
        NormalizeText(value).TrimEnd('.');

    internal static string NormalizeText(string value) => value.Trim().ToUpperInvariant();

    internal static string NormalizeOpaque(string value) => value.Trim().ToUpperInvariant();
}

/// <summary>
/// Reversible storage encoding for additive multi-signal rules. Existing plain
/// gateway fingerprints remain plain strings and continue to round-trip.
/// </summary>
public static class NetworkProfileSelectorCodec
{
    private const string Prefix = "match:v1:";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static string Encode(NetworkProfileMatchRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (rule.PredicateCount == 1 && !string.IsNullOrWhiteSpace(rule.Fingerprint))
        {
            return rule.Fingerprint.Trim();
        }

        if (rule.PredicateCount == 0)
        {
            throw new ArgumentException("At least one network-profile predicate is required.", nameof(rule));
        }

        var selector = new StoredSelector(
            Clean(rule.Fingerprint),
            Clean(rule.GatewayMac),
            Clean(rule.Ssid),
            Clean(rule.InterfaceName),
            Clean(rule.DnsSuffix),
            rule.VpnPresent);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(selector, JsonOptions);
        return Prefix + Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static NetworkProfileMatchRule Decode(string stored, string profile, string label)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stored);
        if (!stored.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return new(profile, label, Fingerprint: stored.Trim());
        }

        try
        {
            var encoded = stored[Prefix.Length..].Replace('-', '+').Replace('_', '/');
            encoded = encoded.PadRight(encoded.Length + ((4 - encoded.Length % 4) % 4), '=');
            var selector = JsonSerializer.Deserialize<StoredSelector>(Convert.FromBase64String(encoded), JsonOptions)
                ?? throw new FormatException("Network-profile selector payload is empty.");
            var rule = new NetworkProfileMatchRule(
                profile,
                label,
                selector.Fingerprint ?? string.Empty,
                selector.GatewayMac ?? string.Empty,
                selector.Ssid ?? string.Empty,
                selector.InterfaceName ?? string.Empty,
                selector.DnsSuffix ?? string.Empty,
                selector.VpnPresent);
            if (rule.PredicateCount == 0)
            {
                throw new FormatException("Network-profile selector has no predicates.");
            }

            return rule;
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            throw new FormatException("Network-profile selector is malformed.", ex);
        }
    }

    public static bool IsEncoded(string stored) => stored.StartsWith(Prefix, StringComparison.Ordinal);

    private static string Clean(string value) => value.Trim();

    private sealed record StoredSelector(
        string Fingerprint,
        string GatewayMac,
        string Ssid,
        string InterfaceName,
        string DnsSuffix,
        bool? VpnPresent);
}

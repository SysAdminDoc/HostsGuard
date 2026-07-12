using System.Runtime.Versioning;
using Microsoft.Win32;

namespace HostsGuard.Windows;

/// <summary>A watched DNS-relevant registry value that changed since the baseline.</summary>
public sealed record DnsRegistryChange(string Key, string Before, string After);

/// <summary>
/// Baseline-and-diff for DNS-path registry surfaces the hosts-file watch can't
/// see: DoH policy, NetBIOS/smart-name-resolution policy, and global name-server
/// overrides. <see cref="Snapshot"/> reads the current values; <see cref="Diff"/>
/// (pure, testable) reports every value that changed vs a stored baseline, so a
/// silent DNS hijack via Group Policy / registry raises a tamper alert.
///
/// The classic <c>Tcpip\Parameters\DataBasePath</c> redirect stays in
/// <see cref="HostsTamperWatch.CheckRegistryTamper"/> (a semantic check), so it
/// is intentionally NOT duplicated here.
/// </summary>
[SupportedOSPlatform("windows")]
public static class DnsRegistryBaseline
{
    private const string Absent = "(absent)";

    // (display key, HKLM subkey, value name). Kept to scalar values that move the
    // DNS resolution path; absence is normal and recorded as "(absent)".
    private static readonly (string Key, string SubKey, string Value)[] Watched =
    {
        (@"Dnscache\Parameters\EnableAutoDoh",
            @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "EnableAutoDoh"),
        (@"DNSClient\DoHPolicy",
            @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "DoHPolicy"),
        (@"DNSClient\EnableNetbios",
            @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableNetbios"),
        (@"DNSClient\DisableSmartNameResolution",
            @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "DisableSmartNameResolution"),
        (@"Tcpip\Parameters\NameServer",
            @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "NameServer"),
        (@"Tcpip6\Parameters\NameServer",
            @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "NameServer"),
    };

    /// <summary>Read the current value of every watched key ("(absent)" when unset).</summary>
    public static IReadOnlyDictionary<string, string> Snapshot()
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, subKey, value) in Watched)
        {
            result[key] = ReadValue(subKey, value);
        }

        return result;
    }

    private static string ReadValue(string subKey, string valueName)
    {
        try
        {
            using var reg = Registry.LocalMachine.OpenSubKey(subKey);
            var raw = reg?.GetValue(valueName);
            return raw is null ? Absent : Convert.ToString(raw, System.Globalization.CultureInfo.InvariantCulture) ?? Absent;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            // A key we cannot read is treated as absent rather than crashing the
            // baseline — the diff still flags a later readable change.
            return Absent;
        }
    }

    /// <summary>
    /// Every watched key whose value differs between <paramref name="baseline"/>
    /// and <paramref name="current"/>. Keys absent from either side fall back to
    /// "(absent)" so an appear/disappear is reported like any other change.
    /// </summary>
    public static IReadOnlyList<DnsRegistryChange> Diff(
        IReadOnlyDictionary<string, string> baseline,
        IReadOnlyDictionary<string, string> current)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(current);

        var keys = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var k in baseline.Keys)
        {
            keys.Add(k);
        }

        foreach (var k in current.Keys)
        {
            keys.Add(k);
        }

        var changes = new List<DnsRegistryChange>();
        foreach (var key in keys)
        {
            var before = baseline.TryGetValue(key, out var b) ? b : Absent;
            var after = current.TryGetValue(key, out var a) ? a : Absent;
            if (!string.Equals(before, after, StringComparison.Ordinal))
            {
                changes.Add(new DnsRegistryChange(key, before, after));
            }
        }

        return changes;
    }
}

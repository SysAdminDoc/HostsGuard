using System.Globalization;
using System.Net;
using System.Runtime.Versioning;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>Result of one <see cref="HostsAdoptionCoordinator.AdoptNow"/> pass.</summary>
public sealed record AdoptionOutcome(
    int Adopted,
    int Organized,
    int Suspicious,
    int FileBlocked,
    IReadOnlyList<string> AdoptedDomains)
{
    /// <summary>True when a hand edit mapped a domain to a real routable IP (a classic hosts hijack).</summary>
    public bool HasSuspiciousRedirect => Suspicious > 0;
}

/// <summary>
/// Adopts hand-added hosts-file entries into the managed database (NET-188).
/// When the user edits the hosts file directly in a text editor, this pass
/// dedupes and re-organizes the whole file into the canonical category
/// sections, curated-categorizes each entry, and imports every newly-added
/// sink-block domain (0.0.0.0/127.0.0.1/:: → host) as a "manual" managed row so
/// it shows up in the app exactly like an in-app block. The AI categorizer (when
/// enabled) fills in categories the curated table doesn't know.
///
/// A hand edit that redirects a domain to a real routable IP (e.g.
/// "93.184.216.34 www.bank.com") is NOT a block and is never adopted — it is
/// flagged as suspicious so the caller keeps the critical tamper alert.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HostsAdoptionCoordinator
{
    /// <summary>Meta key persisting the automatic-adoption toggle. Absent/"on" = enabled.</summary>
    public const string EnabledMetaKey = "adopt_manual_edits";
    private const string LastRunMetaKey = "adopt_manual_last_run";
    private const string LastResultMetaKey = "adopt_manual_last_result";

    /// <summary>Sink / non-routable prefixes that mean "block", never a redirect.</summary>
    private static readonly IReadOnlySet<string> SinkPrefixes = new HashSet<string>(StringComparer.Ordinal)
    {
        "0.0.0.0", "127.0.0.1", "::", "::1", "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "255.255.255.255",
    };

    private readonly HostsEngine _hosts;
    private readonly HostsDatabase _db;
    private readonly object _gate = new();

    public HostsAdoptionCoordinator(HostsEngine hosts, HostsDatabase db)
    {
        _hosts = hosts ?? throw new ArgumentNullException(nameof(hosts));
        _db = db ?? throw new ArgumentNullException(nameof(db));
    }

    /// <summary>Automatic on-external-change adoption. Default on; only an explicit "off" disables it.</summary>
    public bool Enabled => !string.Equals(_db.GetMeta(EnabledMetaKey), "off", StringComparison.Ordinal);

    /// <summary>Persist the automatic-adoption toggle.</summary>
    public void SetEnabled(bool enabled) => _db.SetMeta(EnabledMetaKey, enabled ? "on" : "off");

    public string LastRun => _db.GetMeta(LastRunMetaKey) ?? string.Empty;

    public string LastResult => _db.GetMeta(LastResultMetaKey) ?? string.Empty;

    /// <summary>Sink-blocked hosts domains that aren't managed rows yet (the adoption backlog).</summary>
    public int CountUnadopted()
    {
        _hosts.Read();
        var managed = _db.GetDomains().Select(r => r.Domain).ToHashSet(StringComparer.Ordinal);
        return _hosts.GetBlocked().Count(d => !managed.Contains(d));
    }

    /// <summary>
    /// Run the adoption pass: refresh from disk, adopt newly hand-added sink-block
    /// domains as managed "manual" rows with a curated category, then dedupe and
    /// re-organize the whole file into canonical category sections. Idempotent —
    /// an already-adopted, already-organized file returns zero counts and writes
    /// nothing. Never throws for a normal parse; an AV file lock surfaces as an
    /// <see cref="IOException"/> for the caller to translate.
    /// </summary>
    public AdoptionOutcome AdoptNow(string reason)
    {
        lock (_gate)
        {
            // The tamper watcher already saw the on-disk change; re-read so the
            // engine's in-memory view matches what the editor wrote.
            _hosts.Read();
            var lines = _hosts.GetLines();
            var suspicious = CountSuspiciousRedirects(lines);

            var blocked = _hosts.GetBlocked();
            var managed = _db.GetDomains().Select(r => r.Domain).ToHashSet(StringComparer.Ordinal);
            var newDomains = blocked
                .Where(d => !managed.Contains(d))
                .OrderBy(d => d, StringComparer.Ordinal)
                .ToList();

            if (newDomains.Count != 0)
            {
                // Import as manual rows in one transaction (allowlist-wins upsert),
                // then seed the curated category so the file organizes cleanly.
                _db.AddDomainsBulk(newDomains.Select(d => (d, "blocked", "manual")));
                foreach (var d in newDomains)
                {
                    _db.SetCategoryIfEmpty(d, DomainCategories.Lookup(d));
                }
            }

            // Dedupe (SortedSet per category drops duplicate hosts) + organize the
            // whole file into the canonical taxonomy. Curated categories win; an
            // unknown domain folds through its current "# Section" header, else "Other".
            var organized = _hosts.NormalizeCategorySections(
                DomainCategories.Canonicalize,
                DomainCategories.Lookup,
                DomainCategories.Canonical);

            var outcome = new AdoptionOutcome(newDomains.Count, organized, suspicious, blocked.Count, newDomains);
            Record(reason, outcome);
            return outcome;
        }
    }

    /// <summary>Count hand-edit lines that map a domain to a real routable IP (a hosts hijack signal).</summary>
    public static int CountSuspiciousRedirects(IReadOnlyList<string> lines)
    {
        ArgumentNullException.ThrowIfNull(lines);
        var count = 0;
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var parts = line.Split('#', 2)[0].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2 || SinkPrefixes.Contains(parts[0]))
            {
                continue;
            }

            if (!IPAddress.TryParse(parts[0], out var ip) || IsNonRoutable(ip))
            {
                continue;
            }

            // A real IP mapped to something domain-shaped = a redirect, not a block.
            if (parts.Skip(1).Any(p => Domains.LooksLikeDomain(Domains.ToAscii(p))))
            {
                count++;
            }
        }

        return count;
    }

    private static bool IsNonRoutable(IPAddress ip)
    {
        // Fold an IPv4-mapped IPv6 literal (e.g. ::ffff:0.0.0.0) to its IPv4 form
        // so a mapped sink/loopback address isn't mistaken for a routable redirect.
        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        return IPAddress.IsLoopback(ip)
            || ip.Equals(IPAddress.Any)
            || ip.Equals(IPAddress.IPv6Any)
            || ip.Equals(IPAddress.Broadcast);
    }

    private void Record(string reason, AdoptionOutcome outcome)
    {
        var summary = outcome.Adopted == 0 && outcome.Organized == 0
            ? "no new manual entries"
            : $"adopted {outcome.Adopted}, organized {outcome.Organized}";
        _db.SetMeta(LastRunMetaKey, DateTime.Now.ToString("o", CultureInfo.InvariantCulture));
        _db.SetMeta(LastResultMetaKey, summary);
        if (outcome.Adopted != 0 || outcome.Organized != 0)
        {
            _db.LogEvent("hosts", "manual_adopted", details: $"{summary} ({reason})", reason: "manual_edit");
        }
    }
}

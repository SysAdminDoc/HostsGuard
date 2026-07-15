using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

internal sealed record EncryptedResolverDiscoveryEntry(
    string AdapterId,
    string AdapterName,
    string Source,
    string Resolver,
    string Outcome,
    int Priority,
    string Target,
    IReadOnlyList<string> Addresses,
    IReadOnlyList<string> Protocols,
    string Endpoint,
    bool Drifted,
    string Detail);

internal sealed record EncryptedResolverDiscoverySnapshot(
    IReadOnlyList<EncryptedResolverDiscoveryEntry> Entries,
    DateTime? CheckedAtUtc,
    bool Running,
    bool BaselinePresent,
    bool DriftDetected,
    string Fingerprint,
    string Message);

/// <summary>
/// Manually probes RFC 9462 DDR against each configured resolver and inspects
/// RFC 9463 DHCPv4 option 162 and DHCPv6 option 144. It never changes DNS
/// configuration or adopts a discovered endpoint. Only an explicit baseline
/// acceptance writes trust state.
/// </summary>
internal sealed class EncryptedResolverDiscoveryCoordinator
{
    private const string BaselineMetaKey = "encrypted_resolver_designation_baseline";
    private const string LastDriftAlertMetaKey = "encrypted_resolver_designation_last_drift_alert";
    private const string LastMalformedAlertMetaKey = "encrypted_resolver_designation_last_malformed_alert";
    private static readonly TimeSpan DdrTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan DnrTimeout = TimeSpan.FromSeconds(3);
    private const int MaxDdrAliasHops = 4;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    private readonly object _stateGate = new();
    private readonly SemaphoreSlim _runGate = new(1, 1);
    private readonly IDnsConfig? _dns;
    private readonly IDnsServiceBindingQuery? _ddr;
    private readonly IDnrOptionSource? _dnr;
    private readonly HostsDatabase _db;
    private readonly IClock _clock;
    private IReadOnlyList<EncryptedResolverDiscoveryEntry> _entries = [];
    private Dictionary<string, string> _current = new(StringComparer.Ordinal);
    private DateTime? _checkedAtUtc;
    private bool _running;
    private bool _driftDetected;
    private string _fingerprint = string.Empty;
    private string _message = "Encrypted-resolver discovery has not run";

    internal EncryptedResolverDiscoveryCoordinator(
        IDnsConfig? dns,
        IDnsServiceBindingQuery? ddr,
        IDnrOptionSource? dnr,
        HostsDatabase db,
        IClock clock)
    {
        _dns = dns;
        _ddr = ddr;
        _dnr = dnr;
        _db = db;
        _clock = clock;
    }

    internal EncryptedResolverDiscoverySnapshot Snapshot()
    {
        lock (_stateGate)
        {
            return SnapshotLocked();
        }
    }

    internal async Task<EncryptedResolverDiscoverySnapshot> RunAsync(CancellationToken cancellationToken)
    {
        if (!await _runGate.WaitAsync(0, cancellationToken).ConfigureAwait(false))
        {
            lock (_stateGate)
            {
                return SnapshotLocked() with { Running = true, Message = "Encrypted-resolver discovery is already running" };
            }
        }

        try
        {
            lock (_stateGate)
            {
                _running = true;
                _message = "Encrypted-resolver discovery is running";
            }

            var rows = new List<EncryptedResolverDiscoveryEntry>();
            var current = new Dictionary<string, string>(StringComparer.Ordinal);
            var malformed = new HashSet<string>(StringComparer.Ordinal);
            if (_dns is null)
            {
                return Complete(rows, current, malformed, "DNS engine is not attached to this service instance");
            }

            var adapters = _dns.ListResolverAdapters();
            foreach (var adapter in adapters)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (_ddr is not null)
                {
                    var resolvers = adapter.ConfiguredResolvers.Count != 0
                        ? adapter.ConfiguredResolvers
                        : adapter.EffectiveResolvers;
                    foreach (var resolver in resolvers.Distinct(StringComparer.OrdinalIgnoreCase))
                    {
                        await InspectDdrAsync(adapter, resolver, rows, current, malformed, cancellationToken)
                            .ConfigureAwait(false);
                    }
                }

                if (adapter.UsesDhcp && _dnr is not null)
                {
                    await InspectDnrAsync(adapter, rows, current, malformed, cancellationToken)
                        .ConfigureAwait(false);
                    await InspectDnrV6Async(adapter, rows, current, malformed, cancellationToken)
                        .ConfigureAwait(false);
                }
            }

            var message = rows.Count == 0
                ? "No eligible adapters or resolver endpoints were found"
                : $"Inspected {rows.Count} DDR/DNR observation rows without changing DNS settings";
            return Complete(rows, current, malformed, message);
        }
        catch (OperationCanceledException)
        {
            lock (_stateGate)
            {
                _running = false;
                _message = "Encrypted-resolver discovery was cancelled; cached results were retained";
            }

            throw;
        }
        finally
        {
            _runGate.Release();
        }
    }

    internal EncryptedResolverDiscoverySnapshot AcceptCurrentBaseline()
    {
        lock (_stateGate)
        {
            if (_current.Count == 0)
            {
                return SnapshotLocked() with { Message = "Run discovery before accepting a baseline" };
            }

            if (_entries.Any(static row => row.Outcome == "malformed"))
            {
                return SnapshotLocked() with
                {
                    Message = "Malformed designation data cannot be trusted; correct the network response and rerun discovery",
                };
            }

            SaveBaseline(_current);
            _db.SetMeta(LastDriftAlertMetaKey, string.Empty);
            _db.SetMeta(LastMalformedAlertMetaKey, string.Empty);
            _driftDetected = false;
            _entries = _entries.Select(row => row with { Drifted = false }).ToArray();
            _message = "Current encrypted-resolver designations are the accepted baseline";
            return SnapshotLocked();
        }
    }

    private async Task InspectDdrAsync(
        DnsAdapterState adapter,
        string resolver,
        List<EncryptedResolverDiscoveryEntry> rows,
        Dictionary<string, string> current,
        HashSet<string> malformed,
        CancellationToken cancellationToken)
    {
        var key = $"ddr|{adapter.Id}|{resolver}";
        if (!System.Net.IPAddress.TryParse(resolver, out _))
        {
            rows.Add(StatusRow(adapter, "ddr", resolver, "unavailable", "configured resolver is not an IP address"));
            return;
        }

        var records = new List<DesignatedResolverRecord>();
        var queryName = "_dns.resolver.arpa";
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { queryName };
        for (var hop = 0; hop <= MaxDdrAliasHops; hop++)
        {
            var result = await _ddr!.QueryResourceRecordsAsync(
                queryName,
                64,
                DdrTimeout,
                cancellationToken,
                new DnsQueryTarget(resolver, adapter.InterfaceIndex)).ConfigureAwait(false);
            if (result.Outcome is DnsRawQueryOutcome.NoRecords or DnsRawQueryOutcome.NameNotFound)
            {
                if (hop == 0)
                {
                    current[key] = "none";
                    rows.Add(StatusRow(adapter, "ddr", resolver, "no_records", "resolver advertised no DDR upgrade"));
                }
                else
                {
                    rows.Add(StatusRow(adapter, "ddr", resolver, "no_records", $"DDR alias target {queryName} returned no records"));
                }
                return;
            }

            if (result.Outcome != DnsRawQueryOutcome.Success)
            {
                rows.Add(StatusRow(adapter, "ddr", resolver, OutcomeToken(result.Outcome), result.Error));
                return;
            }

            var parsedAtHop = new List<DesignatedResolverRecord>();
            foreach (var raw in result.Records)
            {
                var parsed = DesignatedResolver.ParseSvcb(raw.Rdata);
                if (parsed is null)
                {
                    malformed.Add($"DDR {adapter.Name}/{resolver}");
                    rows.Add(StatusRow(adapter, "ddr", resolver, "malformed", "invalid SVCB RDATA rejected"));
                }
                else
                {
                    records.Add(parsed);
                    parsedAtHop.Add(parsed);
                    rows.Add(ResolverRow(
                        adapter,
                        "ddr",
                        resolver,
                        parsed,
                        [],
                        parsed.Priority == 0 ? $"alias to {parsed.TargetName}" : "advertised"));
                }
            }

            var aliases = parsedAtHop.Where(static record => record.Priority == 0).ToArray();
            if (aliases.Length == 0)
            {
                current[key] = CanonicalRecords(records);
                return;
            }

            if (aliases.Length != 1 || parsedAtHop.Count != 1 || result.Records.Count != 1)
            {
                malformed.Add($"DDR alias {adapter.Name}/{resolver}");
                rows.Add(StatusRow(adapter, "ddr", resolver, "malformed", "ambiguous DDR AliasMode response rejected"));
                return;
            }

            queryName = aliases[0].TargetName;
            if (!visited.Add(queryName))
            {
                malformed.Add($"DDR alias loop {adapter.Name}/{resolver}");
                rows.Add(StatusRow(adapter, "ddr", resolver, "malformed", "DDR alias loop rejected"));
                return;
            }
        }

        malformed.Add($"DDR alias depth {adapter.Name}/{resolver}");
        rows.Add(StatusRow(adapter, "ddr", resolver, "malformed", "DDR alias chain exceeded four hops"));
    }

    private async Task InspectDnrAsync(
        DnsAdapterState adapter,
        List<EncryptedResolverDiscoveryEntry> rows,
        Dictionary<string, string> current,
        HashSet<string> malformed,
        CancellationToken cancellationToken)
    {
        var key = $"dnr_v4|{adapter.Id}";
        var result = await _dnr!.ReadV4Async(adapter.Id, DnrTimeout, cancellationToken).ConfigureAwait(false);
        if (result.Outcome == DnrOptionOutcome.NoOption)
        {
            current[key] = "none";
            rows.Add(StatusRow(adapter, "dnr_v4", string.Empty, "no_option", "DHCPv4 option 162 was not offered"));
            return;
        }

        if (result.Outcome != DnrOptionOutcome.Success)
        {
            rows.Add(StatusRow(adapter, "dnr_v4", string.Empty, DnrOutcomeToken(result.Outcome), result.Error));
            return;
        }

        var parsed = DesignatedResolver.ParseDnrV4Option(result.Data);
        if (parsed is null)
        {
            malformed.Add($"DNR {adapter.Name}");
            current[key] = "malformed:" + Convert.ToHexString(SHA256.HashData(result.Data)).ToLowerInvariant();
            rows.Add(StatusRow(adapter, "dnr_v4", string.Empty, "malformed", "invalid DHCPv4 option 162 rejected"));
            return;
        }

        foreach (var designation in parsed)
        {
            rows.Add(ResolverRow(
                adapter,
                "dnr_v4",
                string.Empty,
                designation.Resolver,
                designation.Addresses,
                designation.AdnOnly ? "ADN-only designation" : "network designation"));
        }

        current[key] = CanonicalDnr(parsed);
    }

    private async Task InspectDnrV6Async(
        DnsAdapterState adapter,
        List<EncryptedResolverDiscoveryEntry> rows,
        Dictionary<string, string> current,
        HashSet<string> malformed,
        CancellationToken cancellationToken)
    {
        var key = $"dnr_v6|{adapter.Id}";
        var result = await _dnr!.ReadV6Async(adapter.Id, DnrTimeout, cancellationToken).ConfigureAwait(false);
        if (result.Outcome == DnrOptionOutcome.NoOption)
        {
            current[key] = "none";
            rows.Add(StatusRow(adapter, "dnr_v6", string.Empty, "no_option", "DHCPv6 option 144 was not offered"));
            return;
        }

        if (result.Outcome != DnrOptionOutcome.Success)
        {
            rows.Add(StatusRow(adapter, "dnr_v6", string.Empty, DnrOutcomeToken(result.Outcome), result.Error));
            return;
        }

        var parsed = DesignatedResolver.ParseDnrV6Option(result.Data);
        if (parsed is null)
        {
            malformed.Add($"DNRv6 {adapter.Name}");
            current[key] = "malformed:" + Convert.ToHexString(SHA256.HashData(result.Data)).ToLowerInvariant();
            rows.Add(StatusRow(adapter, "dnr_v6", string.Empty, "malformed", "invalid DHCPv6 option 144 rejected"));
            return;
        }

        rows.Add(ResolverRow(
            adapter,
            "dnr_v6",
            string.Empty,
            parsed.Resolver,
            parsed.Addresses,
            parsed.AdnOnly ? "ADN-only designation" : "network designation"));
        current[key] = CanonicalDnr(parsed);
    }

    private EncryptedResolverDiscoverySnapshot Complete(
        List<EncryptedResolverDiscoveryEntry> rows,
        Dictionary<string, string> current,
        HashSet<string> malformed,
        string message)
    {
        var baseline = LoadBaseline();
        var driftKeys = baseline is null
            ? new HashSet<string>(StringComparer.Ordinal)
            : current.Where(pair => !baseline.TryGetValue(pair.Key, out var prior)
                                     || !string.Equals(prior, pair.Value, StringComparison.Ordinal))
                .Select(pair => pair.Key)
                .ToHashSet(StringComparer.Ordinal);
        var drift = driftKeys.Count != 0;
        var fingerprint = Fingerprint(current);

        if (baseline is null && current.Count != 0 && malformed.Count == 0)
        {
            SaveBaseline(current);
            message += "; initial baseline saved";
        }
        else if (baseline is null && malformed.Count != 0)
        {
            message += "; initial baseline not saved because malformed data was rejected";
        }
        else if (drift)
        {
            message += $"; {driftKeys.Count} designation source(s) differ from the accepted baseline";
            AlertOnce(LastDriftAlertMetaKey, fingerprint, "Encrypted resolver designation changed",
                $"Changed sources: {string.Join(", ", driftKeys.Order(StringComparer.Ordinal))}");
        }

        if (malformed.Count != 0)
        {
            message += $"; rejected {malformed.Count} malformed designation(s)";
            AlertOnce(LastMalformedAlertMetaKey,
                Fingerprint(malformed.ToDictionary(value => value, _ => "malformed", StringComparer.Ordinal)),
                "Malformed encrypted resolver designation",
                string.Join(", ", malformed));
        }

        var markedRows = rows.Select(row => row with
        {
            Drifted = driftKeys.Contains($"{row.Source}|{row.AdapterId}|{row.Resolver}")
                      || driftKeys.Contains($"{row.Source}|{row.AdapterId}"),
        }).ToArray();
        lock (_stateGate)
        {
            _entries = markedRows;
            _current = new Dictionary<string, string>(current, StringComparer.Ordinal);
            _checkedAtUtc = _clock.UtcNow;
            _running = false;
            _driftDetected = drift || malformed.Count != 0;
            _fingerprint = fingerprint;
            _message = message;
            _db.LogEvent("dns", "encrypted_resolver_discovery",
                details: $"rows={rows.Count}; definitive={current.Count}; drift={_driftDetected}; {message}");
            return SnapshotLocked();
        }
    }

    private void AlertOnce(string metaKey, string fingerprint, string title, string details)
    {
        if (string.Equals(_db.GetMeta(metaKey), fingerprint, StringComparison.Ordinal))
        {
            return;
        }

        _db.AddAlert(
            "encrypted_resolver_drift",
            "warning",
            title,
            "network DNS designation",
            details,
            action: "encrypted_resolver_drift");
        _db.SetMeta(metaKey, fingerprint);
    }

    private Dictionary<string, string>? LoadBaseline()
    {
        var json = _db.GetMeta(BaselineMetaKey);
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, string>>(json, JsonOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private void SaveBaseline(IReadOnlyDictionary<string, string> baseline)
        => _db.SetMeta(BaselineMetaKey, JsonSerializer.Serialize(
            baseline.OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal),
            JsonOptions));

    private static string CanonicalRecords(IEnumerable<DesignatedResolverRecord> records)
        => string.Join(';', records.Select(CanonicalRecord).Order(StringComparer.Ordinal));

    private static string CanonicalDnr(IEnumerable<DnrV4Resolver> records)
        => string.Join(';', records.Select(record =>
                $"{CanonicalRecord(record.Resolver)}|addresses={string.Join(',', record.Addresses)}|adn={record.AdnOnly}")
            .Order(StringComparer.Ordinal));

    private static string CanonicalDnr(DnrV6Resolver record)
        => $"{CanonicalRecord(record.Resolver)}|addresses={string.Join(',', record.Addresses)}|adn={record.AdnOnly}";

    private static string CanonicalRecord(DesignatedResolverRecord record)
        => string.Join('|',
            $"priority={record.Priority}",
            $"target={CanonicalText(record.TargetName)}",
            $"mandatory={string.Join(',', record.MandatoryKeys)}",
            $"alpn={string.Join(',', record.Alpn.Select(CanonicalText))}",
            $"no_default_alpn={record.NoDefaultAlpn}",
            $"port={record.Port}",
            $"ipv4={string.Join(',', record.Ipv4Hints)}",
            $"ech={(record.Ech is null ? string.Empty : Convert.ToHexString(record.Ech))}",
            $"ipv6={string.Join(',', record.Ipv6Hints)}",
            $"dohpath={CanonicalText(record.DohPath ?? string.Empty)}",
            $"unknown={string.Join(',', record.UnknownParameters.Select(parameter => $"{parameter.Key}:{Convert.ToHexString(parameter.Value)}"))}");

    private static string CanonicalText(string value)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

    private static string Fingerprint(IReadOnlyDictionary<string, string> values)
    {
        var canonical = string.Join('\n', values.OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => $"{pair.Key}={pair.Value}"));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private static EncryptedResolverDiscoveryEntry ResolverRow(
        DnsAdapterState adapter,
        string source,
        string resolver,
        DesignatedResolverRecord record,
        IReadOnlyList<string> addresses,
        string detail)
        => new(
            adapter.Id,
            adapter.Name,
            source,
            resolver,
            record.IsEncrypted ? "encrypted" : "advertised",
            record.Priority,
            record.TargetName,
            addresses,
            record.Alpn,
            record.DohEndpoint ?? (record.Port is { } port ? $"{record.TargetName}:{port}" : record.TargetName),
            false,
            detail);

    private static EncryptedResolverDiscoveryEntry StatusRow(
        DnsAdapterState adapter,
        string source,
        string resolver,
        string outcome,
        string detail)
        => new(adapter.Id, adapter.Name, source, resolver, outcome, 0, string.Empty, [], [], string.Empty, false, detail);

    private static string OutcomeToken(DnsRawQueryOutcome outcome) => outcome switch
    {
        DnsRawQueryOutcome.Timeout => "timeout",
        DnsRawQueryOutcome.ApiUnavailable => "api_unavailable",
        _ => "failed",
    };

    private static string DnrOutcomeToken(DnrOptionOutcome outcome) => outcome switch
    {
        DnrOptionOutcome.Busy => "busy",
        DnrOptionOutcome.Timeout => "timeout",
        DnrOptionOutcome.ApiUnavailable => "api_unavailable",
        _ => "failed",
    };

    private EncryptedResolverDiscoverySnapshot SnapshotLocked() => new(
        _entries,
        _checkedAtUtc,
        _running,
        LoadBaseline() is not null,
        _driftDetected,
        _fingerprint,
        _message);
}

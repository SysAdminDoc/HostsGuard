using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

public sealed record WfpFilterDriftChange(
    string ChangeKind,
    Guid FilterKey,
    string Name,
    string Lifetime,
    Guid LayerKey,
    string LayerName,
    Guid SubLayerKey,
    string SubLayerName,
    string Action,
    Guid? CalloutKey,
    bool Disabled);

public sealed record WfpFilterDriftInspection(
    bool Available,
    string ErrorCode,
    DateTime CheckedAtUtc,
    bool BaselineExists,
    int CurrentFilterCount,
    IReadOnlyList<WfpFilterDriftChange> Changes);

public sealed record WfpFilterDriftCheckResult(
    bool Available,
    bool BaselineCreated,
    bool AlertRaised,
    IReadOnlyList<WfpFilterDriftChange> Changes);

internal sealed record PersistedWfpFilter(
    string FilterKey,
    string Name,
    string Lifetime,
    string LayerKey,
    string LayerName,
    string SubLayerKey,
    string SubLayerName,
    string Action,
    string CalloutKey,
    bool Disabled,
    string Fingerprint);

/// <summary>
/// Alert-only baseline monitor for persistent and boot-time WFP filter objects.
/// It never mutates WFP and never advances a seeded baseline automatically.
/// </summary>
public sealed class WfpFilterDriftMonitor : IDisposable
{
    internal const string BaselineMetaKey = "wfp_persistent_filter_baseline_v1";
    internal const string LastAlertMetaKey = "wfp_persistent_filter_last_alert_v1";
    private static readonly TimeSpan DefaultInterval = TimeSpan.FromMinutes(2);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IWfpFilterInventory _inventory;
    private readonly HostsDatabase _db;
    private readonly TimeSpan _interval;
    private readonly object _gate = new();
    private System.Threading.Timer? _timer;
    private bool _disposed;

    public WfpFilterDriftMonitor(
        IWfpFilterInventory inventory,
        HostsDatabase db,
        TimeSpan? interval = null)
    {
        _inventory = inventory ?? throw new ArgumentNullException(nameof(inventory));
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _interval = interval ?? DefaultInterval;
        if (_interval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(interval));
        }
    }

    public void Start()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _timer ??= new System.Threading.Timer(_ => PollSafely(), null, TimeSpan.Zero, _interval);
        }
    }

    public WfpFilterDriftCheckResult CheckNow()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var snapshot = _inventory.Snapshot();
            if (!snapshot.Available)
            {
                return new WfpFilterDriftCheckResult(false, false, false, []);
            }

            var current = Normalize(snapshot.Filters);
            var baseline = ReadBaseline();
            if (baseline is null)
            {
                WriteBaseline(current);
                _db.SetMeta(LastAlertMetaKey, string.Empty);
                _db.LogEvent(
                    "wfp",
                    "wfp_filter_baseline_seeded",
                    details: $"{current.Count} persistent/boot-time filter(s)",
                    reason: "baseline");
                return new WfpFilterDriftCheckResult(true, true, false, []);
            }

            var changes = Diff(baseline, current);
            if (changes.Count == 0)
            {
                _db.SetMeta(LastAlertMetaKey, string.Empty);
                return new WfpFilterDriftCheckResult(true, false, false, changes);
            }

            var fingerprint = SnapshotFingerprint(current);
            if (string.Equals(_db.GetMeta(LastAlertMetaKey), fingerprint, StringComparison.Ordinal))
            {
                return new WfpFilterDriftCheckResult(true, false, false, changes);
            }

            foreach (var change in changes.Take(25))
            {
                var details = Describe(change);
                _db.LogEvent(
                    change.Name,
                    "wfp_filter_baseline_changed",
                    details: details,
                    reason: "tamper");
                _db.AddAlert(
                    "wfp_filter_drift",
                    "warning",
                    change.ChangeKind switch
                    {
                        "added" => "Persistent WFP filter appeared",
                        "removed" => "Persistent WFP filter vanished",
                        _ => "Persistent WFP filter changed",
                    },
                    change.FilterKey.ToString("D"),
                    details,
                    action: change.ChangeKind);
            }

            if (changes.Count > 25)
            {
                _db.AddAlert(
                    "wfp_filter_drift",
                    "warning",
                    "Many persistent WFP filters changed",
                    "WFP persistent filter baseline",
                    $"{changes.Count} changes detected; the first 25 were recorded with layer, sublayer, and action evidence.",
                    action: "bulk-change");
            }

            _db.SetMeta(LastAlertMetaKey, fingerprint);
            return new WfpFilterDriftCheckResult(true, false, true, changes);
        }
    }

    /// <summary>Side-effect-free live comparison for diagnostics/UI/CLI.</summary>
    public WfpFilterDriftInspection Inspect()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var snapshot = _inventory.Snapshot();
            if (!snapshot.Available)
            {
                return new WfpFilterDriftInspection(
                    false,
                    snapshot.ErrorCode,
                    snapshot.CheckedAtUtc,
                    ReadBaseline() is not null,
                    0,
                    []);
            }

            var current = Normalize(snapshot.Filters);
            var baseline = ReadBaseline();
            return new WfpFilterDriftInspection(
                true,
                string.Empty,
                snapshot.CheckedAtUtc,
                baseline is not null,
                current.Count,
                baseline is null ? [] : Diff(baseline, current));
        }
    }

    internal static IReadOnlyList<PersistedWfpFilter> Normalize(IReadOnlyList<WfpPersistentFilter> filters)
    {
        ArgumentNullException.ThrowIfNull(filters);
        return filters
            .Select(filter =>
            {
                ArgumentNullException.ThrowIfNull(filter);
                var key = filter.FilterKey.ToString("D");
                var name = Clean(filter.Name, 160, key);
                var lifetime = Clean(filter.Lifetime, 32, "unknown");
                var layerKey = filter.LayerKey.ToString("D");
                var layerName = Clean(filter.LayerName, 128, layerKey);
                var subLayerKey = filter.SubLayerKey.ToString("D");
                var subLayerName = Clean(filter.SubLayerName, 128, subLayerKey);
                var action = Clean(filter.Action, 64, "unknown");
                var callout = filter.CalloutKey?.ToString("D") ?? string.Empty;
                var fingerprint = Fingerprint(string.Join('\0',
                    name,
                    lifetime,
                    layerKey,
                    layerName,
                    subLayerKey,
                    subLayerName,
                    action,
                    callout,
                    filter.Disabled ? "disabled" : "enabled"));
                return new PersistedWfpFilter(
                    key,
                    name,
                    lifetime,
                    layerKey,
                    layerName,
                    subLayerKey,
                    subLayerName,
                    action,
                    callout,
                    filter.Disabled,
                    fingerprint);
            })
            .OrderBy(filter => filter.FilterKey, StringComparer.Ordinal)
            .GroupBy(filter => filter.FilterKey, StringComparer.Ordinal)
            .Select(group => group.Single())
            .ToArray();
    }

    internal static IReadOnlyList<WfpFilterDriftChange> Diff(
        IReadOnlyList<PersistedWfpFilter> baseline,
        IReadOnlyList<PersistedWfpFilter> current)
    {
        var before = baseline.ToDictionary(filter => filter.FilterKey, StringComparer.Ordinal);
        var after = current.ToDictionary(filter => filter.FilterKey, StringComparer.Ordinal);
        var keys = before.Keys.Concat(after.Keys)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal);
        var changes = new List<WfpFilterDriftChange>();
        foreach (var key in keys)
        {
            before.TryGetValue(key, out var oldFilter);
            after.TryGetValue(key, out var newFilter);
            if (oldFilter?.Fingerprint == newFilter?.Fingerprint)
            {
                continue;
            }

            var filter = newFilter ?? oldFilter!;
            changes.Add(new WfpFilterDriftChange(
                oldFilter is null ? "added" : newFilter is null ? "removed" : "changed",
                Guid.Parse(filter.FilterKey),
                filter.Name,
                filter.Lifetime,
                Guid.Parse(filter.LayerKey),
                filter.LayerName,
                Guid.Parse(filter.SubLayerKey),
                filter.SubLayerName,
                filter.Action,
                Guid.TryParse(filter.CalloutKey, out var callout) ? callout : null,
                filter.Disabled));
        }

        return changes;
    }

    private IReadOnlyList<PersistedWfpFilter>? ReadBaseline()
    {
        var json = _db.GetMeta(BaselineMetaKey);
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<PersistedWfpFilter[]>(json, JsonOptions) ?? [];
        }
        catch (JsonException ex)
        {
            _db.LogEvent("wfp", "wfp_filter_baseline_invalid", details: ex.Message, reason: "baseline");
            return null;
        }
    }

    private void WriteBaseline(IReadOnlyList<PersistedWfpFilter> filters) =>
        _db.SetMeta(BaselineMetaKey, JsonSerializer.Serialize(filters, JsonOptions));

    private static string Describe(WfpFilterDriftChange change)
    {
        var callout = change.CalloutKey is { } key ? $"; callout={key:D}" : string.Empty;
        return $"{change.ChangeKind}; lifetime={change.Lifetime}; name={change.Name}; " +
               $"layer={change.LayerName} [{change.LayerKey:D}]; " +
               $"sublayer={change.SubLayerName} [{change.SubLayerKey:D}]; " +
               $"action={change.Action}{callout}; disabled={change.Disabled.ToString().ToLowerInvariant()}";
    }

    private static string SnapshotFingerprint(IReadOnlyList<PersistedWfpFilter> filters) =>
        Fingerprint(string.Join('\n', filters.Select(filter => $"{filter.FilterKey}\0{filter.Fingerprint}")));

    private static string Fingerprint(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static string Clean(string? value, int maxLength, string fallback)
    {
        var cleaned = new string((value ?? string.Empty)
            .Where(character => !char.IsControl(character) && !char.IsSurrogate(character) &&
                                char.GetUnicodeCategory(character) != System.Globalization.UnicodeCategory.Format)
            .ToArray())
            .Trim();
        if (cleaned.Length == 0)
        {
            return fallback;
        }

        return cleaned.Length <= maxLength ? cleaned : cleaned[..maxLength];
    }

    private void PollSafely()
    {
        try
        {
            CheckNow();
        }
        catch (ObjectDisposedException)
        {
            // A queued callback observed monitor disposal.
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            _db.LogEvent("wfp", "wfp_filter_baseline_check_failed", details: ex.Message, reason: "monitor");
        }
    }

    public void Dispose()
    {
        System.Threading.Timer? timer;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            timer = _timer;
            _timer = null;
        }

        if (timer is null)
        {
            return;
        }

        using var drained = new ManualResetEvent(false);
        if (timer.Dispose(drained))
        {
            drained.WaitOne(TimeSpan.FromSeconds(5));
        }
    }
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Supplies the effective per-user WinINET and machine WinHTTP proxy/PAC state.
/// Missing values must be represented with a null <see cref="ProxyConfigurationSetting.Value"/>
/// so disappearance and an explicitly empty value remain distinguishable.
/// </summary>
public interface IProxyConfigurationSnapshotSource
{
    IReadOnlyList<ProxyConfigurationSetting> Snapshot();
}

/// <summary>Adapts the Windows snapshot model into field-level service rows.</summary>
public sealed class WindowsProxyConfigurationSnapshotSource : IProxyConfigurationSnapshotSource
{
    private readonly ProxyBaselineSnapshotter _snapshotter;

    public WindowsProxyConfigurationSnapshotSource(ProxyBaselineSnapshotter? snapshotter = null) =>
        _snapshotter = snapshotter ?? new ProxyBaselineSnapshotter();

    public IReadOnlyList<ProxyConfigurationSetting> Snapshot()
    {
        var settings = new List<ProxyConfigurationSetting>();
        foreach (var entry in _snapshotter.Capture().Entries)
        {
            var scope = entry.Scope == ProxyStateScope.WinInetUser ? "WinINET" : "WinHTTP";
            var state = entry.Settings;
            settings.Add(new(scope, entry.Identity, "ProxyEnable", state.ProxyEnabled ? "on" : "off"));
            settings.Add(new(scope, entry.Identity, "ProxyServer", state.ProxyServer));
            settings.Add(new(scope, entry.Identity, "ProxyBypass", state.ProxyBypass));
            settings.Add(new(scope, entry.Identity, "AutoConfigEnabled", state.AutoConfigEnabled ? "on" : "off"));
            settings.Add(new(scope, entry.Identity, "AutoConfigURL", state.AutoConfigUrl));
            settings.Add(new(scope, entry.Identity, "AutoDetect", state.AutoDetect ? "on" : "off"));
            settings.Add(new(scope, entry.Identity, "PerUserProxySettings", state.PerUserProxySettings ? "on" : "off"));
            settings.Add(new(scope, entry.Identity, "Available", state.Available ? "yes" : "no"));
            settings.Add(new(scope, entry.Identity, "CaptureStatus", state.Available ? "available" : state.Error));
            // The snapshotter computes this from unredacted state, then exposes
            // only the digest. It catches credential/query-only drift without
            // assigning that opaque change to every visible field.
            settings.Add(new(scope, entry.Identity, "ConfigurationFingerprint", state.Fingerprint));
        }

        return settings;
    }
}

/// <param name="Scope">Stable source name, normally <c>wininet</c> or <c>winhttp</c>.</param>
/// <param name="Principal">User SID for WinINET, or <c>machine</c> for WinHTTP.</param>
/// <param name="Name">Stable setting name such as ProxyEnable, ProxyServer, or AutoConfigURL.</param>
/// <param name="Value">
/// Value to show after service-side credential/query redaction, or null when
/// the setting is absent.
/// </param>
/// <param name="Fingerprint">
/// Optional lowercase SHA-256 supplied by a trusted snapshotter over its raw
/// state. This detects secret-only changes without giving raw secrets to the
/// persistence layer. Test fakes may omit it and let the service hash Value.
/// </param>
public sealed record ProxyConfigurationSetting(
    string Scope,
    string Principal,
    string Name,
    string? Value,
    string? Fingerprint = null);

public sealed record ProxyBaselineChange(
    string Scope,
    string Principal,
    string Name,
    string Before,
    string After);

public sealed record ProxyBaselineCheckResult(
    bool BaselineCreated,
    bool AlertCreated,
    IReadOnlyList<ProxyBaselineChange> Changes);

public sealed record ProxyBaselineInspectionEntry(
    string Scope,
    string Principal,
    string Name,
    bool BaselinePresent,
    string BaselineValue,
    bool CurrentPresent,
    string CurrentValue,
    bool Changed);

public sealed record ProxyBaselineInspection(
    bool BaselineExists,
    DateTime CheckedAtUtc,
    IReadOnlyList<ProxyBaselineInspectionEntry> Entries)
{
    public bool Changed => Entries.Any(entry => entry.Changed);
}

/// <summary>
/// Report-only proxy/PAC drift monitor. It never writes proxy configuration.
/// The persisted baseline contains only redacted display values and SHA-256
/// fingerprints; raw proxy credentials and PAC query tokens are never stored.
/// </summary>
public sealed class ProxyBaselineMonitor : IDisposable
{
    internal const string BaselineMetaKey = "proxy_configuration_baseline_v1";
    internal const string LastAlertMetaKey = "proxy_configuration_last_alert_v1";
    private static readonly TimeSpan DefaultInterval = TimeSpan.FromMinutes(2);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IProxyConfigurationSnapshotSource _source;
    private readonly HostsDatabase _db;
    private readonly TimeSpan _interval;
    private readonly object _gate = new();
    private System.Threading.Timer? _timer;
    private bool _disposed;

    public ProxyBaselineMonitor(
        IProxyConfigurationSnapshotSource source,
        HostsDatabase db,
        TimeSpan? interval = null)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _interval = interval ?? DefaultInterval;
        if (_interval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(interval));
        }
    }

    /// <summary>Starts immediate and periodic checks. Safe to call more than once.</summary>
    public void Start()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _timer ??= new System.Threading.Timer(_ => PollSafely(), null, TimeSpan.Zero, _interval);
        }
    }

    /// <summary>
    /// Captures current state and compares it with the explicitly accepted baseline.
    /// Repeated checks of an unchanged drift create no additional alert.
    /// </summary>
    public ProxyBaselineCheckResult CheckNow()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var current = Normalize(_source.Snapshot());
            var stored = ReadBaseline();
            if (stored is null)
            {
                WriteBaseline(current);
                _db.SetMeta(LastAlertMetaKey, string.Empty);
                _db.LogEvent("proxy", "proxy_baseline_seeded", details: $"{current.Count} setting(s)", reason: "baseline");
                return new ProxyBaselineCheckResult(true, false, Array.Empty<ProxyBaselineChange>());
            }

            var changes = Diff(stored, current);
            if (changes.Count == 0)
            {
                _db.SetMeta(LastAlertMetaKey, string.Empty);
                return new ProxyBaselineCheckResult(false, false, changes);
            }

            var driftFingerprint = SnapshotFingerprint(current);
            if (string.Equals(_db.GetMeta(LastAlertMetaKey), driftFingerprint, StringComparison.Ordinal))
            {
                return new ProxyBaselineCheckResult(false, false, changes);
            }

            var details = FormatChanges(changes);
            _db.LogEvent("proxy", "proxy_baseline_changed", details: details, reason: "tamper");
            _db.AddAlert(
                "proxy_tamper",
                "warning",
                "System proxy configuration changed",
                "WinINET / WinHTTP proxy and PAC",
                details,
                action: "proxy_baseline_changed");
            _db.SetMeta(LastAlertMetaKey, driftFingerprint);
            return new ProxyBaselineCheckResult(false, true, changes);
        }
    }

    /// <summary>
    /// Side-effect-free comparison for diagnostics/UI refresh. It neither
    /// seeds a missing baseline nor creates alerts or event-log entries.
    /// </summary>
    public ProxyBaselineInspection Inspect()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var current = Normalize(_source.Snapshot());
            var baseline = ReadBaseline();
            var before = (baseline ?? Array.Empty<PersistedProxySetting>()).ToDictionary(Key, StringComparer.Ordinal);
            var after = current.ToDictionary(Key, StringComparer.Ordinal);
            var keys = before.Keys.Concat(after.Keys).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal);
            var entries = new List<ProxyBaselineInspectionEntry>();
            foreach (var key in keys)
            {
                before.TryGetValue(key, out var oldSetting);
                after.TryGetValue(key, out var newSetting);
                var identity = newSetting ?? oldSetting!;
                entries.Add(new ProxyBaselineInspectionEntry(
                    identity.Scope,
                    identity.Principal,
                    identity.Name,
                    oldSetting is not null && oldSetting.DisplayValue != "<absent>",
                    oldSetting?.DisplayValue ?? "<not captured>",
                    newSetting is not null && newSetting.DisplayValue != "<absent>",
                    newSetting?.DisplayValue ?? "<not captured>",
                    baseline is not null && oldSetting?.Fingerprint != newSetting?.Fingerprint));
            }

            return new ProxyBaselineInspection(baseline is not null, DateTime.UtcNow, entries);
        }
    }

    /// <summary>
    /// Explicitly accepts the live configuration as the new baseline. This is
    /// the only operation that advances a seeded baseline.
    /// </summary>
    public int AcceptCurrent()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var current = Normalize(_source.Snapshot());
            WriteBaseline(current);
            _db.SetMeta(LastAlertMetaKey, string.Empty);
            _db.LogEvent("proxy", "proxy_baseline_accepted", details: $"{current.Count} setting(s)", reason: "user");
            return current.Count;
        }
    }

    internal static IReadOnlyList<ProxyBaselineChange> Diff(
        IReadOnlyList<PersistedProxySetting> baseline,
        IReadOnlyList<PersistedProxySetting> current)
    {
        var before = baseline.ToDictionary(Key, StringComparer.Ordinal);
        var after = current.ToDictionary(Key, StringComparer.Ordinal);
        var keys = before.Keys.Concat(after.Keys).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal);
        var changes = new List<ProxyBaselineChange>();
        foreach (var key in keys)
        {
            before.TryGetValue(key, out var oldSetting);
            after.TryGetValue(key, out var newSetting);
            if (oldSetting?.Fingerprint == newSetting?.Fingerprint)
            {
                continue;
            }

            var identity = newSetting ?? oldSetting!;
            changes.Add(new ProxyBaselineChange(
                identity.Scope,
                identity.Principal,
                identity.Name,
                oldSetting?.DisplayValue ?? "<not captured>",
                newSetting?.DisplayValue ?? "<not captured>"));
        }

        return changes;
    }

    internal static IReadOnlyList<PersistedProxySetting> Normalize(
        IReadOnlyList<ProxyConfigurationSetting> settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return settings
            .Select(setting =>
            {
                ArgumentNullException.ThrowIfNull(setting);
                var scope = RequiredIdentity(setting.Scope, nameof(setting.Scope));
                var principal = RequiredIdentity(setting.Principal, nameof(setting.Principal));
                var name = RequiredIdentity(setting.Name, nameof(setting.Name));
                var raw = setting.Value;
                var fingerprint = setting.Fingerprint is null
                    ? Fingerprint(raw)
                    : ValidateFingerprint(setting.Fingerprint);
                return new PersistedProxySetting(
                    scope,
                    principal,
                    name,
                    fingerprint,
                    SafeDisplay(raw));
            })
            .OrderBy(Key, StringComparer.Ordinal)
            .GroupBy(Key, StringComparer.Ordinal)
            .Select(group => group.Single())
            .ToArray();
    }

    private static string RequiredIdentity(string value, string parameter) =>
        string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("Proxy snapshot identities cannot be blank.", parameter)
            : value.Trim();

    private static string Fingerprint(string? value)
    {
        var bytes = Encoding.UTF8.GetBytes(value is null ? "\0absent" : "\0present" + value);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static string ValidateFingerprint(string value)
    {
        if (value.Length != 64 || value.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new ArgumentException("Proxy snapshot fingerprints must be lowercase SHA-256 hex.", nameof(value));
        }

        return value;
    }

    private static string SafeDisplay(string? raw)
    {
        if (raw is null)
        {
            return "<absent>";
        }

        if (raw.Length == 0)
        {
            return "<empty>";
        }

        var parts = raw.Split(';', StringSplitOptions.TrimEntries);
        for (var i = 0; i < parts.Length; i++)
        {
            var prefix = string.Empty;
            var candidate = parts[i];
            var equals = candidate.IndexOf('=');
            var scheme = candidate.IndexOf("://", StringComparison.Ordinal);
            if (equals > 0 && (scheme < 0 || equals < scheme))
            {
                prefix = candidate[..(equals + 1)];
                candidate = candidate[(equals + 1)..];
            }

            var secretDelimiter = candidate.IndexOfAny(['?', '#']);
            if (secretDelimiter >= 0)
            {
                candidate = candidate[..secretDelimiter];
            }

            if (Uri.TryCreate(candidate, UriKind.Absolute, out var uri))
            {
                var builder = new UriBuilder(uri) { UserName = string.Empty, Password = string.Empty, Query = string.Empty, Fragment = string.Empty };
                parts[i] = prefix + builder.Uri.GetLeftPart(UriPartial.Path);
            }
            else if (candidate.Contains('@', StringComparison.Ordinal))
            {
                parts[i] = prefix + "<credentials-redacted>@" + candidate[(candidate.LastIndexOf('@') + 1)..];
            }
        }

        var display = string.Join(';', parts);
        return display.Length <= 512 ? display : display[..509] + "...";
    }

    private IReadOnlyList<PersistedProxySetting>? ReadBaseline()
    {
        var json = _db.GetMeta(BaselineMetaKey);
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<PersistedProxySetting[]>(json, JsonOptions) ?? Array.Empty<PersistedProxySetting>();
        }
        catch (JsonException ex)
        {
            _db.LogEvent("proxy", "proxy_baseline_invalid", details: ex.Message, reason: "baseline");
            return null;
        }
    }

    private void WriteBaseline(IReadOnlyList<PersistedProxySetting> settings) =>
        _db.SetMeta(BaselineMetaKey, JsonSerializer.Serialize(settings, JsonOptions));

    private static string SnapshotFingerprint(IReadOnlyList<PersistedProxySetting> settings)
    {
        var canonical = string.Join('\n', settings.Select(setting => $"{Key(setting)}\0{setting.Fingerprint}"));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private static string FormatChanges(IReadOnlyList<ProxyBaselineChange> changes)
    {
        const int maxShown = 12;
        var shown = changes.Take(maxShown).Select(change =>
            $"{change.Scope}/{change.Principal}/{change.Name}: '{change.Before}' -> '{change.After}'");
        var text = string.Join("; ", shown);
        return changes.Count <= maxShown ? text : $"{text}; +{changes.Count - maxShown} more";
    }

    private static string Key(PersistedProxySetting setting) =>
        $"{setting.Scope.ToLowerInvariant()}\0{setting.Principal.ToLowerInvariant()}\0{setting.Name.ToLowerInvariant()}";

    private void PollSafely()
    {
        try
        {
            CheckNow();
        }
        catch (ObjectDisposedException)
        {
            // A callback queued just before Dispose observes the closed monitor.
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            _db.LogEvent("proxy", "proxy_baseline_check_failed", details: ex.Message, reason: "monitor");
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

        if (timer is not null)
        {
            using var drained = new ManualResetEvent(false);
            if (timer.Dispose(drained))
            {
                drained.WaitOne(TimeSpan.FromSeconds(5));
            }
        }
    }

    internal sealed record PersistedProxySetting(
        string Scope,
        string Principal,
        string Name,
        string Fingerprint,
        string DisplayValue);
}

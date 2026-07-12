using System.IO.Compression;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>Implements the Diagnostics gRPC service (health + counts).</summary>
[SupportedOSPlatform("windows")]
public sealed class DiagnosticsServiceImpl : HostsGuard.Contracts.Diagnostics.DiagnosticsBase
{
    private readonly ServiceState _state;

    public DiagnosticsServiceImpl(ServiceState state) => _state = state;

    public override Task<ServiceStatus> GetStatus(Empty request, ServerCallContext context)
    {
        var stats = _state.Db.GetStats();
        var status = new ServiceStatus
        {
            Version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0",
            Elevated = IsElevated(),
            UptimeSeconds = (long)(DateTime.UtcNow - _state.StartedAtUtc).TotalSeconds,
            HostsBlocked = _state.Hosts.GetBlocked().Count,
            HostsOverScaleThreshold = HostsEngine.IsOverScaleThreshold(_state.Hosts.GetBlocked().Count),
            DbBlocked = stats.Blocked,
            DbAllowed = stats.Whitelisted,
            FeedTotal = stats.FeedTotal,
            DnsMonitorActive = _state.DnsMonitorActive,
            ConnectionMonitorActive = _state.ConnectionMonitorActive,
            SniMonitorActive = _state.Sni is not null,
            BandwidthMonitorActive = _state.Bandwidth is not null,
            KillSwitchEngaged = _state.KillSwitch?.IsEngaged ?? false,
            SecureRulesArmed = _state.SecureRules.Enabled,
            PersistenceDroppedWrites = _state.ActivityPersistence.DroppedWriteCount,
            PersistenceWriteBatches = _state.ActivityPersistence.WriteBatchCount,
            PersistenceLargestBatch = _state.ActivityPersistence.LargestDnsBatchSize,
            PendingConsent = _state.Consent.PendingCount,
            EchUnavailable = _state.EchUnavailableSniObservations,
            SchemaVersion = HostsDatabase.SchemaVersion,
            SchemaVersionOnDisk = _state.Db.SchemaVersionOnDisk(),
            FilteringMode = _state.Consent.Mode,
            RuntimeVersion = Environment.Version.ToString(),
            SqliteVersion = _state.Db.SqliteEngineVersion(),
        };
        return Task.FromResult(status);
    }

    // ─── NET-187 SHA-256-verified self-update ────────────────────────────────

    public override async Task<UpdateStatus> GetUpdateStatus(Empty request, ServerCallContext context)
    {
        if (_state.Updater is not { } updater)
        {
            return new UpdateStatus
            {
                InstalledVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0",
                LastError = "updater unavailable (no list fetcher)",
            };
        }

        var outcome = await updater.CheckAsync(context.CancellationToken);
        var staged = updater.Staged;
        return new UpdateStatus
        {
            InstalledVersion = updater.InstalledVersion,
            LatestVersion = updater.LatestVersion,
            UpdateAvailable = outcome.UpdateAvailable,
            StagedVersion = staged?.Version ?? string.Empty,
            StagedSha256 = staged?.Sha256 ?? string.Empty,
            StagedAt = staged?.StagedAt ?? string.Empty,
            LastCheck = updater.LastCheck,
            LastError = updater.LastError,
        };
    }

    public override async Task<Ack> StageUpdate(StageUpdateRequest request, ServerCallContext context)
    {
        if (_state.GateWhenLocked() is { } locked)
        {
            return locked;
        }

        if (_state.Updater is not { } updater)
        {
            return new Ack { Ok = false, Message = "updater unavailable (no list fetcher)", ErrorCode = "hostsguard.error.v1/updater_unavailable" };
        }

        var localPath = (request.LocalPath ?? string.Empty).Trim();
        var outcome = localPath.Length != 0
            ? updater.StageLocal(localPath, request.Sha256)
            : await updater.StageAsync(context.CancellationToken);
        return new Ack
        {
            Ok = outcome.Ok,
            Message = outcome.Message,
            ErrorCode = outcome.Ok ? string.Empty : "hostsguard.error.v1/update_stage_failed",
        };
    }

    public override Task<ProxyBaselineReport> InspectProxyBaseline(Empty request, ServerCallContext context)
    {
        if (_state.ProxyBaseline is not { } monitor)
        {
            return Task.FromResult(new ProxyBaselineReport
            {
                Message = "proxy baseline monitor unavailable",
                CheckedAt = DateTime.UtcNow.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
            });
        }

        var inspection = monitor.Inspect();
        var report = new ProxyBaselineReport
        {
            BaselineExists = inspection.BaselineExists,
            Changed = inspection.Changed,
            CheckedAt = inspection.CheckedAtUtc.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
            Message = !inspection.BaselineExists
                ? "No proxy baseline has been recorded yet."
                : inspection.Changed
                    ? "Proxy or PAC state differs from the accepted baseline."
                    : "Proxy and PAC state matches the accepted baseline.",
        };
        report.Entries.AddRange(inspection.Entries.Select(entry => new ProxyBaselineEntry
        {
            Scope = entry.Scope,
            Sid = entry.Principal == "machine" ? string.Empty : entry.Principal,
            Setting = entry.Name,
            BaselinePresent = entry.BaselinePresent,
            BaselineValue = entry.BaselineValue,
            CurrentPresent = entry.CurrentPresent,
            CurrentValue = entry.CurrentValue,
            Changed = entry.Changed,
        }));
        return Task.FromResult(report);
    }

    public override Task<Ack> AcceptProxyBaseline(Empty request, ServerCallContext context)
    {
        if (_state.GateWhenLocked() is { } locked)
        {
            return Task.FromResult(locked);
        }

        if (_state.ProxyBaseline is not { } monitor)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = "proxy baseline monitor unavailable",
                ErrorCode = "hostsguard.error.v1/proxy_monitor_unavailable",
            });
        }

        var count = monitor.AcceptCurrent();
        return Task.FromResult(new Ack
        {
            Ok = true,
            Message = $"accepted {count} WinINET/WinHTTP proxy and PAC setting(s) as the new baseline",
        });
    }

    /// <summary>
    /// Redacted support bundle: status, recent event log, managed-domain counts,
    /// firewall rule names, and schedules. Every text payload runs through the
    /// redaction pipeline; the session token and webhook-style secrets never
    /// have a path into the zip.
    /// </summary>
    public override Task<Ack> ExportSupportBundle(SupportBundleRequest request, ServerCallContext context)
    {
        var dir = Path.Combine(_state.DataDir, "support");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir,
            $"hostsguard_bundle_{DateTime.Now:yyyyMMdd_HHmmss}_{Guid.NewGuid().ToString("N")[..8]}.zip");

        using (var zip = ZipFile.Open(path, ZipArchiveMode.Create))
        {
            var stats = _state.Db.GetStats();
            AddEntry(zip, "status.json", JsonSerializer.Serialize(new
            {
                version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(),
                elevated = IsElevated(),
                uptime_seconds = (long)(DateTime.UtcNow - _state.StartedAtUtc).TotalSeconds,
                hosts_blocked = _state.Hosts.GetBlocked().Count,
                db_blocked = stats.Blocked,
                db_allowed = stats.Whitelisted,
                feed_total = stats.FeedTotal,
            }, new JsonSerializerOptions { WriteIndented = true }));

            var log = _state.Db.GetLog(500)
                .Select(l => $"{l.Ts}\t{l.Action}\t{Redaction.RedactText(l.Domain)}\t{Redaction.RedactText(l.Details)}");
            AddEntry(zip, "events.log", string.Join('\n', log));

            var rules = (_state.Firewall?.ListRules() ?? Array.Empty<FwRule>())
                .Select(r => $"{r.Name}\t{r.Direction}\t{r.Action}\t{(r.Enabled ? "on" : "off")}\t{Redaction.RedactText(r.RemoteAddr)}");
            AddEntry(zip, "firewall_rules.tsv", string.Join('\n', rules));

            var schedules = _state.Db.GetSchedules()
                .Select(s => $"{Redaction.RedactText(s.Target)}\tdays={s.Days}\t{s.Start}-{s.End}");
            AddEntry(zip, "schedules.tsv", string.Join('\n', schedules));

            // NET-063 local-only metrics: event counts grouped by the canonical
            // taxonomy + the consent surface (mode/posture). Counts + booleans
            // only — no domains, IPs, or secrets.
            AddEntry(zip, "diagnostics.json", BuildDiagnostics());

            // Consent decision history (counts + redacted app/remote).
            var decisions = _state.Db.GetLog(500)
                .Where(l => l.Action.StartsWith("consent_", StringComparison.Ordinal))
                .Select(l => $"{l.Ts}\t{l.Action}\t{Redaction.RedactText(l.Domain)}\t{Redaction.RedactText(l.Details)}");
            AddEntry(zip, "consent_decisions.tsv", string.Join('\n', decisions));

            // NET-176 protocol-aware metadata profile for Wireshark handoff and
            // support triage. This is deliberately not PCAP; all endpoint,
            // domain, URL, secret, and path-like text is redacted before write.
            var trafficProfile = TrafficProfileExporter.BuildBundle(_state, request, DateTime.Now);
            AddEntry(zip, "traffic_profile_manifest.json", trafficProfile.Manifest);
            AddEntry(zip, "traffic_profile.json", trafficProfile.Json);
            AddEntry(zip, "traffic_profile.csv", trafficProfile.Csv);
        }

        _state.Db.LogEvent("support", "bundle_export", details: Path.GetFileName(path));
        return Task.FromResult(new Ack { Ok = true, Message = path });
    }

    /// <summary>
    /// Local-only metrics: recent-event counts by taxonomy category and action,
    /// plus the consent mode/posture snapshot. Counts and booleans only — safe
    /// to include verbatim (no domains, IPs, tokens, or secrets).
    /// </summary>
    private string BuildDiagnostics()
    {
        var recent = _state.Db.GetLog(2000);
        var byCategory = recent.GroupBy(l => EventTaxonomy.Category(l.Action))
            .ToDictionary(g => g.Key, g => g.Count());
        var byAction = recent.GroupBy(l => l.Action)
            .OrderByDescending(g => g.Count())
            .Take(30)
            .ToDictionary(g => g.Key, g => g.Count());

        string posture = "unavailable";
        try
        {
            if (_state.Firewall is { } fw)
            {
                posture = string.Join(", ", fw.GetPosture().Select(p => $"{p.Name}={(p.OutboundBlock ? "block" : "allow")}"));
            }
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            // Posture read failed — leave "unavailable".
        }

        return JsonSerializer.Serialize(new
        {
            generated = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
            app_version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(),
            runtime_version = Environment.Version.ToString(),
            sqlite_version = _state.Db.SqliteEngineVersion(),
            filtering_mode = _state.Consent.Mode,
            detection_armed = _state.Consent.DetectionArmed,
            default_outbound = posture,
            temp_allows_pending = _state.TempAllows.Pending().Count,
            events_window = recent.Count,
            events_by_category = byCategory,
            events_by_action_top = byAction,

            // NET-169 runtime health: monitor liveness, silent-drop counters, and
            // schema drift — the signals a support engineer cannot otherwise see.
            health = new
            {
                dns_monitor_active = _state.DnsMonitorActive,
                connection_monitor_active = _state.ConnectionMonitorActive,
                sni_monitor_active = _state.Sni is not null,
                bandwidth_monitor_active = _state.Bandwidth is not null,
                secure_rules_armed = _state.SecureRules.Enabled,
                kill_switch_engaged = _state.KillSwitch?.IsEngaged ?? false,
                pending_consent = _state.Consent.PendingCount,
                ech_unavailable = _state.EchUnavailableSniObservations,
                persistence_dropped_writes = _state.ActivityPersistence.DroppedWriteCount,
                persistence_write_batches = _state.ActivityPersistence.WriteBatchCount,
                persistence_largest_batch = _state.ActivityPersistence.LargestDnsBatchSize,
                schema_version = HostsDatabase.SchemaVersion,
                schema_version_on_disk = _state.Db.SchemaVersionOnDisk(),
            },
        }, new JsonSerializerOptions { WriteIndented = true });
    }

    private static void AddEntry(ZipArchive zip, string name, string content)
    {
        var entry = zip.CreateEntry(name);
        using var writer = new StreamWriter(entry.Open());
        writer.Write(content);
    }

    public override Task<DefenderStatus> GetDefenderStatus(Empty request, ServerCallContext context)
    {
        var status = new DefenderStatus
        {
            Guidance = Core.BlockedServices.TelemetryDefenderNote,
        };
        if (_state.Defender is { } defender && defender.IsAvailable())
        {
            status.Available = true;
            status.HostsExcluded = defender.GetExclusionPaths()
                .Any(p => string.Equals(p.TrimEnd('\\'), _state.Hosts.HostsPath, StringComparison.OrdinalIgnoreCase));
        }

        // Revert heuristic: the DB expects blocked domains but the live hosts
        // file has none — the classic post-remediation signature.
        status.PossibleRevert = _state.Hosts.GetBlocked().Count == 0 && _state.Db.GetStats().Blocked > 0;
        return Task.FromResult(status);
    }

    private static bool IsElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }
}

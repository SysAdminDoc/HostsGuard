using System.IO.Compression;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;

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
            DbBlocked = stats.Blocked,
            DbAllowed = stats.Whitelisted,
            FeedTotal = stats.FeedTotal,
            DnsMonitorActive = false,
            ConnectionMonitorActive = false,
        };
        return Task.FromResult(status);
    }

    /// <summary>
    /// Redacted support bundle: status, recent event log, managed-domain counts,
    /// firewall rule names, and schedules. Every text payload runs through the
    /// redaction pipeline; the session token and webhook-style secrets never
    /// have a path into the zip.
    /// </summary>
    public override Task<Ack> ExportSupportBundle(Empty request, ServerCallContext context)
    {
        var dir = Path.Combine(_state.DataDir, "support");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir,
            $"hostsguard_bundle_{DateTime.Now:yyyyMMdd_HHmmss}.zip");

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
            filtering_mode = _state.Consent.Mode,
            detection_armed = _state.Consent.DetectionArmed,
            default_outbound = posture,
            temp_allows_pending = _state.TempAllows.Pending().Count,
            events_window = recent.Count,
            events_by_category = byCategory,
            events_by_action_top = byAction,
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

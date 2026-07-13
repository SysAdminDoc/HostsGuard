using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;

namespace HostsGuard.Service;

/// <summary>
/// Server-streaming live feeds plus the persistent connection-history and
/// per-app bandwidth queries (NET-070). Each watcher subscribes to the
/// in-process EventBus; the stream ends when the client disconnects. The
/// engines (ETW DNS, connection monitor, temp-allow scheduler) publish onto
/// the bus.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class MonitoringServiceImpl : Monitoring.MonitoringBase
{
    private readonly ServiceState _state;

    public MonitoringServiceImpl(ServiceState state) => _state = state;

    public override Task WatchDns(Empty request, IServerStreamWriter<DnsEvent> responseStream, ServerCallContext context)
        => Pump(responseStream, context);

    public override Task WatchConnections(Empty request, IServerStreamWriter<ConnectionEvent> responseStream, ServerCallContext context)
        => Pump(responseStream, context);

    public override Task WatchEvents(Empty request, IServerStreamWriter<ActivityEvent> responseStream, ServerCallContext context)
        => Pump(responseStream, context);

    public override Task<Ack> ClearConnectionHistory(Empty request, ServerCallContext context)
    {
        var deleted = _state.Db.ClearConnectionHistory();
        _state.Db.LogEvent("connection_history", "history_cleared", process: "monitoring",
            details: $"deleted {deleted} connection history row{(deleted == 1 ? string.Empty : "s")}");
        return Task.FromResult(new Ack
        {
            Ok = true,
            Message = $"cleared {deleted} connection history row{(deleted == 1 ? string.Empty : "s")}",
        });
    }

    public override Task<ConnectionHistoryList> GetConnectionHistory(ConnectionHistoryRequest request, ServerCallContext context)
    {
        var limit = Math.Clamp(request.Limit > 0 ? request.Limit : 500, 1, 2000);
        var offset = Math.Max(0, request.Offset);
        var page = _state.Db.GetConnectionHistoryPage(new ConnectionHistoryFilter(
            Limit: limit,
            Offset: offset,
            Search: Clean(request.Search),
            Since: Clean(request.Since),
            Until: Clean(request.Until),
            Process: Clean(request.Process),
            Host: Clean(request.Host),
            RemoteAddr: Clean(request.RemoteAddr),
            FwStatus: Clean(request.FwStatus),
            Protocol: Clean(request.Protocol)));
        var list = new ConnectionHistoryList
        {
            Total = page.Total,
            Limit = page.Limit,
            Offset = page.Offset,
            RetentionDays = _state.Db.HistoryRetentionDays,
        };
        foreach (var r in page.Rows)
        {
            list.Rows.Add(new ConnectionHistoryRow
            {
                Ts = r.Ts,
                Process = r.Process,
                Pid = (int)r.Pid,
                Protocol = r.Protocol,
                RemoteAddr = r.RemoteAddr,
                RemotePort = (int)r.RemotePort,
                Country = r.Country,
                FwStatus = r.FwStatus,
                Host = r.Host,
                Asn = r.Asn,
            });
        }

        return Task.FromResult(list);
    }

    public override Task<EventLogList> ListEvents(EventLogRequest request, ServerCallContext context)
    {
        var limit = Math.Clamp(request.Limit > 0 ? request.Limit : 200, 1, 2000);
        var offset = Math.Max(0, request.Offset);
        var page = _state.Db.GetEvents(new EventLogFilter(
            Limit: limit,
            Offset: offset,
            Search: Clean(request.Search),
            Since: Clean(request.Since),
            Until: Clean(request.Until),
            Action: Clean(request.Action),
            Reason: Clean(request.Reason),
            Domain: Clean(request.Domain),
            Process: Clean(request.Process),
            Category: Clean(request.Category)));

        var list = new EventLogList
        {
            Limit = limit,
            Offset = offset,
            Total = page.Total,
            Redacted = request.Redact,
        };
        foreach (var row in page.Rows)
        {
            list.Entries.Add(new EventLogEntry
            {
                Id = row.Id,
                Ts = row.Ts,
                Domain = request.Redact ? Redaction.RedactText(row.Domain) : row.Domain,
                Action = row.Action,
                Process = request.Redact ? Redaction.RedactScalar("program", row.Process) : row.Process,
                Details = request.Redact ? Redaction.RedactText(row.Details) : row.Details,
                Reason = row.Reason,
                Category = row.Category,
            });
        }

        return Task.FromResult(list);
    }

    public override Task<ListenerExposureList> ListListeners(Empty request, ServerCallContext context)
    {
        var snapshot = _state.ConnectionSnapshot();
        var listeners = snapshot
            .Where(static row => row.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) ||
                row.State.Equals("LISTEN", StringComparison.OrdinalIgnoreCase))
            .Select(static row => new ListenerEndpoint(
                row.Protocol, row.LocalAddress, row.LocalPort, row.Pid, row.Process))
            .ToArray();
        var owners = snapshot
            .Where(static row => row.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) ||
                row.State.Equals("LISTEN", StringComparison.OrdinalIgnoreCase))
            .GroupBy(static row => row.Pid)
            .Select(group =>
            {
                var row = group.First();
                var service = _state.LookupSoleService?.Invoke(row.Pid);
                return new ListenerOwnerAttribution(
                    row.Pid,
                    row.ProcessPath,
                    service?.Key ?? string.Empty,
                    service?.Display ?? (_state.LookupService?.Invoke(row.Pid) ?? string.Empty),
                    row.PackageFamilyName);
            })
            .ToArray();
        var rules = _state.Firewall?.ListRules() ?? Array.Empty<FwRule>();
        var profiles = _state.Firewall?.GetActiveInboundProfiles() ?? Array.Empty<InboundFirewallProfile>();
        var analyzed = ListenerExposureAnalyzer.Analyze(listeners, owners, rules, profiles);

        var response = new ListenerExposureList();
        foreach (var exposure in analyzed)
        {
            response.Listeners.Add(new Contracts.ListenerExposure
            {
                Protocol = exposure.Endpoint.Protocol,
                LocalAddress = exposure.Endpoint.LocalAddress,
                LocalPort = exposure.Endpoint.LocalPort,
                Process = exposure.Endpoint.ProcessName,
                Pid = exposure.Endpoint.Pid,
                Service = exposure.Owner.ServiceDisplayName.Length != 0
                    ? exposure.Owner.ServiceDisplayName
                    : exposure.Owner.ServiceName,
                Package = exposure.Owner.PackageFamilyName,
                BindScope = exposure.BindScope.ToString().ToLowerInvariant(),
                ActiveProfiles = string.Join(',', exposure.Profiles.Select(static profile => profile.Profile)),
                Coverage = FormatListenerCoverage(exposure.Profiles),
                Risk = ListenerRisk(exposure),
                Reason = ListenerReason(exposure, profiles.Count),
            });
        }

        return Task.FromResult(response);
    }

    private static string FormatListenerCoverage(IReadOnlyList<ListenerProfileExposure> profiles)
        => profiles.Count == 0
            ? "unknown"
            : string.Join(", ", profiles.Select(static profile =>
                $"{profile.Profile}:{profile.Action.ToString().ToLowerInvariant()}"));

    private static string ListenerRisk(ListenerExposureAssessment exposure)
    {
        if (!exposure.NeedsAttention)
        {
            return "low";
        }

        return exposure.Profiles.Any(static profile => profile.Action is
                ListenerInboundAction.AllowRule or
                ListenerInboundAction.FirewallDisabled or
                ListenerInboundAction.DefaultAllow or
                ListenerInboundAction.RestrictedAllow or
                ListenerInboundAction.RestrictedMixed ||
            !profile.DefaultInboundBlock && profile.Action is
                ListenerInboundAction.ProfileMismatch or ListenerInboundAction.RestrictedBlock)
            ? "high"
            : "medium";
    }

    private static string ListenerReason(ListenerExposureAssessment exposure, int activeProfileCount)
    {
        if (activeProfileCount == 0)
        {
            return exposure.PublicBound
                ? "Public or wildcard bind; active firewall profile coverage is unavailable."
                : "Local bind; active firewall profile coverage is unavailable.";
        }

        return exposure.Finding switch
        {
            "local_bind" => "Bound to a local-only address; effective inbound policy is shown per active profile.",
            "public_bound_profile_mismatch" => "Public or wildcard bind has rules, but none apply to an active profile.",
            "public_bound_unruled" => "Public or wildcard bind has no matching inbound rule; profile defaults apply.",
            "public_bound_firewall_disabled" => "Public or wildcard bind is on an active profile with Windows Firewall disabled.",
            "public_bound_permitted_locally" => "Public or wildcard bind is permitted by a matching rule or profile default.",
            "public_bound_blocked_locally" => "Public or wildcard bind is blocked by effective local firewall policy.",
            _ => exposure.Finding,
        };
    }

    public override Task<AlertList> ListAlerts(AlertRequest request, ServerCallContext context)
    {
        var limit = Math.Clamp(request.Limit > 0 ? request.Limit : 200, 1, 2000);
        var offset = Math.Max(0, request.Offset);
        var page = _state.Db.GetAlerts(new AlertFilter(
            Limit: limit,
            Offset: offset,
            IncludeRead: request.IncludeRead,
            SurfaceOnly: !request.IncludeLogOnly,
            Type: Clean(request.Type)));

        var list = new AlertList
        {
            Total = page.Total,
            Unread = page.Unread,
        };
        foreach (var row in page.Rows)
        {
            var entry = new AlertEntry
            {
                Id = row.Id,
                Created = row.Created,
                Updated = row.Updated,
                Type = row.Type,
                Severity = row.Severity,
                Title = row.Title,
                Subject = row.Subject,
                Details = row.Details,
                Action = row.Action,
                Process = row.Process,
                IsRead = row.IsRead,
                Surfaced = row.Surfaced,
            };
            if (row.Type.Equals("suspicious_domain", StringComparison.Ordinal))
            {
                entry.DgaEvidence = ToDgaEvidence(Core.DgaHeuristic.Analyze(row.Subject));
            }

            list.Entries.Add(entry);
        }

        return Task.FromResult(list);
    }

    internal static DgaEvidence ToDgaEvidence(Core.DgaScoreBreakdown score) => new()
    {
        Version = score.Version,
        RegistrableLabel = score.RegistrableLabel,
        LabelLength = score.LabelLength,
        Entropy = score.Entropy,
        EntropyThreshold = score.EntropyThreshold,
        VowelRatio = score.VowelRatio,
        VowelRatioThreshold = score.VowelRatioThreshold,
        DigitRatio = score.DigitRatio,
        DigitRatioThreshold = score.DigitRatioThreshold,
        MaxConsonantRun = score.MaxConsonantRun,
        ConsonantRunThreshold = score.ConsonantRunThreshold,
        Score = score.Score,
        DecisionThreshold = score.DecisionThreshold,
        IsAlgorithmic = score.IsAlgorithmic,
        Reason = score.Reason,
    };

    public override Task<Ack> AckAlert(AlertAckRequest request, ServerCallContext context)
    {
        var changed = _state.Db.AckAlerts(request.Ids, request.All, Clean(request.Type));
        return Task.FromResult(new Ack { Ok = true, Message = $"acknowledged {changed} alert{(changed == 1 ? string.Empty : "s")}" });
    }

    public override Task<AlertTypeList> ListAlertTypes(Empty request, ServerCallContext context)
    {
        var list = new AlertTypeList();
        foreach (var row in _state.Db.GetAlertTypes())
        {
            list.Types_.Add(new AlertTypeEntry
            {
                Type = row.Type,
                Label = row.Label,
                Surface = row.Surface,
                Unread = row.Unread,
            });
        }

        return Task.FromResult(list);
    }

    public override Task<Ack> SetAlertType(AlertTypeRequest request, ServerCallContext context)
    {
        var type = Clean(request.Type);
        if (type is null)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = "alert type is required",
                ErrorCode = "hostsguard.error.v1/invalid_alert_type",
            });
        }

        _state.Db.SetAlertTypeSurface(type, request.Surface);
        return Task.FromResult(new Ack
        {
            Ok = true,
            Message = request.Surface ? $"{type} alerts will surface" : $"{type} alerts are log-only",
        });
    }

    public override Task<AppBandwidthList> GetAppBandwidth(BandwidthRequest request, ServerCallContext context)
        => Task.FromResult(BuildBandwidth(request, DateTime.Now));

    /// <summary>Aligned, zero-filled per-app series ending at <paramref name="now"/>'s minute.</summary>
    public AppBandwidthList BuildBandwidth(BandwidthRequest request, DateTime now)
    {
        var minutes = Math.Clamp(request.Minutes > 0 ? request.Minutes : 60, 5, 1440);
        var top = Math.Clamp(request.Top > 0 ? request.Top : 5, 1, 12);
        var origin = new DateTime(now.Year, now.Month, now.Day, now.Hour, now.Minute, 0, now.Kind)
            .AddMinutes(-(minutes - 1));
        var rows = _state.Db.GetBandwidth(origin.ToString("yyyy-MM-ddTHH:mm", CultureInfo.InvariantCulture));

        var perProcess = new Dictionary<string, (long[] Buckets, long Sent, long Recv)>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            if (!DateTime.TryParseExact(row.Minute, "yyyy-MM-ddTHH:mm", CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out var minute))
            {
                continue;
            }

            var slot = (int)(minute - origin).TotalMinutes;
            if (slot < 0 || slot >= minutes)
            {
                continue;
            }

            if (!perProcess.TryGetValue(row.Process, out var acc))
            {
                acc = (new long[minutes], 0, 0);
            }

            acc.Buckets[slot] += row.Sent + row.Recv;
            perProcess[row.Process] = (acc.Buckets, acc.Sent + row.Sent, acc.Recv + row.Recv);
        }

        var list = new AppBandwidthList { CountersActive = _state.Bandwidth?.CountersActive ?? false };
        foreach (var (process, acc) in perProcess
                     .OrderByDescending(kv => kv.Value.Sent + kv.Value.Recv)
                     .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                     .Take(top))
        {
            var series = new AppBandwidthSeries { Process = process, TotalSent = acc.Sent, TotalRecv = acc.Recv };
            series.Bytes.AddRange(acc.Buckets);
            list.Series.Add(series);
        }

        return list;
    }

    public override Task<HistorySettings> GetHistorySettings(Empty request, ServerCallContext context)
        => Task.FromResult(new HistorySettings { RetentionDays = _state.Db.HistoryRetentionDays });

    public override Task<HistoryPrivacyExclusionList> ListHistoryPrivacyExclusions(Empty request, ServerCallContext context)
    {
        var result = new HistoryPrivacyExclusionList
        {
            Disclosure = "Live visibility and enforcement remain active. Passive history and usage are omitted; security alerts retain only decision evidence.",
        };
        result.Exclusions.AddRange(_state.Db.GetHistoryPrivacyExclusions().Select(row => new HistoryPrivacyExclusion
        {
            Scope = row.Scope, Match = row.Match, Added = row.Added,
        }));
        return Task.FromResult(result);
    }

    public override Task<Ack> SetHistoryPrivacyExclusion(HistoryPrivacyExclusion request, ServerCallContext context)
    {
        try
        {
            _state.Db.UpsertHistoryPrivacyExclusion(request.Scope, request.Match);
            return Task.FromResult(new Ack { Ok = true, Message = $"history privacy exclusion saved for {request.Scope}:{request.Match}; prior matching history purged" });
        }
        catch (ArgumentException ex)
        {
            return Task.FromResult(new Ack { Ok = false, Message = ex.Message, ErrorCode = "hostsguard.error.v1/invalid_history_privacy_exclusion" });
        }
    }

    public override Task<Ack> DeleteHistoryPrivacyExclusion(HistoryPrivacyExclusion request, ServerCallContext context)
    {
        try
        {
            var removed = _state.Db.DeleteHistoryPrivacyExclusion(request.Scope, request.Match);
            return Task.FromResult(new Ack { Ok = removed != 0, Message = removed != 0 ? "history privacy exclusion removed" : "history privacy exclusion not found" });
        }
        catch (ArgumentException ex)
        {
            return Task.FromResult(new Ack { Ok = false, Message = ex.Message, ErrorCode = "hostsguard.error.v1/invalid_history_privacy_exclusion" });
        }
    }

    public override Task<UsageRollupList> GetUsageRollups(UsageRollupRequest request, ServerCallContext context)
        => Task.FromResult(BuildUsageRollups(request, DateTime.Now));

    public UsageRollupList BuildUsageRollups(UsageRollupRequest request, DateTime now)
    {
        var days = Math.Clamp(request.Days > 0 ? request.Days : 30, 1, 365);
        var limit = Math.Clamp(request.Limit > 0 ? request.Limit : 200, 1, 2000);
        var since = now.Date.AddDays(-(days - 1));
        var rows = _state.Db.GetUsageRollups(
            since,
            limit,
            Clean(request.Search),
            Clean(request.Process),
            Clean(request.Domain));

        var list = new UsageRollupList { RetentionDays = _state.Db.HistoryRetentionDays };
        foreach (var row in rows)
        {
            list.Entries.Add(new UsageRollupEntry
            {
                Day = row.Day,
                Process = row.Process,
                Domain = row.Domain,
                Sent = row.Sent,
                Recv = row.Recv,
                Total = row.Sent + row.Recv,
            });
        }

        return list;
    }

    public override Task<UsageQuotaRuleList> GetUsageQuotaRules(Empty request, ServerCallContext context)
        => Task.FromResult(BuildUsageQuotaRules(DateTime.Now));

    public UsageQuotaRuleList BuildUsageQuotaRules(DateTime now)
    {
        var list = new UsageQuotaRuleList();
        foreach (var row in _state.Db.GetUsageQuotaRules())
        {
            list.Rules.Add(ToContract(row, _state.Db.GetUsageBytesForQuota(row.Scope, row.Match, row.WindowDays, now)));
        }

        return list;
    }

    public override Task<Ack> SetUsageQuotaRule(UsageQuotaRule request, ServerCallContext context)
    {
        var scope = NormalizeQuotaScope(request.Scope);
        var match = Clean(request.Match);
        if (scope.Length == 0 || match is null)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = "usage quota requires scope app|domain and a non-empty match",
                ErrorCode = "hostsguard.error.v1/invalid_usage_quota",
            });
        }

        if (request.LimitBytes <= 0)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = "usage quota limit must be greater than zero bytes",
                ErrorCode = "hostsguard.error.v1/invalid_usage_quota",
            });
        }

        if (request.WindowDays is < 1 or > 365)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = "usage quota window must be 1-365 days",
                ErrorCode = "hostsguard.error.v1/invalid_usage_quota",
            });
        }

        var rule = _state.Db.UpsertUsageQuotaRule(scope, match, request.LimitBytes, request.WindowDays, request.Enabled, request.BlockOnExceed);
        if (rule.BlockedSince.Length != 0 && (!rule.Enabled || !rule.BlockOnExceed))
        {
            _state.QuotaEnforcer.ClearBlockById(rule.Id, "rule disabled or block-on-exceed turned off");
        }

        _state.Db.LogEvent(rule.Match, "usage_quota_saved", process: scope == "app" ? rule.Match : string.Empty,
            details: $"{rule.Scope} quota {FormatBytes(rule.LimitBytes)} over {rule.WindowDays} day{(rule.WindowDays == 1 ? string.Empty : "s")} ({(rule.Enabled ? "enabled" : "disabled")}{(rule.BlockOnExceed ? ", block-on-exceed" : string.Empty)})",
            reason: "usage_budget");
        return Task.FromResult(new Ack { Ok = true, Message = $"usage quota saved for {rule.Scope} {rule.Match}" });
    }

    public override Task<Ack> DeleteUsageQuotaRule(UsageQuotaRule request, ServerCallContext context)
    {
        // Lift any active enforcement block before the rule row disappears,
        // otherwise its HG_QuotaBlock_* rules / hosts entry would be orphaned.
        if (request.Id > 0)
        {
            _state.QuotaEnforcer.ClearBlockById(request.Id, "quota rule deleted");
        }
        else
        {
            var target = _state.Db.GetUsageQuotaRules().FirstOrDefault(r =>
                string.Equals(r.Scope, NormalizeQuotaScope(request.Scope), StringComparison.Ordinal) &&
                string.Equals(r.Match, Clean(request.Match), StringComparison.OrdinalIgnoreCase));
            if (target is not null)
            {
                _state.QuotaEnforcer.ClearBlockById(target.Id, "quota rule deleted");
            }
        }

        var removed = _state.Db.DeleteUsageQuotaRule(request.Id, request.Scope, request.Match);
        if (removed == 0)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = "usage quota rule not found",
                ErrorCode = "hostsguard.error.v1/not_found",
            });
        }

        _state.Db.LogEvent("usage_quota", "usage_quota_deleted", details: $"{removed} quota rule removed", reason: "usage_budget");
        return Task.FromResult(new Ack { Ok = true, Message = $"removed {removed} usage quota rule{(removed == 1 ? string.Empty : "s")}" });
    }

    public override Task<Ack> ResetUsageQuotaHistory(Empty request, ServerCallContext context)
    {
        var unblocked = _state.QuotaEnforcer.ClearAllBlocks("quota history reset");
        var changed = _state.Db.ResetUsageQuotaHistory();
        _state.Db.LogEvent("usage_quota", "usage_quota_reset",
            details: $"{changed} quota alert cursor(s) reset{(unblocked != 0 ? $", {unblocked} enforcement block(s) lifted" : string.Empty)}",
            reason: "usage_budget");
        return Task.FromResult(new Ack
        {
            Ok = true,
            Message = $"reset {changed} usage quota alert cursor{(changed == 1 ? string.Empty : "s")}"
                + (unblocked != 0 ? $"; lifted {unblocked} enforcement block{(unblocked == 1 ? string.Empty : "s")}" : string.Empty),
        });
    }

    public override Task<UsageQuotaHistoryExport> ExportUsageQuotaHistory(UsageQuotaHistoryRequest request, ServerCallContext context)
    {
        var days = Math.Clamp(request.Days > 0 ? request.Days : 30, 1, 365);
        var format = Clean(request.Format)?.ToLowerInvariant();
        if (format is not ("json" or "csv"))
        {
            format = "csv";
        }

        var since = DateTime.Now.Date.AddDays(-(days - 1));
        var rows = _state.Db.GetUsageQuotaHistory(since, request.Scope, request.Match);
        var content = format == "json" ? BuildUsageQuotaHistoryJson(rows) : BuildUsageQuotaHistoryCsv(rows);
        return Task.FromResult(new UsageQuotaHistoryExport { Format = format, Content = content });
    }

    public override Task<TrafficProfileExport> ExportTrafficProfile(TrafficProfileRequest request, ServerCallContext context)
        => Task.FromResult(TrafficProfileExporter.Build(_state, request, DateTime.Now));

    public override Task<Ack> SetHistorySettings(HistorySettings request, ServerCallContext context)
    {
        if (request.RetentionDays is < 1 or > 365)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = "retention must be 1-365 days",
                ErrorCode = "hostsguard.error.v1/invalid_argument",
            });
        }

        _state.Db.HistoryRetentionDays = request.RetentionDays;
        _state.Db.RunRetentionSweep(DateTime.Now, forceMaintenance: true);
        return Task.FromResult(new Ack { Ok = true, Message = $"history retention set to {request.RetentionDays} days" });
    }

    private static UsageQuotaRule ToContract(UsageQuotaRuleRow row, long usedBytes)
        => new()
        {
            Id = row.Id,
            Scope = row.Scope,
            Match = row.Match,
            LimitBytes = row.LimitBytes,
            WindowDays = row.WindowDays,
            Enabled = row.Enabled,
            UsedBytes = usedBytes,
            LastAlertedBytes = row.LastAlertedBytes,
            LastAlertedAt = row.LastAlertedAt,
            BlockOnExceed = row.BlockOnExceed,
            BlockActive = row.BlockedSince.Length != 0,
            BlockedSince = row.BlockedSince,
        };

    private static string BuildUsageQuotaHistoryJson(IEnumerable<UsageQuotaHistoryRow> rows)
        => JsonSerializer.Serialize(rows.Select(r => new
        {
            day = r.Day,
            scope = r.Scope,
            match = r.Match,
            sent = r.Sent,
            received = r.Recv,
            total = r.Sent + r.Recv,
        }), new JsonSerializerOptions { WriteIndented = true });

    private static string BuildUsageQuotaHistoryCsv(IEnumerable<UsageQuotaHistoryRow> rows)
    {
        var sb = new System.Text.StringBuilder();
        CsvExport.AppendRow(sb, "Day", "Scope", "Match", "Sent", "Received", "Total");
        foreach (var r in rows)
        {
            CsvExport.AppendRow(
                sb,
                r.Day,
                r.Scope,
                r.Match,
                r.Sent.ToString(CultureInfo.InvariantCulture),
                r.Recv.ToString(CultureInfo.InvariantCulture),
                (r.Sent + r.Recv).ToString(CultureInfo.InvariantCulture));
        }

        return sb.ToString();
    }

    private static string NormalizeQuotaScope(string? scope)
    {
        var clean = (scope ?? string.Empty).Trim().ToLowerInvariant();
        return clean switch
        {
            "app" or "process" => "app",
            "domain" or "host" => "domain",
            _ => string.Empty,
        };
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = Math.Max(0, bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return string.Create(CultureInfo.InvariantCulture, $"{value:0.#} {units[unit]}");
    }

    private async Task Pump<T>(IServerStreamWriter<T> stream, ServerCallContext context)
    {
        using var sub = _state.Bus.Subscribe<T>();
        try
        {
            await foreach (var item in sub.Reader.ReadAllAsync(context.CancellationToken))
            {
                await stream.WriteAsync(item, context.CancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Client went away — normal stream termination.
        }
    }

    private static string? Clean(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

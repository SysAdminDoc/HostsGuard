using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;
using HostsGuard.Core;

namespace HostsGuard.App.ViewModels;

public sealed partial class FwActivityViewModel
{
    // ─── Connection history + per-app bandwidth (NET-070) ────────────────────

    public ObservableCollection<HistoryRowViewModel> HistoryRows { get; } = new();

    public ObservableCollection<EventLogRowViewModel> EventRows { get; } = new();

    public ObservableCollection<UsageRollupRowViewModel> UsageRows { get; } = new();

    public ObservableCollection<UsageQuotaRuleViewModel> UsageQuotaRules { get; } = new();

    public ObservableCollection<HistoryPrivacyExclusion> HistoryPrivacyExclusions { get; } = new();

    public static IReadOnlyList<string> HistoryPrivacyScopes { get; } = new[] { "app", "domain" };

    [ObservableProperty] private string _historyPrivacyScope = "domain";
    [ObservableProperty] private string _historyPrivacyMatch = string.Empty;
    [ObservableProperty] private string _historyPrivacyStatus = I18n.T("HistoryPrivacy_NotLoaded", "Privacy exclusions not loaded.");

    public ObservableCollection<TimelineSeriesViewModel> Bandwidth { get; } = new();

    public static IReadOnlyList<string> EventCategories { get; } = new[]
    {
        string.Empty,
        "hosts",
        "firewall",
        "consent",
        "dns",
        "lists",
        "policy",
        "defender",
        "support",
        "other",
    };

    [ObservableProperty]
    private string _historySearch = string.Empty;

    [ObservableProperty]
    private string _historyProcess = string.Empty;

    [ObservableProperty]
    private string _historyHost = string.Empty;

    [ObservableProperty]
    private string _historyRemoteAddr = string.Empty;

    [ObservableProperty]
    private string _historyStatusFilter = string.Empty;

    [ObservableProperty]
    private string _historyProtocol = string.Empty;

    [ObservableProperty]
    private string _historySince = string.Empty;

    [ObservableProperty]
    private string _historyUntil = string.Empty;

    [ObservableProperty]
    private int _historyLimit = 500;

    [ObservableProperty]
    private int _historyOffset;

    [ObservableProperty]
    private string _historyStatus = I18n.T("FwHistory_LoadPrompt", "Click Load to show recorded connections.");

    [ObservableProperty]
    private string _eventSearch = string.Empty;

    [ObservableProperty]
    private string _eventSince = string.Empty;

    [ObservableProperty]
    private string _eventUntil = string.Empty;

    [ObservableProperty]
    private string _eventAction = string.Empty;

    [ObservableProperty]
    private string _eventReason = string.Empty;

    [ObservableProperty]
    private string _eventDomain = string.Empty;

    [ObservableProperty]
    private string _eventProcess = string.Empty;

    [ObservableProperty]
    private string _eventCategory = string.Empty;

    [ObservableProperty]
    private string _eventMatchedSource = string.Empty;

    [ObservableProperty]
    private string _eventStatus = I18n.T("FwHistory_EventLoadPrompt", "Click Load events to browse the persisted event ledger.");

    [ObservableProperty]
    private int _eventLimit = 200;

    [ObservableProperty]
    private int _eventOffset;

    [ObservableProperty]
    private string _bandwidthStatus = I18n.T("Common_NotLoaded", "Not loaded");

    [ObservableProperty]
    private string _usageSearch = string.Empty;

    [ObservableProperty]
    private string _usageProcess = string.Empty;

    [ObservableProperty]
    private string _usageDomain = string.Empty;

    [ObservableProperty]
    private int _usageDays = 30;

    [ObservableProperty]
    private int _usageLimit = 200;

    [ObservableProperty]
    private string _usageStatus = I18n.T("FwHistory_UsageLoadPrompt", "Click Load usage to show daily app/domain data.");

    [ObservableProperty]
    private string _usageQuotaScope = "app";

    [ObservableProperty]
    private string _usageQuotaMatch = string.Empty;

    [ObservableProperty]
    private string _usageQuotaLimitText = "1GB";

    [ObservableProperty]
    private int _usageQuotaWindowDays = 30;

    [ObservableProperty]
    private bool _usageQuotaEnabled = true;

    [ObservableProperty]
    private bool _usageQuotaBlockOnExceed;

    [ObservableProperty]
    private string _usageQuotaStatus = I18n.T("FwHistory_QuotaLoadPrompt", "Click Load quotas to show usage-budget alerts.");

    [ObservableProperty]
    private int _retentionDays = 30;

    [RelayCommand]
    public async Task LoadHistoryAsync()
    {
        await RunServiceActionAsync(I18n.T("FwHistory_ActionLoad", "Load connection history"), s => HistoryStatus = s, async () =>
        {
            HistoryLimit = Math.Clamp(HistoryLimit <= 0 ? 500 : HistoryLimit, 1, 2000);
            HistoryOffset = Math.Max(0, HistoryOffset);
            var history = await _client.Monitoring.GetConnectionHistoryAsync(new ConnectionHistoryRequest
            {
                Limit = HistoryLimit,
                Offset = HistoryOffset,
                Search = HistorySearch ?? string.Empty,
                Since = HistorySince ?? string.Empty,
                Until = HistoryUntil ?? string.Empty,
                Process = HistoryProcess ?? string.Empty,
                Host = HistoryHost ?? string.Empty,
                RemoteAddr = HistoryRemoteAddr ?? string.Empty,
                FwStatus = HistoryStatusFilter ?? string.Empty,
                Protocol = HistoryProtocol ?? string.Empty,
            });
            RetentionDays = history.RetentionDays > 0
                ? history.RetentionDays
                : (await _client.Monitoring.GetHistorySettingsAsync(new Empty())).RetentionDays;
            HistoryRows.Clear();
            foreach (var row in history.Rows)
            {
                HistoryRows.Add(new HistoryRowViewModel
                {
                    Ts = row.Ts,
                    Process = row.Process,
                    Pid = row.Pid,
                    Protocol = row.Protocol,
                    RemoteAddr = row.RemoteAddr,
                    Host = row.Host,
                    RemotePort = row.RemotePort,
                    Country = row.Country,
                    Asn = row.Asn,
                    FwStatus = row.FwStatus,
                });
            }

            var shownConnections = HistoryRows.Count == 1
                ? I18n.T("FwHistory_RecordedConnectionCount", "{0} recorded connection", HistoryRows.Count)
                : I18n.T("FwHistory_RecordedConnectionCountPlural", "{0} recorded connections", HistoryRows.Count);
            var matches = history.Total == 1
                ? I18n.T("Common_MatchCount", "{0} match", history.Total)
                : I18n.T("Common_MatchCountPlural", "{0} matches", history.Total);
            var retainedDays = RetentionDays == 1
                ? I18n.T("Common_DayCount", "{0} day", RetentionDays)
                : I18n.T("Common_DayCountPlural", "{0} days", RetentionDays);
            HistoryStatus = I18n.T("FwHistory_CountStatus", "{0} shown of {1} · offset {2} · retained {3}",
                shownConnections, matches, history.Offset, retainedDays);
            await LoadBandwidthAsync();
            await LoadUsageAsync();
            await LoadUsageQuotasAsync();
        });
    }

    [RelayCommand]
    public async Task PreviousHistoryPageAsync()
    {
        HistoryOffset = Math.Max(0, HistoryOffset - Math.Max(1, HistoryLimit));
        await LoadHistoryAsync();
    }

    [RelayCommand]
    public async Task NextHistoryPageAsync()
    {
        HistoryOffset += Math.Max(1, HistoryLimit);
        await LoadHistoryAsync();
    }

    [RelayCommand]
    public async Task LoadEventsAsync()
    {
        await RunServiceActionAsync(I18n.T("FwHistory_ActionLoadEvents", "Load event log"), s => EventStatus = s, async () =>
        {
            var limit = Math.Clamp(EventLimit <= 0 ? 200 : EventLimit, 1, 2000);
            EventLimit = limit;
            EventOffset = Math.Max(0, EventOffset);
            var events = await _client.Monitoring.ListEventsAsync(new EventLogRequest
            {
                Limit = limit,
                Offset = EventOffset,
                Search = EventSearch ?? string.Empty,
                Since = EventSince ?? string.Empty,
                Until = EventUntil ?? string.Empty,
                Action = EventAction ?? string.Empty,
                Reason = EventReason ?? string.Empty,
                Domain = EventDomain ?? string.Empty,
                Process = EventProcess ?? string.Empty,
                Category = EventCategory ?? string.Empty,
                MatchedSource = EventMatchedSource ?? string.Empty,
            });
            EventRows.Clear();
            foreach (var row in events.Entries)
            {
                EventRows.Add(new EventLogRowViewModel
                {
                    Ts = row.Ts,
                    Category = row.Category,
                    Action = row.Action,
                    Reason = row.Reason,
                    Domain = row.Domain,
                    Process = row.Process,
                    Details = row.Details,
                    MatchedSource = row.MatchedSource,
                });
            }

            var shownEvents = EventRows.Count == 1
                ? I18n.T("Common_EventCount", "{0} event", EventRows.Count)
                : I18n.T("Common_EventCountPlural", "{0} events", EventRows.Count);
            var matches = events.Total == 1
                ? I18n.T("Common_MatchCount", "{0} match", events.Total)
                : I18n.T("Common_MatchCountPlural", "{0} matches", events.Total);
            EventStatus = I18n.T("FwHistory_EventCountStatus", "{0} shown of {1} · offset {2}", shownEvents, matches, events.Offset);
        });
    }

    [RelayCommand]
    public async Task PreviousEventsPageAsync()
    {
        EventOffset = Math.Max(0, EventOffset - Math.Max(1, EventLimit));
        await LoadEventsAsync();
    }

    [RelayCommand]
    public async Task NextEventsPageAsync()
    {
        EventOffset += Math.Max(1, EventLimit);
        await LoadEventsAsync();
    }

    [RelayCommand]
    public async Task SaveRetentionAsync()
    {
        await RunServiceActionAsync(I18n.T("FwHistory_ActionSaveRetention", "Save history retention"), s => HistoryStatus = s, async () =>
        {
            var ack = await _client.Monitoring.SetHistorySettingsAsync(new HistorySettings { RetentionDays = RetentionDays });
            HistoryStatus = ack.Message;
        });
    }

    [RelayCommand]
    public async Task ClearHistoryAsync()
    {
        if (!_confirm.Confirm(I18n.T("FwHistory_ClearTitle", "Clear connection history"),
            I18n.T("FwHistory_ClearMessage", "Delete all retained connection-history rows? Event logs, hosts blocks, and firewall rules are unchanged.")))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("FwHistory_ActionClear", "Clear connection history"), s => HistoryStatus = s, async () =>
        {
            var ack = await _client.Monitoring.ClearConnectionHistoryAsync(new Empty());
            HistoryRows.Clear();
            HistoryOffset = 0;
            HistoryStatus = ack.Message;
        });
    }

    /// <summary>Export the loaded connection history to a CSV file (NET-091/168).</summary>
    [RelayCommand]
    public async Task ExportHistoryCsvAsync()
    {
        if (_filePicker is null)
        {
            return;
        }

        if (HistoryRows.Count == 0)
        {
            HistoryStatus = I18n.T("FwHistory_ExportRequiresLoad", "Load history first — nothing to export.");
            return;
        }

        var path = _filePicker.SaveFile(I18n.T("FwHistory_ExportCsvTitle", "Export connection history (CSV)"), "connection_history.csv",
            I18n.T("FileFilter_Csv", "CSV files ({0})|{0}", "*.csv"));
        if (string.IsNullOrEmpty(path))
        {
            return;
        }

        try
        {
            await System.IO.File.WriteAllTextAsync(path, BuildHistoryCsv(HistoryRows));
            HistoryStatus = HistoryRows.Count == 1
                ? I18n.T("FwHistory_ExportedCsv", "Exported {0} connection to {1}", HistoryRows.Count, System.IO.Path.GetFileName(path))
                : I18n.T("FwHistory_ExportedCsvPlural", "Exported {0} connections to {1}", HistoryRows.Count, System.IO.Path.GetFileName(path));
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException)
        {
            HistoryStatus = I18n.T("Common_ExportFailed", "Export failed: {0}", ex.Message);
        }
    }

    /// <summary>Export a redacted metadata-only traffic profile for diagnostics/Wireshark handoff.</summary>
    [RelayCommand]
    public async Task ExportTrafficProfileAsync()
    {
        if (_filePicker is null)
        {
            return;
        }

        var path = _filePicker.SaveFile(I18n.T("FwHistory_ExportProfileTitle", "Export traffic profile"), "traffic_profile.json",
            I18n.T("FileFilter_JsonCsv", "JSON files ({0})|{0}|CSV files ({1})|{1}", "*.json", "*.csv"));
        if (string.IsNullOrEmpty(path))
        {
            return;
        }

        var format = System.IO.Path.GetExtension(path).Equals(".csv", StringComparison.OrdinalIgnoreCase)
            ? "csv"
            : "json";
        await RunServiceActionAsync(I18n.T("FwHistory_ActionExportProfile", "Export traffic profile"), s => HistoryStatus = s, async () =>
        {
            var profile = await _client.Monitoring.ExportTrafficProfileAsync(new TrafficProfileRequest
            {
                Since = HistorySince ?? string.Empty,
                Until = HistoryUntil ?? string.Empty,
                Process = HistoryProcess ?? string.Empty,
                Protocol = HistoryProtocol ?? string.Empty,
                Action = EventAction ?? string.Empty,
                Limit = Math.Clamp(HistoryLimit <= 0 ? 2000 : HistoryLimit, 1, 10_000),
                Format = format,
            });
            try
            {
                await System.IO.File.WriteAllTextAsync(path, profile.Content);
                var connectionCount = profile.ConnectionCount == 1
                    ? I18n.T("FwActivity_ConnectionCount", "{0} connection", profile.ConnectionCount)
                    : I18n.T("FwActivity_ConnectionCountPlural", "{0} connections", profile.ConnectionCount);
                var eventCount = profile.EventCount == 1
                    ? I18n.T("Common_EventCount", "{0} event", profile.EventCount)
                    : I18n.T("Common_EventCountPlural", "{0} events", profile.EventCount);
                HistoryStatus = I18n.T("FwHistory_ExportedProfile", "Exported redacted {0} traffic profile ({1}, {2}; no packet payloads) to {3}",
                    profile.Format, connectionCount, eventCount, System.IO.Path.GetFileName(path));
            }
            catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                HistoryStatus = I18n.T("Common_ExportFailed", "Export failed: {0}", ex.Message);
            }
        });
    }

    /// <summary>Serialize connection-history rows to CSV (RFC-4180 quoting). Pure — unit-tested.</summary>
    public static string BuildHistoryCsv(IEnumerable<HistoryRowViewModel> rows)
    {
        var sb = new System.Text.StringBuilder();
        CsvExport.AppendRow(sb,
            I18n.T("Csv_When", "When"),
            I18n.T("Csv_Process", "Process"),
            I18n.T("Csv_PID", "PID"),
            I18n.T("Csv_Protocol", "Protocol"),
            I18n.T("Csv_Host", "Host"),
            I18n.T("Csv_Remote", "Remote"),
            I18n.T("Csv_Port", "Port"),
            I18n.T("Csv_Country", "Country"),
            I18n.T("Csv_ASN", "ASN"),
            I18n.T("Csv_Firewall", "Firewall"));
        foreach (var r in rows)
        {
            CsvExport.AppendRow(
                sb,
                r.Ts,
                r.Process,
                r.Pid.ToString(CultureInfo.InvariantCulture),
                r.Protocol,
                r.Host,
                r.RemoteAddr,
                r.RemotePort.ToString(CultureInfo.InvariantCulture),
                r.Country,
                r.Asn,
                r.FwStatus);
        }

        return sb.ToString();
    }

    public async Task LoadBandwidthAsync()
    {
        await RunServiceActionAsync(I18n.T("FwHistory_ActionLoadBandwidth", "Load bandwidth timeline"), s => BandwidthStatus = s, async () =>
        {
            var list = await _client.Monitoring.GetAppBandwidthAsync(new BandwidthRequest { Minutes = 60, Top = TimelineMaxSeries });
            BuildBandwidthSeries(list);
        });
    }

    [RelayCommand]
    public async Task LoadUsageAsync()
    {
        await RunServiceActionAsync(I18n.T("FwHistory_ActionLoadUsage", "Load usage rollups"), s => UsageStatus = s, async () =>
        {
            UsageDays = Math.Clamp(UsageDays <= 0 ? 30 : UsageDays, 1, 365);
            UsageLimit = Math.Clamp(UsageLimit <= 0 ? 200 : UsageLimit, 1, 2000);
            var list = await _client.Monitoring.GetUsageRollupsAsync(new UsageRollupRequest
            {
                Days = UsageDays,
                Limit = UsageLimit,
                Search = UsageSearch ?? string.Empty,
                Process = UsageProcess ?? string.Empty,
                Domain = UsageDomain ?? string.Empty,
            });

            UsageRows.Clear();
            foreach (var row in list.Entries)
            {
                UsageRows.Add(new UsageRollupRowViewModel
                {
                    Day = row.Day,
                    Process = row.Process,
                    Domain = row.Domain,
                    Sent = row.Sent,
                    Recv = row.Recv,
                });
            }

            var shownRows = UsageRows.Count == 1
                ? I18n.T("FwHistory_UsageRowCount", "{0} usage row", UsageRows.Count)
                : I18n.T("FwHistory_UsageRowCountPlural", "{0} usage rows", UsageRows.Count);
            var retainedDays = list.RetentionDays == 1
                ? I18n.T("Common_DayCount", "{0} day", list.RetentionDays)
                : I18n.T("Common_DayCountPlural", "{0} days", list.RetentionDays);
            UsageStatus = I18n.T("FwHistory_UsageCountStatus", "{0} shown · retained {1}", shownRows, retainedDays);
        });
    }

    [RelayCommand]
    public async Task LoadUsageQuotasAsync()
    {
        await RunServiceActionAsync(I18n.T("FwHistory_ActionLoadQuotas", "Load usage quotas"), s => UsageQuotaStatus = s, async () =>
        {
            var list = await _client.Monitoring.GetUsageQuotaRulesAsync(new Empty());
            UsageQuotaRules.Clear();
            foreach (var rule in list.Rules)
            {
                UsageQuotaRules.Add(new UsageQuotaRuleViewModel
                {
                    Id = rule.Id,
                    Scope = rule.Scope,
                    Match = rule.Match,
                    LimitBytes = rule.LimitBytes,
                    WindowDays = rule.WindowDays,
                    Enabled = rule.Enabled,
                    UsedBytes = rule.UsedBytes,
                    LastAlertedBytes = rule.LastAlertedBytes,
                    LastAlertedAt = rule.LastAlertedAt,
                    BlockOnExceed = rule.BlockOnExceed,
                    BlockActive = rule.BlockActive,
                });
            }

            UsageQuotaStatus = UsageQuotaRules.Count == 1
                ? I18n.T("FwHistory_QuotaCountStatus", "{0} usage quota loaded", UsageQuotaRules.Count)
                : I18n.T("FwHistory_QuotaCountStatusPlural", "{0} usage quotas loaded", UsageQuotaRules.Count);
        });
    }

    [RelayCommand]
    public async Task SaveUsageQuotaAsync()
    {
        if (string.IsNullOrWhiteSpace(UsageQuotaScope) || string.IsNullOrWhiteSpace(UsageQuotaMatch))
        {
            UsageQuotaStatus = I18n.T("FwHistory_QuotaTargetRequired", "Enter app/domain scope and match before saving.");
            return;
        }

        if (!TryParseBytes(UsageQuotaLimitText, out var limitBytes))
        {
            UsageQuotaStatus = I18n.T("FwHistory_QuotaLimitRequired", "Enter a positive quota limit such as 500MB or 1GB.");
            return;
        }

        await RunServiceActionAsync(I18n.T("FwHistory_ActionSaveQuota", "Save usage quota"), s => UsageQuotaStatus = s, async () =>
        {
            UsageQuotaWindowDays = Math.Clamp(UsageQuotaWindowDays <= 0 ? 30 : UsageQuotaWindowDays, 1, 365);
            var ack = await _client.Monitoring.SetUsageQuotaRuleAsync(new UsageQuotaRule
            {
                Scope = UsageQuotaScope,
                Match = UsageQuotaMatch,
                LimitBytes = limitBytes,
                WindowDays = UsageQuotaWindowDays,
                Enabled = UsageQuotaEnabled,
                BlockOnExceed = UsageQuotaBlockOnExceed,
            });
            UsageQuotaStatus = ack.Message;
            await LoadUsageQuotasAsync();
        });
    }

    [RelayCommand]
    public async Task DeleteUsageQuotaAsync(UsageQuotaRuleViewModel? row)
    {
        if (row is null)
        {
            return;
        }

        if (!_confirm.Confirm(I18n.T("FwHistory_DeleteQuotaTitle", "Delete usage quota"),
            I18n.T("FwHistory_DeleteQuotaMessage", "Remove the {0} quota for {1}? Existing usage rollups are unchanged.", row.Scope, row.Match)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("FwHistory_ActionDeleteQuota", "Delete usage quota"), s => UsageQuotaStatus = s, async () =>
        {
            var ack = await _client.Monitoring.DeleteUsageQuotaRuleAsync(new UsageQuotaRule { Id = row.Id });
            UsageQuotaStatus = ack.Message;
            await LoadUsageQuotasAsync();
        });
    }

    [RelayCommand]
    public async Task ResetUsageQuotaHistoryAsync()
    {
        if (!_confirm.Confirm(I18n.T("FwHistory_ResetQuotaTitle", "Reset usage quota history"),
            I18n.T("FwHistory_ResetQuotaMessage", "Clear quota alert cursors so thresholds can alert again? Daily usage rollups remain intact.")))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("FwHistory_ActionResetQuota", "Reset usage quota history"), s => UsageQuotaStatus = s, async () =>
        {
            var ack = await _client.Monitoring.ResetUsageQuotaHistoryAsync(new Empty());
            UsageQuotaStatus = ack.Message;
            await LoadUsageQuotasAsync();
        });
    }

    [RelayCommand]
    public async Task ExportUsageQuotaHistoryAsync()
    {
        if (_filePicker is null)
        {
            return;
        }

        var path = _filePicker.SaveFile(I18n.T("FwHistory_ExportQuotaTitle", "Export usage quota history (CSV)"), "usage_quota_history.csv",
            I18n.T("FileFilter_CsvJson", "CSV files ({0})|{0}|JSON files ({1})|{1}", "*.csv", "*.json"));
        if (string.IsNullOrEmpty(path))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("FwHistory_ActionExportQuota", "Export usage quota history"), s => UsageQuotaStatus = s, async () =>
        {
            var export = await _client.Monitoring.ExportUsageQuotaHistoryAsync(new UsageQuotaHistoryRequest
            {
                Days = Math.Clamp(UsageDays <= 0 ? 30 : UsageDays, 1, 365),
                Format = path.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ? "json" : "csv",
            });
            await System.IO.File.WriteAllTextAsync(path, export.Content);
            UsageQuotaStatus = I18n.T("FwHistory_ExportedQuota", "Exported usage quota history to {0}", System.IO.Path.GetFileName(path));
        });
    }

    /// <summary>Rebuild the bandwidth polylines from a fetched series list (pure; testable).</summary>
    public void BuildBandwidthSeries(AppBandwidthList list)
    {
        ArgumentNullException.ThrowIfNull(list);
        Bandwidth.Clear();
        if (list.Series.Count == 0)
        {
            BandwidthStatus = list.CountersActive
                ? I18n.T("FwHistory_NoTraffic", "No traffic recorded yet")
                : I18n.T("FwHistory_CountersInactive", "Byte counters inactive (service not elevated)");
            return;
        }

        var peak = Math.Max(1, list.Series.Max(s => s.Bytes.Count == 0 ? 0 : s.Bytes.Max()));
        for (var i = 0; i < list.Series.Count; i++)
        {
            var s = list.Series[i];
            var points = new System.Text.StringBuilder();
            var stepX = s.Bytes.Count > 1 ? TimelineWidth / (s.Bytes.Count - 1) : 0;
            for (var b = 0; b < s.Bytes.Count; b++)
            {
                var x = b * stepX;
                var y = TimelineHeight - (s.Bytes[b] / (double)peak * (TimelineHeight - 6)) - 2;
                if (b != 0)
                {
                    points.Append(' ');
                }

                points.Append(x.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture))
                      .Append(',')
                      .Append(y.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture));
            }

            Bandwidth.Add(new TimelineSeriesViewModel
            {
                Name = s.Process,
                PointsText = points.ToString(),
                ColorIndex = i,
                LegendText = I18n.T("FwHistory_BandwidthLegend", "↑{0} ↓{1}", FormatBytes(s.TotalSent), FormatBytes(s.TotalRecv)),
            });
        }

        BandwidthStatus = list.Series.Count == 1
            ? I18n.T("FwHistory_BandwidthStatus", "Top {0} app · last 60 min · peak {1}/min", list.Series.Count, FormatBytes(peak))
            : I18n.T("FwHistory_BandwidthStatusPlural", "Top {0} apps · last 60 min · peak {1}/min", list.Series.Count, FormatBytes(peak));
    }

    [RelayCommand]
    public async Task LoadHistoryPrivacyAsync()
    {
        await RunServiceActionAsync(I18n.T("HistoryPrivacy_Load", "Load privacy exclusions"), s => HistoryPrivacyStatus = s, async () =>
        {
            var list = await _client.Monitoring.ListHistoryPrivacyExclusionsAsync(new Empty());
            HistoryPrivacyExclusions.Clear();
            foreach (var row in list.Exclusions) HistoryPrivacyExclusions.Add(row);
            HistoryPrivacyStatus = list.Disclosure;
        });
    }

    [RelayCommand]
    public async Task SaveHistoryPrivacyAsync()
    {
        if (string.IsNullOrWhiteSpace(HistoryPrivacyMatch))
        {
            HistoryPrivacyStatus = I18n.T("HistoryPrivacy_MatchRequired", "Enter an app process name or domain.");
            return;
        }
        await RunServiceActionAsync(I18n.T("HistoryPrivacy_Save", "Save privacy exclusion"), s => HistoryPrivacyStatus = s, async () =>
        {
            var ack = await _client.Monitoring.SetHistoryPrivacyExclusionAsync(new HistoryPrivacyExclusion { Scope = HistoryPrivacyScope, Match = HistoryPrivacyMatch });
            HistoryPrivacyStatus = ack.Message;
            if (ack.Ok) { HistoryPrivacyMatch = string.Empty; await LoadHistoryPrivacyAsync(); }
        });
    }

    [RelayCommand]
    public async Task DeleteHistoryPrivacyAsync(HistoryPrivacyExclusion? row)
    {
        if (row is null) return;
        await RunServiceActionAsync(I18n.T("HistoryPrivacy_Delete", "Delete privacy exclusion"), s => HistoryPrivacyStatus = s, async () =>
        {
            var ack = await _client.Monitoring.DeleteHistoryPrivacyExclusionAsync(row);
            HistoryPrivacyStatus = ack.Message;
            await LoadHistoryPrivacyAsync();
        });
    }

    /// <summary>Humanized byte count ("1.4 MB").</summary>
    public static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = Math.Max(0, bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{value:0.#} {units[unit]}");
    }

    public static bool TryParseBytes(string text, out long bytes)
    {
        bytes = 0;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var value = text.Trim();
        var numberEnd = value.Length;
        while (numberEnd > 0 && char.IsLetter(value[numberEnd - 1]))
        {
            numberEnd--;
        }

        if (numberEnd <= 0)
        {
            return false;
        }

        var unit = value[numberEnd..].Trim().ToUpperInvariant();
        var numberText = value[..numberEnd].Trim();
        if (!decimal.TryParse(numberText, System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var parsed) || parsed <= 0)
        {
            return false;
        }

        var multiplier = unit switch
        {
            "" or "B" => 1m,
            "K" or "KB" => 1024m,
            "M" or "MB" => 1024m * 1024m,
            "G" or "GB" => 1024m * 1024m * 1024m,
            "T" or "TB" => 1024m * 1024m * 1024m * 1024m,
            _ => 0m,
        };
        if (multiplier <= 0)
        {
            return false;
        }

        var total = parsed * multiplier;
        if (total > long.MaxValue)
        {
            return false;
        }

        bytes = (long)Math.Ceiling(total);
        return bytes > 0;
    }
}

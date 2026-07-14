using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

/// <summary>One row of the service-health glance (NET-186).</summary>
public sealed class HealthRowViewModel
{
    public string Aspect { get; init; } = string.Empty;

    public string State { get; init; } = string.Empty;

    public string Detail { get; init; } = string.Empty;

    public bool Healthy { get; init; } = true;
}

public sealed partial class ToolsViewModel
{
    // ─── Service-health glance (NET-186, on the NET-169 diagnostics fields) ──

    public ObservableCollection<HealthRowViewModel> HealthRows { get; } = new();

    [ObservableProperty]
    private string _healthStatusText = I18n.T(
        "Health_StatusHint", "Load the health glance to see monitor liveness, enforcement posture, and database state.");

    [RelayCommand]
    public async Task LoadHealthAsync()
    {
        await RunServiceActionAsync(I18n.T("Health_ActionLoad", "Load service health"), s => HealthStatusText = s, async () =>
        {
            var status = await _client.Diagnostics.GetStatusAsync(new Empty());
            var lastListRefresh = string.Empty;
            try
            {
                var lists = await _client.Lists.ListBlocklistSourcesAsync(new Empty());
                lastListRefresh = lists.Sources
                    .Where(s => s.Subscribed && s.LastRefresh.Length != 0)
                    .Select(s => s.LastRefresh)
                    .OrderByDescending(s => s, StringComparer.Ordinal)
                    .FirstOrDefault() ?? string.Empty;
            }
            catch (Grpc.Core.RpcException)
            {
            }

            HealthRows.Clear();
            var up = I18n.T("Health_Up", "Up");
            var down = I18n.T("Health_Down", "Down");

            HealthRows.Add(new HealthRowViewModel
            {
                Aspect = I18n.T("Health_Service", "Service"),
                State = I18n.T("Health_Running", "Running"),
                Detail = I18n.T("Health_ServiceDetail", "v{0} · {1} · up {2}",
                    status.Version,
                    status.Elevated ? I18n.T("Health_Elevated", "elevated") : I18n.T("Health_NotElevated", "not elevated"),
                    FormatUptime(status.UptimeSeconds)),
                Healthy = status.Elevated,
            });
            if (status.ObservationSources.Count != 0)
            {
                foreach (var observation in status.ObservationSources
                             .OrderBy(row => ObservationOrder(row.Source)))
                {
                    var healthy = observation.State == "healthy";
                    HealthRows.Add(new HealthRowViewModel
                    {
                        Aspect = ObservationName(observation.Source),
                        State = observation.State switch
                        {
                            "healthy" => up,
                            "degraded" => I18n.T("Health_Degraded", "Degraded"),
                            _ => down,
                        },
                        Detail = I18n.T(
                            "Health_ObservationDetail",
                            "lost {0} · gaps {1} · restarts {2} · transition {3} · {4}",
                            observation.LossCount,
                            observation.GapCount,
                            observation.RestartCount,
                            TimeText.Compact(observation.LastTransitionAt),
                            observation.Detail),
                        Healthy = healthy,
                    });
                }
            }
            else
            {
                HealthRows.Add(new HealthRowViewModel
                {
                    Aspect = I18n.T("Health_DnsMonitor", "DNS monitor"),
                    State = status.DnsMonitorActive ? up : down,
                    Detail = status.DnsMonitorActive ? string.Empty : I18n.T("Health_MonitorDownDetail", "requires the elevated service"),
                    Healthy = status.DnsMonitorActive,
                });
                HealthRows.Add(new HealthRowViewModel
                {
                    Aspect = I18n.T("Health_BandwidthMonitor", "Bandwidth monitor"),
                    State = status.BandwidthMonitorActive ? up : down,
                    Detail = status.BandwidthMonitorActive ? string.Empty : I18n.T("Health_OptMonitorDetail", "elevation-gated; usage budgets need it"),
                    Healthy = status.BandwidthMonitorActive,
                });
            }
            HealthRows.Add(new HealthRowViewModel
            {
                Aspect = I18n.T("Health_ConnMonitor", "Connection monitor"),
                State = status.ConnectionMonitorActive ? up : down,
                Healthy = status.ConnectionMonitorActive,
            });
            HealthRows.Add(new HealthRowViewModel
            {
                Aspect = I18n.T("Health_SniMonitor", "SNI capture"),
                State = status.SniMonitorActive ? up : I18n.T("Health_Off", "Off"),
                Detail = status.SniMonitorActive ? string.Empty : I18n.T("Health_SniDetail", "opt-in"),
                Healthy = true, // opt-in: off is a valid state, not a fault
            });
            HealthRows.Add(new HealthRowViewModel
            {
                Aspect = I18n.T("Health_Enforcement", "Enforcement"),
                State = status.FilteringMode.Length != 0 ? status.FilteringMode : I18n.T("Health_ModeNormal", "normal"),
                Detail = (status.KillSwitchEngaged ? I18n.T("Health_KillSwitchOn", "kill-switch engaged · ") : string.Empty)
                       + (status.SecureRulesArmed ? I18n.T("Health_SecureRulesOn", "secure rules armed · ") : string.Empty)
                       + I18n.T("Health_PendingConsent", "{0} pending consent", status.PendingConsent),
                Healthy = true,
            });
            HealthRows.Add(new HealthRowViewModel
            {
                Aspect = I18n.T("Health_Persistence", "Activity persistence"),
                State = status.PersistenceDroppedWrites == 0
                    ? I18n.T("Health_Ok", "OK")
                    : I18n.T("Health_Dropping", "Dropping"),
                Detail = status.PersistenceDroppedWrites == 0
                    ? I18n.T("Health_PersistenceDetail", "{0} batches written", status.PersistenceWriteBatches)
                    : I18n.T("Health_PersistenceDropDetail", "{0} writes dropped — the service is shedding DNS/SNI history", status.PersistenceDroppedWrites),
                Healthy = status.PersistenceDroppedWrites == 0,
            });
            HealthRows.Add(new HealthRowViewModel
            {
                Aspect = I18n.T("Health_Database", "Database"),
                State = status.SchemaVersion == status.SchemaVersionOnDisk
                    ? I18n.T("Health_Ok", "OK")
                    : I18n.T("Health_Mismatch", "Mismatch"),
                Detail = I18n.T("Health_SchemaDetail", "schema v{0} (on disk v{1})", status.SchemaVersion, status.SchemaVersionOnDisk),
                Healthy = status.SchemaVersion == status.SchemaVersionOnDisk,
            });
            if (status.RuntimeVersion.Length != 0 || status.SqliteVersion.Length != 0)
            {
                HealthRows.Add(new HealthRowViewModel
                {
                    Aspect = I18n.T("Health_Runtime", "Runtime"),
                    State = I18n.T("Health_Ok", "OK"),
                    Detail = I18n.T("Health_RuntimeDetail", ".NET {0} · SQLite {1}",
                        status.RuntimeVersion, status.SqliteVersion),
                    Healthy = true,
                });
            }

            HealthRows.Add(new HealthRowViewModel
            {
                Aspect = I18n.T("Health_Blocklists", "Blocklists"),
                State = lastListRefresh.Length != 0
                    ? I18n.T("Health_Refreshed", "Refreshed")
                    : I18n.T("Health_NeverRefreshed", "Never refreshed"),
                Detail = lastListRefresh.Length != 0
                    ? I18n.T("Health_LastRefreshDetail", "last refresh {0}", TimeText.Compact(lastListRefresh))
                    : I18n.T("Health_NoSubsDetail", "no subscribed sources have refreshed yet"),
                Healthy = true,
            });
            if (status.HostsOverScaleThreshold)
            {
                HealthRows.Add(new HealthRowViewModel
                {
                    Aspect = I18n.T("Health_HostsScale", "Hosts file scale"),
                    State = I18n.T("Health_Large", "Large"),
                    Detail = I18n.T("Health_HostsScaleDetail", "large enough to slow system-wide DNS — prefer firewall IP rules"),
                    Healthy = false,
                });
            }

            var unhealthy = HealthRows.Count(r => !r.Healthy);
            HealthStatusText = unhealthy == 0
                ? I18n.T("Health_AllOk", "All health checks OK.")
                : I18n.T("Health_SomeBad", "{0} health check(s) need attention.", unhealthy);
        });
    }

    private static int ObservationOrder(string source) => source switch
    {
        "dns_etw" => 0,
        "network_etw" => 1,
        "security_log" => 2,
        _ => 3,
    };

    private static string ObservationName(string source) => source switch
    {
        "dns_etw" => I18n.T("Health_DnsObservation", "DNS observation (ETW)"),
        "network_etw" => I18n.T("Health_NetworkObservation", "Network observation (ETW)"),
        "security_log" => I18n.T("Health_SecurityObservation", "Blocked evidence (Security log)"),
        _ => source,
    };

    // ─── SHA-256-verified self-update (NET-187) ──────────────────────────────

    [ObservableProperty]
    private string _updateStatusText = I18n.T(
        "Update_StatusHint", "Check the release feed; staging downloads the installer, verifies its pinned SHA-256, and applies it on the next service restart.");

    [RelayCommand]
    public async Task CheckUpdateAsync()
    {
        await RunServiceActionAsync(I18n.T("Update_ActionCheck", "Check for updates"), s => UpdateStatusText = s, async () =>
        {
            var status = await _client.Diagnostics.GetUpdateStatusAsync(new Empty());
            var staged = status.StagedVersion.Length != 0
                ? I18n.T("Update_StagedSuffix", " · staged {0} — applies on next service restart", status.StagedVersion)
                : string.Empty;
            UpdateStatusText = status.LastError.Length != 0
                ? status.LastError
                : status.UpdateAvailable
                    ? I18n.T("Update_Available", "Update available: {0} (installed {1}).{2}", status.LatestVersion, status.InstalledVersion, staged)
                    : I18n.T("Update_UpToDate", "Up to date: {0} (latest {1}).{2}", status.InstalledVersion, status.LatestVersion, staged);
            StatusText = UpdateStatusText;
        });
    }

    [RelayCommand]
    public async Task StageUpdateAsync()
    {
        await RunServiceActionAsync(I18n.T("Update_ActionStage", "Stage update"), s => UpdateStatusText = s, async () =>
        {
            var ack = await _client.Diagnostics.StageUpdateAsync(new StageUpdateRequest());
            UpdateStatusText = ack.Message;
            StatusText = ack.Message;
        });
    }

    private static string FormatUptime(long seconds)
    {
        var span = TimeSpan.FromSeconds(Math.Max(0, seconds));
        return span.TotalDays >= 1
            ? $"{(int)span.TotalDays}d {span.Hours}h"
            : span.TotalHours >= 1 ? $"{(int)span.TotalHours}h {span.Minutes}m" : $"{span.Minutes}m";
    }
}

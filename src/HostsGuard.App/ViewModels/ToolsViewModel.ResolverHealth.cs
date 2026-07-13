using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class ToolsViewModel
{
    public ObservableCollection<ResolverHealthRowViewModel> ResolverHealthEntries { get; } = new();

    [ObservableProperty]
    private string _resolverHealthHost = "example.com";

    [ObservableProperty]
    private bool _resolverHealthScheduleEnabled;

    [ObservableProperty]
    private int _resolverHealthScheduleIntervalMinutes = 60;

    [ObservableProperty]
    private string _resolverHealthStatusText = I18n.T(
        "ResolverHealth_NoReport",
        "No resolver health report yet. Scheduled checks will appear here when available.");

    [RelayCommand]
    public Task LoadResolverHealthAsync() => RunServiceActionAsync(
        I18n.T("ResolverHealth_ActionLoad", "Load resolver health"),
        status => ResolverHealthStatusText = status,
        async () => ApplyResolverHealthReport(await _client.Dns.GetResolverHealthAsync(new Empty())));

    [RelayCommand]
    public Task RunResolverHealthAsync() => RunServiceActionAsync(
        I18n.T("ResolverHealth_ActionRun", "Run resolver health check"),
        status => ResolverHealthStatusText = status,
        async () => ApplyResolverHealthReport(await _client.Dns.RunResolverHealthAsync(
            new ResolverHealthRequest { Host = ResolverHealthHost.Trim() })));

    [RelayCommand]
    public Task ApplyResolverHealthScheduleAsync() => RunServiceActionAsync(
        I18n.T("ResolverHealth_ActionSchedule", "Save resolver health schedule"),
        status => ResolverHealthStatusText = status,
        async () =>
        {
            ResolverHealthScheduleIntervalMinutes = Math.Clamp(ResolverHealthScheduleIntervalMinutes, 15, 1_440);
            ApplyResolverHealthReport(await _client.Dns.SetResolverHealthScheduleAsync(
                new ResolverHealthScheduleRequest
                {
                    Enabled = ResolverHealthScheduleEnabled,
                    IntervalMinutes = ResolverHealthScheduleIntervalMinutes,
                }));
        });

    private void ApplyResolverHealthReport(ResolverHealthReport report)
    {
        ResolverHealthEntries.Clear();
        foreach (var entry in report.Entries.OrderBy(static entry => entry.AdapterName, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(static entry => entry.Endpoint, StringComparer.OrdinalIgnoreCase))
        {
            ResolverHealthEntries.Add(ResolverHealthRowViewModel.From(entry));
        }

        ResolverHealthHost = string.IsNullOrWhiteSpace(report.Host) ? ResolverHealthHost : report.Host;
        ResolverHealthScheduleEnabled = report.ScheduleEnabled;
        if (report.ScheduleIntervalMinutes > 0)
        {
            ResolverHealthScheduleIntervalMinutes = report.ScheduleIntervalMinutes;
        }

        if (report.Running)
        {
            ResolverHealthStatusText = I18n.T("ResolverHealth_Running", "Resolver health check is running.");
            return;
        }

        if (report.Entries.Count == 0 && string.IsNullOrWhiteSpace(report.CheckedAt))
        {
            ResolverHealthStatusText = I18n.T(
                "ResolverHealth_NoReport",
                "No resolver health report yet. Scheduled checks will appear here when available.");
            return;
        }

        ResolverHealthStatusText = I18n.T(
            "ResolverHealth_Status",
            "{0} endpoint(s); checked {1}; scheduled={2}; next={3}. {4}",
            report.Entries.Count,
            ValueOrUnavailable(report.CheckedAt),
            report.ScheduleEnabled ? I18n.T("Common_Yes", "yes") : I18n.T("Common_No", "no"),
            ValueOrUnavailable(report.NextScheduledAt),
            report.Message);
    }

    private static string ValueOrUnavailable(string value) => string.IsNullOrWhiteSpace(value)
        ? I18n.T("ResolverHealth_Unavailable", "Unavailable")
        : value;
}

public sealed class ResolverHealthRowViewModel
{
    public string Adapter { get; init; } = string.Empty;
    public string Endpoint { get; init; } = string.Empty;
    public string Protocol { get; init; } = string.Empty;
    public string AResult { get; init; } = string.Empty;
    public string AaaaResult { get; init; } = string.Empty;
    public string RttText { get; init; } = string.Empty;
    public string TlsStatus { get; init; } = string.Empty;
    public string CertificateStatus { get; init; } = string.Empty;
    public string ResultText { get; init; } = string.Empty;

    public static ResolverHealthRowViewModel From(ResolverHealthEntry entry) => new()
    {
        Adapter = string.IsNullOrWhiteSpace(entry.AdapterName) ? entry.AdapterId : entry.AdapterName,
        Endpoint = entry.Endpoint,
        Protocol = entry.Protocol.ToUpperInvariant(),
        AResult = FormatAddressResult(entry.AStatus, entry.ACount, entry.ADetail),
        AaaaResult = FormatAddressResult(entry.AaaaStatus, entry.AaaaCount, entry.AaaaDetail),
        RttText = entry.RttAvailable
            ? I18n.T("ResolverHealth_RttMs", "{0} ms", entry.RttMs)
            : I18n.T("ResolverHealth_Unavailable", "Unavailable"),
        TlsStatus = FormatTls(entry.TlsStatus),
        CertificateStatus = FormatCertificate(entry.TlsStatus),
        ResultText = entry.Success
            ? I18n.T("ResolverHealth_ResultOk", "Healthy")
            : string.IsNullOrWhiteSpace(entry.Error)
                ? I18n.T("ResolverHealth_Unavailable", "Unavailable")
                : entry.Error,
    };

    private static string FormatAddressResult(string status, int count, string detail)
    {
        if (status.Equals("available", StringComparison.OrdinalIgnoreCase))
        {
            return I18n.T("ResolverHealth_AddressAvailable", "Available ({0})", count);
        }

        if (!string.IsNullOrWhiteSpace(detail))
        {
            return detail;
        }

        return status.Equals("failed", StringComparison.OrdinalIgnoreCase)
            ? I18n.T("ResolverHealth_Failed", "Failed")
            : I18n.T("ResolverHealth_Unavailable", "Unavailable");
    }

    private static string FormatTls(string status) => status.ToLowerInvariant() switch
    {
        "valid" => I18n.T("ResolverHealth_TlsValid", "Valid"),
        "certificate_failure" => I18n.T("ResolverHealth_TlsCertificateFailure", "Certificate failure"),
        "not_applicable" => I18n.T("ResolverHealth_NotApplicable", "Not applicable"),
        _ => I18n.T("ResolverHealth_Unavailable", "Unavailable"),
    };

    private static string FormatCertificate(string status) => status.ToLowerInvariant() switch
    {
        "valid" => I18n.T("ResolverHealth_CertificateValid", "Valid"),
        "certificate_failure" => I18n.T("ResolverHealth_CertificateFailure", "Failed"),
        "not_applicable" => I18n.T("ResolverHealth_NotApplicable", "Not applicable"),
        _ => I18n.T("ResolverHealth_Unavailable", "Unavailable"),
    };
}

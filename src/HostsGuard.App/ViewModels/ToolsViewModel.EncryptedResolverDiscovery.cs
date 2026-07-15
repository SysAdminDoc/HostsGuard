using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class ToolsViewModel
{
    public ObservableCollection<EncryptedResolverDiscoveryRowViewModel> EncryptedResolverDiscoveryEntries { get; } = new();

    [ObservableProperty]
    private string _encryptedResolverDiscoveryStatusText = I18n.T(
        "EncryptedResolver_NoReport",
        "No DDR/DNR discovery report yet. Run discovery to create or compare the tamper baseline.");

    [RelayCommand]
    public Task LoadEncryptedResolverDiscoveryAsync() => RunServiceActionAsync(
        I18n.T("EncryptedResolver_ActionLoad", "Load encrypted-resolver discovery"),
        status => EncryptedResolverDiscoveryStatusText = status,
        async () => ApplyEncryptedResolverDiscoveryReport(
            await _client.Dns.GetEncryptedResolverDiscoveryAsync(new Empty())));

    [RelayCommand]
    public Task RunEncryptedResolverDiscoveryAsync() => RunServiceActionAsync(
        I18n.T("EncryptedResolver_ActionRun", "Run encrypted-resolver discovery"),
        status => EncryptedResolverDiscoveryStatusText = status,
        async () => ApplyEncryptedResolverDiscoveryReport(
            await _client.Dns.RunEncryptedResolverDiscoveryAsync(new Empty())));

    [RelayCommand]
    public Task AcceptEncryptedResolverBaselineAsync() => RunServiceActionAsync(
        I18n.T("EncryptedResolver_ActionAccept", "Trust current encrypted-resolver baseline"),
        status => EncryptedResolverDiscoveryStatusText = status,
        async () => ApplyEncryptedResolverDiscoveryReport(
            await _client.Dns.AcceptEncryptedResolverBaselineAsync(new Empty())));

    private void ApplyEncryptedResolverDiscoveryReport(EncryptedResolverDiscoveryReport report)
    {
        EncryptedResolverDiscoveryEntries.Clear();
        foreach (var entry in report.Entries
                     .OrderBy(static entry => entry.AdapterName, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(static entry => entry.Source, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(static entry => entry.Priority))
        {
            EncryptedResolverDiscoveryEntries.Add(EncryptedResolverDiscoveryRowViewModel.From(entry));
        }

        if (report.Running)
        {
            EncryptedResolverDiscoveryStatusText = I18n.T(
                "EncryptedResolver_Running",
                "Encrypted-resolver discovery is running.");
            return;
        }

        EncryptedResolverDiscoveryStatusText = I18n.T(
            "EncryptedResolver_Status",
            "{0} row(s); checked {1}; baseline={2}; drift={3}. {4}",
            report.Entries.Count,
            string.IsNullOrWhiteSpace(report.CheckedAt)
                ? I18n.T("EncryptedResolver_Unavailable", "Unavailable")
                : report.CheckedAt,
            report.BaselinePresent ? I18n.T("Common_Yes", "yes") : I18n.T("Common_No", "no"),
            report.DriftDetected ? I18n.T("Common_Yes", "yes") : I18n.T("Common_No", "no"),
            report.Message);
    }
}

public sealed class EncryptedResolverDiscoveryRowViewModel
{
    public string Adapter { get; init; } = string.Empty;
    public string Source { get; init; } = string.Empty;
    public string Resolver { get; init; } = string.Empty;
    public string Outcome { get; init; } = string.Empty;
    public string Target { get; init; } = string.Empty;
    public string Protocols { get; init; } = string.Empty;
    public string Addresses { get; init; } = string.Empty;
    public string Drift { get; init; } = string.Empty;
    public string Detail { get; init; } = string.Empty;

    public static EncryptedResolverDiscoveryRowViewModel From(EncryptedResolverDiscoveryEntry entry) => new()
    {
        Adapter = string.IsNullOrWhiteSpace(entry.AdapterName) ? entry.AdapterId : entry.AdapterName,
        Source = entry.Source.ToLowerInvariant() switch
        {
            "dnr_v4" => "DNRv4",
            "dnr_v6" => "DNRv6",
            _ => "DDR",
        },
        Resolver = string.IsNullOrWhiteSpace(entry.Resolver)
            ? I18n.T("EncryptedResolver_Network", "Network")
            : entry.Resolver,
        Outcome = entry.Outcome,
        Target = string.IsNullOrWhiteSpace(entry.Endpoint) ? entry.Target : entry.Endpoint,
        Protocols = string.Join(", ", entry.Protocols),
        Addresses = string.Join(", ", entry.Addresses),
        Drift = entry.Drifted
            ? I18n.T("EncryptedResolver_Changed", "Changed")
            : I18n.T("EncryptedResolver_Unchanged", "Unchanged"),
        Detail = entry.Detail,
    };
}

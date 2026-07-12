using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed class ProxyBaselineRowViewModel
{
    public string Scope { get; init; } = string.Empty;
    public string Identity { get; init; } = string.Empty;
    public string Setting { get; init; } = string.Empty;
    public string Baseline { get; init; } = string.Empty;
    public string Current { get; init; } = string.Empty;
    public bool Changed { get; init; }
    public string State => Changed
        ? I18n.T("Proxy_StateChanged", "Changed")
        : I18n.T("Proxy_StateMatch", "Matches");

    public static ProxyBaselineRowViewModel From(ProxyBaselineEntry entry) => new()
    {
        Scope = entry.Scope,
        Identity = entry.Sid.Length == 0 ? I18n.T("Proxy_Machine", "Machine") : entry.Sid,
        Setting = entry.Setting,
        Baseline = entry.BaselinePresent ? entry.BaselineValue : I18n.T("Proxy_NotRecorded", "Not recorded"),
        Current = entry.CurrentPresent ? entry.CurrentValue : I18n.T("Proxy_NotSet", "Not set"),
        Changed = entry.Changed,
    };
}

public sealed partial class ToolsViewModel
{
    public ObservableCollection<ProxyBaselineRowViewModel> ProxyBaselineRows { get; } = new();

    [ObservableProperty]
    private string _proxyBaselineStatus = I18n.T(
        "Proxy_StatusHint", "Check current WinINET and WinHTTP proxy/PAC state against the accepted baseline.");

    [RelayCommand]
    public async Task InspectProxyBaselineAsync()
    {
        await RunServiceActionAsync(I18n.T("Proxy_ActionInspect", "Check proxy baseline"), s => ProxyBaselineStatus = s, async () =>
        {
            var report = await _client.Diagnostics.InspectProxyBaselineAsync(new Empty());
            ProxyBaselineRows.Clear();
            foreach (var entry in report.Entries.OrderBy(item => item.Scope, StringComparer.Ordinal)
                         .ThenBy(item => item.Sid, StringComparer.Ordinal)
                         .ThenBy(item => item.Setting, StringComparer.Ordinal))
            {
                ProxyBaselineRows.Add(ProxyBaselineRowViewModel.From(entry));
            }

            ProxyBaselineStatus = report.Message.Length != 0
                ? report.Message
                : !report.BaselineExists
                    ? I18n.T("Proxy_NoBaseline", "No accepted proxy baseline yet.")
                    : report.Changed
                        ? I18n.T("Proxy_Changed", "Proxy/PAC state differs from the accepted baseline.")
                        : I18n.T("Proxy_Unchanged", "Proxy/PAC state matches the accepted baseline.");
            StatusText = ProxyBaselineStatus;
        });
    }

    [RelayCommand]
    public async Task AcceptProxyBaselineAsync()
    {
        await RunServiceActionAsync(I18n.T("Proxy_ActionAccept", "Accept proxy baseline"), s => ProxyBaselineStatus = s, async () =>
        {
            var ack = await _client.Diagnostics.AcceptProxyBaselineAsync(new Empty());
            ProxyBaselineStatus = ack.Message;
            StatusText = ack.Message;
            if (ack.Ok)
            {
                await InspectProxyBaselineAsync();
            }
        });
    }
}

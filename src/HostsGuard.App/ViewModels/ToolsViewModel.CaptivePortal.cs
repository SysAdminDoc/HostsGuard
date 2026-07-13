using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class ToolsViewModel
{
    private readonly HashSet<int> _captivePortalPauseMinutes = new();

    [ObservableProperty]
    private string _captivePortalStatusText = I18n.T(
        "CaptivePortal_NotChecked", "Captive portal status not checked");

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(PauseForCaptivePortalCommand))]
    private bool _captivePortalPauseAvailable;

    [RelayCommand]
    public async Task CheckCaptivePortalAsync()
    {
        await RunServiceActionAsync(
            I18n.T("CaptivePortal_ActionCheck", "Check captive portal"),
            s => CaptivePortalStatusText = s,
            async () =>
            {
                var status = await _client.Diagnostics.CheckCaptivePortalAsync(new Empty());
                _captivePortalPauseMinutes.Clear();
                foreach (var minutes in status.AllowedPauseMinutes.Where(m => m is 5 or 15 or 60))
                {
                    _captivePortalPauseMinutes.Add(minutes);
                }

                CaptivePortalPauseAvailable = status.PauseAvailable &&
                    _captivePortalPauseMinutes.Count != 0;
                CaptivePortalStatusText = DescribeCaptivePortal(status);
            });
    }

    [RelayCommand(CanExecute = nameof(CanPauseForCaptivePortal))]
    public async Task PauseForCaptivePortalAsync(object? minutesValue)
    {
        if (!TryGetPauseMinutes(minutesValue, out var minutes) ||
            !_captivePortalPauseMinutes.Contains(minutes))
        {
            CaptivePortalStatusText = I18n.T(
                "CaptivePortal_PauseUnavailable",
                "A timed pause is offered only when a captive portal is suspected.");
            return;
        }

        await RunServiceActionAsync(
            I18n.T("CaptivePortal_ActionPause", "Pause enforcement for captive portal sign-in"),
            s => CaptivePortalStatusText = s,
            async () =>
            {
                var ack = await _client.Firewall.PauseEnforcementAsync(
                    new EnforcementPauseRequest { Minutes = minutes });
                CaptivePortalStatusText = ack.Message;
                if (ack.Ok)
                {
                    CaptivePortalPauseAvailable = false;
                }
            });
    }

    private bool CanPauseForCaptivePortal(object? minutesValue) =>
        CaptivePortalPauseAvailable &&
        TryGetPauseMinutes(minutesValue, out var minutes) &&
        _captivePortalPauseMinutes.Contains(minutes);

    private static bool TryGetPauseMinutes(object? value, out int minutes) =>
        value switch
        {
            int typed => (minutes = typed) != 0,
            string text => int.TryParse(text, out minutes),
            _ => (minutes = 0) != 0,
        };

    private static string DescribeCaptivePortal(CaptivePortalStatus status)
    {
        var state = status.State.ToLowerInvariant() switch
        {
            "clear" => I18n.T("CaptivePortal_Clear", "Clear"),
            "suspected" => I18n.T("CaptivePortal_Suspected", "Portal suspected"),
            "offline" => I18n.T("CaptivePortal_Offline", "Offline"),
            _ => I18n.T("CaptivePortal_Unavailable", "Probe unavailable"),
        };
        var detail = string.IsNullOrWhiteSpace(status.Detail) ? state : status.Detail;
        return status.HttpStatus > 0
            ? I18n.T("CaptivePortal_Status",
                "{0}: {1} (HTTP {2}, observed host {3}). Enforcement was not changed.",
                state, detail, status.HttpStatus,
                string.IsNullOrWhiteSpace(status.ObservedHost) ? "-" : status.ObservedHost)
            : I18n.T("CaptivePortal_StatusNoHttp",
                "{0}: {1}. Enforcement was not changed.", state, detail);
    }
}

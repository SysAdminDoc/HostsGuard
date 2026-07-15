using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class HostsViewModel
{
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(PinRedirectCommand))]
    private string _newRedirectDomain = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(PinRedirectCommand))]
    private string _newRedirectIp = string.Empty;

    public ObservableCollection<HostsRedirectViewModel> Redirects { get; } = new();

    private bool CanPinRedirect() =>
        !string.IsNullOrWhiteSpace(NewRedirectDomain) && !string.IsNullOrWhiteSpace(NewRedirectIp);

    [RelayCommand(CanExecute = nameof(CanPinRedirect))]
    public async Task PinRedirectAsync()
    {
        var domain = NewRedirectDomain.Trim();
        var ip = NewRedirectIp.Trim();
        if (!_confirm.Confirm(
                I18n.T("HostsRedirect_PinTitle", "Pin domain to IP"),
                I18n.T("HostsRedirect_PinConfirm",
                    "Pin {0} to {1} in the Windows hosts file? Any managed block for this domain is removed; the exact pin is tracked as intentional.",
                    domain, ip)))
        {
            StatusText = I18n.T("HostsRedirect_PinCancelled", "Domain pin cancelled; no changes were made.");
            return;
        }

        await RunServiceActionAsync(I18n.T("HostsRedirect_PinAction", "Pin domain"), async () =>
        {
            var ack = await _client.Hosts.PinRedirectAsync(new RedirectRequest { Domain = domain, Ip = ip });
            if (!ack.Ok)
            {
                StatusText = ack.Message;
                return;
            }

            NewRedirectDomain = string.Empty;
            NewRedirectIp = string.Empty;
            await RefreshCoreAsync();
            StatusText = ack.Message;
        });
    }

    [RelayCommand]
    public async Task RemoveRedirectAsync(HostsRedirectViewModel? row)
    {
        if (row is null)
        {
            StatusText = I18n.T("Common_SelectRow", "Select a row first");
            return;
        }

        if (!_confirm.Confirm(
                I18n.T("HostsRedirect_RemoveTitle", "Remove domain pin"),
                I18n.T("HostsRedirect_RemoveConfirm",
                    "Remove the managed {0} → {1} mapping from the Windows hosts file?", row.Domain, row.Ip)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("HostsRedirect_RemoveAction", "Remove domain pin"), async () =>
        {
            var ack = await _client.Hosts.RemoveRedirectAsync(new DomainRequest { Domain = row.Domain });
            await RefreshRedirectsCoreAsync();
            StatusText = ack.Message;
        });
    }

    private async Task RefreshRedirectsCoreAsync()
    {
        var list = await _client.Hosts.ListRedirectsAsync(new Empty());
        Redirects.Clear();
        foreach (var redirect in list.Redirects)
        {
            Redirects.Add(HostsRedirectViewModel.From(redirect));
        }
    }
}

public sealed class HostsRedirectViewModel
{
    public string Domain { get; init; } = string.Empty;

    public string Ip { get; init; } = string.Empty;

    public string Modified { get; init; } = string.Empty;

    public static HostsRedirectViewModel From(ManagedRedirect redirect) => new()
    {
        Domain = redirect.Domain,
        Ip = redirect.Ip,
        Modified = redirect.Modified is null
            ? string.Empty
            : redirect.Modified.ToDateTime().ToLocalTime().ToString("g"),
    };
}

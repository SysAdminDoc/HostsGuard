using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

/// <summary>
/// Raw hosts-file editor. Reads through the service (parity with what the
/// engine sees) and saves through the transactional engine so tamper detection
/// keeps recognizing our own writes.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class RawHostsViewModel : ObservableObject
{
    private readonly HostsServiceClient _client;
    private string _loadedText = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsDirty))]
    private string _text = string.Empty;

    [ObservableProperty]
    private string _statusText = "Ready";

    public RawHostsViewModel(HostsServiceClient client)
        => _client = client ?? throw new ArgumentNullException(nameof(client));

    public bool IsDirty => !string.Equals(Text, _loadedText, StringComparison.Ordinal);

    [RelayCommand]
    public async Task LoadAsync()
    {
        var result = await _client.Hosts.GetHostsTextAsync(new Empty());
        _loadedText = result.Text;
        Text = result.Text;
        StatusText = $"{Text.Split('\n').Length} lines";
        OnPropertyChanged(nameof(IsDirty));
    }

    [RelayCommand]
    public async Task SaveAsync()
    {
        var ack = await _client.Hosts.SetHostsTextAsync(new HostsText { Text = Text });
        StatusText = ack.Message;
        if (ack.Ok)
        {
            await LoadAsync();
        }
    }
}

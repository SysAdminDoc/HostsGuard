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
    [NotifyCanExecuteChangedFor(nameof(SaveCommand))]
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
        SaveCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand(CanExecute = nameof(CanSave))]
    public async Task SaveAsync()
    {
        var ack = await _client.Hosts.SetHostsTextAsync(new HostsText { Text = Text });
        StatusText = ack.Message;
        if (ack.Ok)
        {
            await LoadAsync();
        }
    }

    private bool CanSave() => IsDirty;

    /// <summary>AI-categorize the hosts file's entries and reload the organized text.</summary>
    [RelayCommand]
    public async Task AiCategorizeAsync()
    {
        StatusText = "Asking DeepSeek to categorize hosts-file entries…";
        var result = await _client.Hosts.CategorizeDomainsAsync(new CategorizeRequest { HostsFile = true });
        StatusText = result.Message;
        if (result.Ok && result.Categorized > 0)
        {
            await LoadAsync();
            StatusText = result.Message; // keep the outcome over the line count
        }
    }
}

using System.Windows;

namespace HostsGuard.App.Services;

/// <summary>
/// Shared destructive-action confirm flow (port of the Python <c>_confirm</c>).
/// Every delete/reset/remove path routes through this seam so view-model tests
/// can prove no destructive call is reachable without confirmation.
/// </summary>
public interface IConfirm
{
    bool Confirm(string title, string message);
}

/// <summary>Production confirm: a modal Yes/No prompt, defaulting to No.</summary>
public sealed class MessageBoxConfirm : IConfirm
{
    public bool Confirm(string title, string message)
        => MessageBox.Show(message, title, MessageBoxButton.YesNo, MessageBoxImage.Warning,
            MessageBoxResult.No) == MessageBoxResult.Yes;
}

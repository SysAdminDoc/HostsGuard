using HostsGuard.App;

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

/// <summary>Production confirm: a themed modal prompt, defaulting to Cancel.</summary>
public sealed class MessageBoxConfirm : IConfirm
{
    public bool Confirm(string title, string message)
        => ConfirmDialog.Confirm(title, message);
}

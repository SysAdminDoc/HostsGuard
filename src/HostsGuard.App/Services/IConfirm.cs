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

/// <summary>
/// Canonical destructive-mutation prompt. Keeping target and consequence as
/// separate required fields prevents terse action labels from becoming the
/// only guardrail around data or policy changes.
/// </summary>
public sealed record MutationConfirmation(string Title, string Target, string Consequence)
{
    public bool Request(IConfirm confirm)
    {
        ArgumentNullException.ThrowIfNull(confirm);
        ArgumentException.ThrowIfNullOrWhiteSpace(Title);
        ArgumentException.ThrowIfNullOrWhiteSpace(Target);
        ArgumentException.ThrowIfNullOrWhiteSpace(Consequence);
        return confirm.Confirm(Title, I18n.T(
            "Mutation_ConfirmMessage",
            "Target: {0}{2}{2}{1}{2}{2}Continue?",
            Target,
            Consequence,
            Environment.NewLine));
    }
}

/// <summary>Production confirm: a themed modal prompt, defaulting to Cancel.</summary>
public sealed class MessageBoxConfirm : IConfirm
{
    public bool Confirm(string title, string message)
        => ConfirmDialog.Confirm(title, message);
}

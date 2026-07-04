namespace HostsGuard.App.Services;

/// <summary>
/// Single-line text-input seam (mirrors <see cref="IConfirm"/>) so ViewModels can
/// ask the user for a value — e.g. the NET-107 right-click "fix category/purpose"
/// correction — while staying headless-testable.
/// </summary>
public interface IPrompt
{
    /// <summary>Prompt for a line of text; null when the user cancels.</summary>
    string? Ask(string title, string message, string defaultValue = "");
}

/// <summary>Production prompt: a themed modal input dialog.</summary>
public sealed class InputDialogPrompt : IPrompt
{
    public string? Ask(string title, string message, string defaultValue = "")
        => InputDialog.Ask(title, message, defaultValue);
}

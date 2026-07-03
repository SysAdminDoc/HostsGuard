namespace HostsGuard.App.Services;

/// <summary>
/// File-selection seam so ViewModels stay headless-testable (mirrors IConfirm).
/// The WPF implementation opens the standard Open/Save dialogs.
/// </summary>
public interface IFilePicker
{
    /// <summary>Pick an existing file; null when the user cancels.</summary>
    string? PickFile(string title, string? initialPath = null, string? filter = null);

    /// <summary>Pick a destination path to write; null when the user cancels.</summary>
    string? SaveFile(string title, string defaultName, string? filter = null);
}

/// <summary>Open/SaveFileDialog-backed picker used by the running app.</summary>
public sealed class DialogFilePicker : IFilePicker
{
    private const string DefaultFilter = "All files (*.*)|*.*";

    public string? PickFile(string title, string? initialPath = null, string? filter = null)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = title,
            Filter = filter ?? "Programs (*.exe)|*.exe|All files (*.*)|*.*",
            CheckFileExists = true,
        };
        if (!string.IsNullOrEmpty(initialPath))
        {
            try
            {
                var dir = System.IO.Path.GetDirectoryName(initialPath);
                if (!string.IsNullOrEmpty(dir) && System.IO.Directory.Exists(dir))
                {
                    dialog.InitialDirectory = dir;
                }

                dialog.FileName = System.IO.Path.GetFileName(initialPath);
            }
            catch (ArgumentException)
            {
                // Malformed old path — open with defaults.
            }
        }

        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    public string? SaveFile(string title, string defaultName, string? filter = null)
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = title,
            FileName = defaultName,
            Filter = filter ?? DefaultFilter,
            OverwritePrompt = true,
        };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }
}

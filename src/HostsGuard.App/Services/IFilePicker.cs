namespace HostsGuard.App.Services;

/// <summary>
/// File-selection seam so ViewModels stay headless-testable (mirrors IConfirm).
/// The WPF implementation opens a standard OpenFileDialog.
/// </summary>
public interface IFilePicker
{
    /// <summary>Pick an existing file; null when the user cancels.</summary>
    string? PickFile(string title, string? initialPath = null);
}

/// <summary>OpenFileDialog-backed picker used by the running app.</summary>
public sealed class DialogFilePicker : IFilePicker
{
    public string? PickFile(string title, string? initialPath = null)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = title,
            Filter = "Programs (*.exe)|*.exe|All files (*.*)|*.*",
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
}

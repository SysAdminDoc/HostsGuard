using System.Windows;

namespace HostsGuard.App;

/// <summary>Themed single-line text-input modal (NET-107 correction path).</summary>
public partial class InputDialog : Window
{
    public InputDialog(string title, string message, string defaultValue)
    {
        InitializeComponent();
        Title = title;
        TitleText.Text = title;
        MessageText.Text = message;
        InputBox.Text = defaultValue ?? string.Empty;
        Loaded += (_, _) =>
        {
            InputBox.SelectAll();
            InputBox.Focus();
        };
    }

    /// <summary>The value entered (valid only when ShowDialog returned true).</summary>
    public string Value => InputBox.Text.Trim();

    public static string? Ask(string title, string message, string defaultValue = "")
    {
        var dialog = new InputDialog(title, message, defaultValue);
        var owner = Application.Current?.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive);
        if (owner is not null && !ReferenceEquals(owner, dialog))
        {
            dialog.Owner = owner;
        }

        return dialog.ShowDialog() == true ? dialog.Value : null;
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }
}

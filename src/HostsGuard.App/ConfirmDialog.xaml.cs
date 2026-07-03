using System.Windows;

namespace HostsGuard.App;

/// <summary>Tokenized confirmation surface for destructive policy changes.</summary>
public partial class ConfirmDialog : Window
{
    public ConfirmDialog(string title, string message)
    {
        InitializeComponent();
        Title = title;
        TitleText.Text = title;
        MessageText.Text = message;
        CancelButton.Focus();
    }

    public static bool Confirm(string title, string message)
    {
        var dialog = new ConfirmDialog(title, message);
        var owner = Application.Current?.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive);
        if (owner is not null && !ReferenceEquals(owner, dialog))
        {
            dialog.Owner = owner;
        }

        return dialog.ShowDialog() == true;
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void OnConfirm(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }
}

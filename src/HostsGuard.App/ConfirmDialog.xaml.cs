using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Shapes;
using HostsGuard.App.Services;

namespace HostsGuard.App;

/// <summary>Tokenized confirmation surface for destructive policy changes.</summary>
public partial class ConfirmDialog : Window
{
    public ConfirmDialog(string title, string message)
        : this(title, message, ThemedDialogKind.Confirmation)
    {
    }

    internal ConfirmDialog(string title, string message, ThemedDialogKind kind)
    {
        InitializeComponent();
        Title = title;
        TitleText.Text = title;
        MessageText.Text = message;
        if (kind == ThemedDialogKind.Confirmation)
        {
            CancelButton.Focus();
            return;
        }

        AutomationProperties.SetName(this, title);
        ActionNote.Visibility = Visibility.Collapsed;
        CancelButton.Visibility = Visibility.Collapsed;
        ConfirmButton.Content = I18n.T("Dialog_Ok", "OK");
        ConfirmButton.IsDefault = true;
        ConfirmButton.SetResourceReference(StyleProperty, "Hg.AccentButton");
        if (kind == ThemedDialogKind.Warning)
        {
            IconBorder.SetResourceReference(Border.BackgroundProperty, "Hg.WarnSoft");
            IconBorder.SetResourceReference(Border.BorderBrushProperty, "Hg.Yellow");
            IconPath.SetResourceReference(Shape.StrokeProperty, "Hg.Yellow");
        }

        ConfirmButton.Focus();
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

    public static void ShowAlert(
        string title,
        string message,
        ThemedDialogKind kind,
        Window? owner = null)
    {
        if (kind == ThemedDialogKind.Confirmation)
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        var dialog = new ConfirmDialog(title, message, kind);
        owner ??= Application.Current?.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive);
        if (owner is not null && !ReferenceEquals(owner, dialog))
        {
            dialog.Owner = owner;
        }

        _ = dialog.ShowDialog();
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

public enum ThemedDialogKind
{
    Confirmation,
    Warning,
    Error,
}

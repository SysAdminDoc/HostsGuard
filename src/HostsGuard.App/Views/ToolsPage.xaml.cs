using System.Windows;
using HostsGuard.App.ViewModels;

namespace HostsGuard.App.Views;

public partial class ToolsPage : MajorTabPage
{
    public ToolsPage() => InitializeComponent();

    private void OnLockPasswordSync(object sender, RoutedEventArgs e)
    {
        if (ToolsSurface.DataContext is ToolsViewModel tools)
        {
            tools.LockPassword = LockPasswordBox.Password;
            LockPasswordBox.Clear();
        }
    }

    private void OnAiKeySync(object sender, RoutedEventArgs e)
    {
        if (ToolsSurface.DataContext is ToolsViewModel tools)
        {
            tools.AiApiKey = AiKeyBox.Password;
            AiKeyBox.Clear();
        }
    }
}

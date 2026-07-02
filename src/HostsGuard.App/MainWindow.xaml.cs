using System.ComponentModel;
using System.Windows;
using HostsGuard.App.ViewModels;

namespace HostsGuard.App;

/// <summary>
/// Shell window: five tabs, status bar, tray icon. Closing hides to the tray;
/// the tray menu's Exit quits for real.
/// </summary>
public partial class MainWindow : Window
{
    private bool _exiting;

    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_exiting)
        {
            e.Cancel = true;
            Hide();
            return;
        }

        Tray.Dispose();
        base.OnClosing(e);
    }

    private void OnTrayOpen(object sender, RoutedEventArgs e)
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void OnTrayExit(object sender, RoutedEventArgs e)
    {
        _exiting = true;
        Close();
        Application.Current.Shutdown();
    }
}

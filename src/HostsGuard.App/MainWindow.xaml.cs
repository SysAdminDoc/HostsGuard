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
        viewModel.DecisionRequested += OnDecisionRequested;
    }

    /// <summary>Consent prompt push (WFCP-011): raised on the UI thread by the VM.</summary>
    private void OnDecisionRequested(Contracts.ConnectionDecisionRequest request)
    {
        var window = new ConsentWindow(request);
        window.ShowDialog();
        if (window.Result is { } decision && DataContext is MainViewModel vm)
        {
            _ = vm.SendDecisionAsync(decision);
        }
    }

    private void OnTrayMode(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string mode } && DataContext is MainViewModel vm)
        {
            _ = vm.SetFilteringModeAsync(mode);
        }
    }

    private void OnTrayGlobalMode(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string mode } && DataContext is MainViewModel vm)
        {
            _ = vm.SetGlobalModeAsync(mode);
        }
    }

    /// <summary>PasswordBox can't bind — push its value to the VM before the lock command runs.</summary>
    private void OnLockPasswordSync(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel { Tools: { } tools } && LockPasswordBox is not null)
        {
            tools.LockPassword = LockPasswordBox.Password;
        }
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

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

    /// <summary>
    /// WPF quirk guard: a grouped DataGrid first measured while its tab is not
    /// selected can clamp every column to MinWidth and never recover. Re-assert
    /// the declared widths whenever the grid becomes visible.
    /// </summary>
    private void OnConnectionsGridVisible(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (sender is not System.Windows.Controls.DataGrid grid || !grid.IsVisible)
        {
            return;
        }

        _ = RepairColumnWidthsAsync(grid);

        static async Task RepairColumnWidthsAsync(System.Windows.Controls.DataGrid grid)
        {
            for (var attempt = 0; attempt < 8; attempt++)
            {
                await Task.Delay(150);
                try
                {
                    if (!grid.IsVisible || grid.Columns.All(c => c.ActualWidth > c.MinWidth))
                    {
                        return;
                    }

                    // Step 1: revive the internal scroll host. Until the rows
                    // presenter re-registers, GetViewportWidthForColumns()
                    // reports 0 and every recompute clamps to MinWidth again.
                    (grid.Template?.FindName("DG_ScrollViewer", grid) as System.Windows.Controls.ScrollViewer)
                        ?.InvalidateScrollInfo();
                    InvalidateSubtree(grid);
                    grid.UpdateLayout();

                    // Step 2: rerun the width computation against the revived
                    // viewport. No public API triggers it, hence reflection.
                    grid.Columns.GetType()
                        .GetMethod("InvalidateColumnWidthsComputation",
                            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                        ?.Invoke(grid.Columns, null);
                    grid.UpdateLayout();
                }
                catch (Exception ex) when (ex is System.Reflection.TargetInvocationException or InvalidOperationException)
                {
                    // Best-effort repair — a failed attempt must never take the
                    // shell down; the next attempt (or a manual resize) retries.
                }
            }
        }

        static void InvalidateSubtree(DependencyObject node)
        {
            for (var i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(node); i++)
            {
                var child = System.Windows.Media.VisualTreeHelper.GetChild(node, i);
                if (child is UIElement el)
                {
                    el.InvalidateMeasure();
                    el.InvalidateArrange();
                }

                InvalidateSubtree(child);
            }
        }
    }

    /// <summary>Reflect the current filtering mode as a checkmark when the tray menu opens.</summary>
    private void OnTrayMenuOpened(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
        {
            TrayModeNormal.IsChecked = vm.FilteringMode == "normal";
            TrayModeNotify.IsChecked = vm.FilteringMode == "notify";
            TrayModeLearning.IsChecked = vm.FilteringMode == "learning";
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

using System.ComponentModel;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;

namespace HostsGuard.App;

/// <summary>
/// Shell window: five tabs, status bar, tray icon. Closing hides to the tray;
/// the tray menu's Exit quits for real.
/// </summary>
public partial class MainWindow : Window
{
    private const int DwmwaUseImmersiveDarkMode = 20;
    private const int DwmwaUseImmersiveDarkModeBefore20H1 = 19;
    private bool _exiting;

    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        viewModel.DecisionRequested += OnDecisionRequested;
        viewModel.PropertyChanged += OnViewModelPropertyChanged;

        // WPF DataGrids don't select a row on right-click, so every context menu
        // bound to SelectedItem/SelectedItems would act on the previously
        // left-clicked row — e.g. "Hide domain" hid the wrong row and the one you
        // right-clicked stayed. Select the row under the pointer before the menu
        // opens (Explorer semantics: a right-click inside an existing
        // multi-selection is preserved). One window-level handler covers every grid.
        AddHandler(PreviewMouseRightButtonDownEvent,
            new System.Windows.Input.MouseButtonEventHandler(OnRightButtonSelectRow),
            handledEventsToo: true);
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(
        IntPtr hwnd,
        int dwAttribute,
        ref int pvAttribute,
        int cbAttribute);

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        ApplyNativeTitleBarTheme();
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.Theme))
        {
            ApplyNativeTitleBarTheme();
        }
    }

    private void ApplyNativeTitleBarTheme()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763))
        {
            return;
        }

        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd == IntPtr.Zero)
        {
            return;
        }

        var dark = DataContext is MainViewModel { Theme: "dark" };
        var value = dark ? 1 : 0;
        _ = DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref value, sizeof(int));
        _ = DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkModeBefore20H1, ref value, sizeof(int));
    }

    private static void OnRightButtonSelectRow(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        var node = e.OriginalSource as DependencyObject;
        while (node is not null and not System.Windows.Controls.DataGridRow)
        {
            node = System.Windows.Media.VisualTreeHelper.GetParent(node);
        }

        if (node is System.Windows.Controls.DataGridRow { IsSelected: false } row
            && System.Windows.Controls.ItemsControl.ItemsControlFromItemContainer(row)
                is System.Windows.Controls.DataGrid grid)
        {
            grid.UnselectAll();
            row.IsSelected = true;
        }
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
        if (sender is FrameworkElement { Tag: string tag } && DataContext is MainViewModel vm)
        {
            // "learning:15" arms a time-boxed Learning window (NET-101); plain
            // "learning"/"notify"/"normal" keep the existing behavior.
            var parts = tag.Split(':', 2);
            var minutes = parts.Length == 2 && int.TryParse(parts[1], out var m) ? m : 0;
            _ = vm.SetFilteringModeAsync(parts[0], minutes);
        }
    }

    /// <summary>
    /// WPF quirk guard: a DataGrid first measured while its tab is not selected
    /// (or before the service populates rows) can clamp every column to MinWidth
    /// and never recover — the "smushed" view. Re-assert the declared widths
    /// whenever a grid becomes visible. Attached to every primary tab grid.
    /// </summary>
    private void OnGridVisible(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (sender is not System.Windows.Controls.DataGrid grid || !grid.IsVisible)
        {
            return;
        }

        _ = DataGridWidthRepair.RepairAsync(grid);
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

    /// <summary>
    /// PasswordBox can't bind — copy its value to the VM before the lock command
    /// runs (Click fires before Command), then clear the box so the masked
    /// password doesn't linger on screen after arm/disarm/unlock.
    /// </summary>
    private void OnLockPasswordSync(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel { Tools: { } tools } && LockPasswordBox is not null)
        {
            tools.LockPassword = LockPasswordBox.Password;
            LockPasswordBox.Clear();
        }
    }

    /// <summary>Push the AI API key to the VM before saving, then clear the box.</summary>
    private void OnAiKeySync(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel { Tools: { } tools } && AiKeyBox is not null)
        {
            tools.AiApiKey = AiKeyBox.Password;
            AiKeyBox.Clear();
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

        // Exiting for real: warn before discarding unsaved raw hosts-file edits.
        if (DataContext is MainViewModel { RawHosts.IsDirty: true }
            && !ConfirmDialog.Confirm("Discard unsaved changes",
                "The Raw Editor has unsaved hosts-file edits. Exit and discard them?"))
        {
            e.Cancel = true;
            _exiting = false; // stay open; the app returns to normal
            return;
        }

        Tray.Dispose();
        if (DataContext is MainViewModel vm)
        {
            vm.PropertyChanged -= OnViewModelPropertyChanged;
        }

        base.OnClosing(e);
    }

    private void OnAbout(object sender, RoutedEventArgs e)
    {
        var version = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion.Split('+')[0] ?? "unknown";
        MessageBox.Show(
            $"HostsGuard v{version}\n\nSplit-trust Windows network-privacy manager: hosts-file blocking, "
            + "firewall control, live DNS/connection monitoring, and outbound consent prompts.",
            "About HostsGuard", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void OnOpenGitHub(object sender, RoutedEventArgs e)
        => System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://github.com/SysAdminDoc/HostsGuard")
        {
            UseShellExecute = true,
        });

    private void OnClearActivitySelection(object sender, RoutedEventArgs e)
    {
        ActivityGrid.SelectedItem = null;
        ActivityGrid.UnselectAll();
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
        // OnClosing resets _exiting to false if the user cancels (unsaved edits),
        // so only shut down when the close actually went through.
        if (_exiting)
        {
            Application.Current.Shutdown();
        }
    }
}

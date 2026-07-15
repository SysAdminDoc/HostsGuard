using System.Windows;
using System.Windows.Controls;
using HostsGuard.App.Services;

namespace HostsGuard.App.Views;

/// <summary>Shared interaction plumbing for independently rendered primary pages.</summary>
public class MajorTabPage : UserControl
{
    /// <summary>Repairs star/auto columns after a hidden tab first becomes visible.</summary>
    protected void OnGridVisible(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (sender is DataGrid { IsVisible: true } grid)
        {
            _ = DataGridWidthRepair.RepairAsync(grid);
        }
    }
}

using System.Windows;

namespace HostsGuard.App.Views;

public partial class HostsActivityPage : MajorTabPage
{
    public HostsActivityPage() => InitializeComponent();

    private void OnClearActivitySelection(object sender, RoutedEventArgs e)
    {
        ActivityGrid.SelectedItem = null;
        ActivityGrid.UnselectAll();
    }
}

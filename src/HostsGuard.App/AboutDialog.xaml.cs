using System.Diagnostics;
using System.Reflection;
using System.Windows;
using HostsGuard.App.Services;

namespace HostsGuard.App;

/// <summary>Product identity, architecture, and release metadata.</summary>
public partial class AboutDialog : Window
{
    private const string RepositoryUrl = "https://github.com/SysAdminDoc/HostsGuard";

    public AboutDialog()
    {
        InitializeComponent();
        var version = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion.Split('+')[0] ?? "unknown";
        VersionText.Text = I18n.T("About_VersionFormat", "v{0} | .NET 10 | Windows", version);
        Loaded += (_, _) => CloseButton.Focus();
    }

    private void OnOpenGitHub(object sender, RoutedEventArgs e)
        => Process.Start(new ProcessStartInfo(RepositoryUrl) { UseShellExecute = true });

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}

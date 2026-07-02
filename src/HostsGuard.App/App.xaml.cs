using System.IO;
using System.Windows;
using System.Windows.Threading;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace HostsGuard.App;

/// <summary>
/// Unelevated WPF shell. Composition root: builds the DI container, loads the
/// persisted theme/scale, shows the main window, and starts the (non-fatal)
/// service connection. All privileged work stays behind the named-pipe client.
/// </summary>
public partial class App : Application
{
    private ServiceProvider? _provider;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandledException;

        var services = new ServiceCollection();
        services.AddSingleton<AppConfigStore>();
        services.AddSingleton<ThemeManager>();
        services.AddSingleton<IConfirm, MessageBoxConfirm>();
        services.AddSingleton<IFilePicker, DialogFilePicker>();
        services.AddSingleton(sp => new MainViewModel(
            HostsServiceClient.Connect,
            sp.GetRequiredService<AppConfigStore>(),
            sp.GetRequiredService<ThemeManager>(),
            sp.GetRequiredService<IConfirm>(),
            sp.GetRequiredService<IFilePicker>()));
        services.AddSingleton<MainWindow>();
        _provider = services.BuildServiceProvider();

        var config = _provider.GetRequiredService<AppConfigStore>();
        config.Load();
        _provider.GetRequiredService<ThemeManager>().Apply(config.Theme);

        var window = _provider.GetRequiredService<MainWindow>();
        window.Show();

        var main = _provider.GetRequiredService<MainViewModel>();
        _ = main.ConnectCommand.ExecuteAsync(null);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _provider?.Dispose();
        base.OnExit(e);
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "HostsGuard", "logs");
            Directory.CreateDirectory(dir);
            File.AppendAllText(
                Path.Combine(dir, "app_crash.log"),
                $"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}] {e.Exception}{Environment.NewLine}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Crash logging is best-effort; the MessageBox below still surfaces it.
        }

        MessageBox.Show(e.Exception.Message, "HostsGuard — unexpected error",
            MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}

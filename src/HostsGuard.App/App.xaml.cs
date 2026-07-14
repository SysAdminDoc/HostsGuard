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
        var uiSmoke = UiSmokeOptions.FromArgs(e.Args);

        var services = new ServiceCollection();
        services.AddSingleton<AppConfigStore>();
        services.AddSingleton<ThemeManager>();
        services.AddSingleton<IConfirm, MessageBoxConfirm>();
        services.AddSingleton<IFilePicker, DialogFilePicker>();
        services.AddSingleton<IPrompt, InputDialogPrompt>();
        services.AddSingleton<IReleaseUpdateChecker>(_ => ReleaseUpdateChecker.CreateDefault());
        services.AddSingleton(sp => new MainViewModel(
            HostsServiceClient.Connect,
            sp.GetRequiredService<AppConfigStore>(),
            sp.GetRequiredService<ThemeManager>(),
            sp.GetRequiredService<IConfirm>(),
            sp.GetRequiredService<IFilePicker>(),
            sp.GetRequiredService<IPrompt>(),
            sp.GetRequiredService<IReleaseUpdateChecker>()));
        services.AddSingleton<MainWindow>();
        _provider = services.BuildServiceProvider();

        var config = _provider.GetRequiredService<AppConfigStore>();
        config.Load();
        // Fix the UI culture before any window is built — the Loc markup extension
        // resolves at load time, so a language change applies on next launch (NET-098).
        ApplyCulture(uiSmoke.LocaleOverride ?? config.Language);
        var theme = uiSmoke.ThemeOverride ?? config.Theme;
        var themeManager = _provider.GetRequiredService<ThemeManager>();
        themeManager.Apply(theme);
        themeManager.StartWatching();

        var main = _provider.GetRequiredService<MainViewModel>();
        if (uiSmoke.ThemeOverride is not null)
        {
            main.Theme = theme;
        }

        var window = _provider.GetRequiredService<MainWindow>();
        if (uiSmoke.Background)
        {
            window.WindowStartupLocation = WindowStartupLocation.Manual;
            window.Left = -32000;
            window.Top = -32000;
            window.Width = uiSmoke.Width;
            window.Height = uiSmoke.Height;
            window.ShowActivated = false;
            window.ShowInTaskbar = false;
        }

        window.Show();
        if (uiSmoke.VisualSmokeOutputDir is not null)
        {
            main.PrepareVisualSmokeFixture();
            _ = RunVisualSmokeAsync(window, uiSmoke, theme);
            return;
        }

        _ = main.ConnectCommand.ExecuteAsync(null);
    }

    private async Task RunVisualSmokeAsync(MainWindow window, UiSmokeOptions uiSmoke, string theme)
    {
        try
        {
            var exitCode = await VisualSmokeRunner.RunAsync(
                window,
                uiSmoke.VisualSmokeOutputDir!,
                theme,
                System.Globalization.CultureInfo.CurrentUICulture.Name,
                uiSmoke.Width,
                uiSmoke.Height,
                uiSmoke.SettleMs,
                CancellationToken.None);
            Shutdown(exitCode);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            VisualSmokeRunner.WriteFailure(uiSmoke.VisualSmokeOutputDir!, ex);
            Shutdown(2);
        }
    }

    private sealed record UiSmokeOptions(
        bool Background,
        string? ThemeOverride,
        string? LocaleOverride,
        int Width,
        int Height,
        int SettleMs,
        string? VisualSmokeOutputDir)
    {
        public static UiSmokeOptions FromArgs(IReadOnlyList<string> args)
        {
            var background = false;
            string? theme = null;
            string? locale = null;
            var width = 1600;
            var height = 1000;
            var settleMs = 1200;
            string? visualSmokeOutputDir = null;

            foreach (var arg in args)
            {
                if (string.Equals(arg, "--uia-background", StringComparison.OrdinalIgnoreCase))
                {
                    background = true;
                    continue;
                }

                if (arg.StartsWith("--theme=", StringComparison.OrdinalIgnoreCase))
                {
                    var value = arg["--theme=".Length..].Trim().ToLowerInvariant();
                    theme = value is "light" or "contrast-aquatic" or "contrast-desert" or "contrast-dusk" or "contrast-night-sky"
                        ? value
                        : "dark";
                    continue;
                }

                if (arg.StartsWith("--locale=", StringComparison.OrdinalIgnoreCase))
                {
                    var value = arg["--locale=".Length..].Trim();
                    locale = value is "en" or "es" or "de" or "fr" or "qps-ploc" ? value : null;
                    continue;
                }

                if (arg.StartsWith("--size=", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = arg["--size=".Length..].Split('x', 2, StringSplitOptions.TrimEntries);
                    if (parts.Length == 2
                        && int.TryParse(parts[0], out var parsedWidth)
                        && int.TryParse(parts[1], out var parsedHeight))
                    {
                        width = Math.Clamp(parsedWidth, 1080, 4096);
                        height = Math.Clamp(parsedHeight, 680, 2160);
                    }
                    continue;
                }

                if (arg.StartsWith("--visual-smoke-settle-ms=", StringComparison.OrdinalIgnoreCase))
                {
                    var value = arg["--visual-smoke-settle-ms=".Length..].Trim();
                    if (int.TryParse(value, out var parsedSettleMs))
                    {
                        settleMs = Math.Clamp(parsedSettleMs, 50, 10000);
                    }
                    continue;
                }

                if (arg.StartsWith("--visual-smoke-output=", StringComparison.OrdinalIgnoreCase))
                {
                    var value = arg["--visual-smoke-output=".Length..].Trim();
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        visualSmokeOutputDir = value;
                    }
                }
            }

            return new UiSmokeOptions(background, theme, locale, width, height, settleMs, visualSmokeOutputDir);
        }
    }

    /// <summary>Pin the UI culture from the persisted language tag ("" = system).</summary>
    private static void ApplyCulture(string tag)
    {
        if (string.IsNullOrWhiteSpace(tag))
        {
            return;
        }

        try
        {
            var culture = System.Globalization.CultureInfo.GetCultureInfo(tag);
            System.Globalization.CultureInfo.CurrentUICulture = culture;
            System.Globalization.CultureInfo.DefaultThreadCurrentUICulture = culture;
        }
        catch (System.Globalization.CultureNotFoundException)
        {
            // Unknown tag — fall back to the Windows display language.
        }
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

        // A dropped service connection surfaces as a gRPC/pipe error — show a calm,
        // actionable message instead of a raw "StatusCode=Unavailable" dump.
        // Handler-side failures (StatusCode.Unknown) are NOT connectivity: the
        // service is up, so don't tell the user to restart it.
        var (message, title, icon) = Services.ServiceErrors.IsConnectivity(e.Exception)
            ? ("HostsGuard can't reach its background service. It may be starting, stopped, or restarting — "
               + "wait a moment and try again, or reopen HostsGuard.",
               "HostsGuard — service unavailable", MessageBoxImage.Warning)
            : (Services.ServiceErrors.Describe(e.Exception), "HostsGuard — action failed", MessageBoxImage.Error);

        MessageBox.Show(message, title, MessageBoxButton.OK, icon);
        e.Handled = true;
    }
}

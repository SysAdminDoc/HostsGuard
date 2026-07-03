using System.IO;
using System.Windows;
using FluentAssertions;
using HostsGuard.App;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Contracts;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>
/// NET-060 headless WPF smoke: construct the full main window and the consent
/// window in BOTH themes on an STA thread, without a service and without
/// showing anything — every XAML parse error, missing resource key, or broken
/// binding path in a template throws here instead of at first launch.
/// </summary>
public sealed class WpfSmokeTests
{
    private static volatile string _stage = "not started";

    private static void RunSta(Action action)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            finally
            {
                // Kill the thread's dispatcher without pumping: a smoke never
                // starts Application.Run, so a shutdown *pump* would hang.
                System.Windows.Threading.Dispatcher.CurrentDispatcher.InvokeShutdown();
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join(TimeSpan.FromSeconds(120)).Should().BeTrue($"the STA smoke must not hang (stage: {_stage})");
        failure.Should().BeNull();
    }

    private static ResourceDictionary Load(string name) => new()
    {
        Source = new Uri($"pack://application:,,,/HostsGuard.App;component/Themes/{name}.xaml"),
    };

    [Fact]
    public void Every_window_constructs_in_both_themes_without_a_service()
    {
        RunSta(() =>
        {
            _stage = "creating Application";
            var app = Application.Current ?? new Application
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown,
            };
            foreach (var theme in new[] { "Dark", "Light" })
            {
                _stage = $"loading {theme} theme";
                app.Resources.MergedDictionaries.Clear();
                app.Resources.MergedDictionaries.Add(Load(theme));
                app.Resources.MergedDictionaries.Add(Load("Styles"));

                // Shell: real VM graph over a lazy (never-connected) channel.
                _stage = $"{theme}: building view-models";
                var client = new HostsServiceClient(NamedPipeChannel.Create(SessionToken.Generate(), "hg-smoke-none"));
                var config = new AppConfigStore(Path.Combine(Path.GetTempPath(), "hg_smoke_" + Guid.NewGuid().ToString("N") + ".json"));
                var vm = new MainViewModel(() => client, config, new ThemeManager(), new FakeConfirm(true));
                vm.Hosts = new HostsViewModel(client, new FakeConfirm(true));
                vm.Activity = new HostsActivityViewModel(client);
                vm.RawHosts = new RawHostsViewModel(client);
                vm.FwActivity = new FwActivityViewModel(client, new FakeConfirm(true), config);
                vm.FwRules = new FwRulesViewModel(client, new FakeConfirm(true));
                vm.Tools = new ToolsViewModel(client, new FakeConfirm(true));
                vm.Blocklists = new BlocklistsViewModel(client, new FakeConfirm(true));

                _stage = $"{theme}: constructing MainWindow";
                var window = new MainWindow(vm);
                window.DataContext.Should().BeSameAs(vm);
                // Force template application for the whole tree. No Close():
                // the shell cancels Close into a tray-hide by design.
                _stage = $"{theme}: laying out MainWindow";
                window.Measure(new Size(1280, 800));
                window.Arrange(new Rect(0, 0, 1280, 800));
                window.UpdateLayout();

                _stage = $"{theme}: constructing ConsentWindow";
                var consent = new ConsentWindow(new ConnectionDecisionRequest
                {
                    Id = "smoke",
                    Application = @"C:\Program Files\Example\example.exe",
                    Direction = "Out",
                    RemoteAddress = "203.0.113.9",
                    RemotePort = 443,
                    Protocol = "TCP",
                    ProcessId = 4711,
                });
                consent.Measure(new Size(500, 600));
                consent.Arrange(new Rect(0, 0, 500, 600));
                consent.UpdateLayout();

                // Accessibility (NET-080): the primary action carries a screen-
                // reader name and the window itself is named.
                var allow = (System.Windows.Controls.Button)consent.FindName("AllowButton");
                System.Windows.Automation.AutomationProperties.GetName(allow).Should().Be("Allow this connection");
                System.Windows.Automation.AutomationProperties.GetName(consent)
                    .Should().Be("HostsGuard connection consent prompt");

                _stage = $"{theme}: constructing ConfirmDialog";
                var confirm = new ConfirmDialog("Delete firewall rule", "Delete HG_Test?");
                confirm.Measure(new Size(500, 260));
                confirm.Arrange(new Rect(0, 0, 500, 260));
                confirm.UpdateLayout();
                System.Windows.Automation.AutomationProperties.GetName(confirm)
                    .Should().Be("HostsGuard confirmation");

                vm.Dispose();
            }

            _stage = "done";
        });
    }
}

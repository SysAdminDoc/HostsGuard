using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
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

    private static IEnumerable<T> Descendants<T>(DependencyObject root)
        where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is T match)
            {
                yield return match;
            }

            foreach (var nested in Descendants<T>(child))
            {
                yield return nested;
            }
        }
    }

    private static IEnumerable<T> LogicalDescendants<T>(DependencyObject root)
        where T : DependencyObject
    {
        foreach (var child in LogicalTreeHelper.GetChildren(root).OfType<DependencyObject>())
        {
            if (child is T match)
            {
                yield return match;
            }

            foreach (var nested in LogicalDescendants<T>(child))
            {
                yield return nested;
            }
        }
    }

    /// <summary>
    /// NET-088 accessibility invariant: every text/combo/password input on a tab
    /// must expose an AutomationProperties.Name — those controls carry no intrinsic
    /// text, so without an explicit name a screen reader announces nothing.
    /// </summary>
    private static void AssertAllInputsNamed(Window window, TabControl tabs, int tabIndex, string theme)
    {
        var unnamed = new List<string>();
        foreach (var el in Descendants<Control>(window))
        {
            if (el is not (TextBox or ComboBox or PasswordBox))
            {
                continue;
            }

            // The editable-part TextBox inside a ComboBox template inherits its
            // name from the ComboBox — don't flag it separately.
            if (el is TextBox && el.TemplatedParent is ComboBox)
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(System.Windows.Automation.AutomationProperties.GetName(el)))
            {
                unnamed.Add(el.GetType().Name);
            }
        }

        unnamed.Should().BeEmpty(
            $"every text/combo/password input on tab {tabIndex} ({theme}) must expose an AutomationProperties.Name");
    }

    /// <summary>
    /// NET-116 accessibility conformance: an icon-only button (no textual Content)
    /// must carry an AutomationProperties.Name, and every realized DataGrid column
    /// must have a header — both are announced by screen readers, and a blank one
    /// leaves the control unlabeled. Deterministic on the realized tree, no desktop
    /// session required.
    /// </summary>
    private static void AssertTabAccessible(Window window, int tabIndex, string theme)
    {
        var iconButtons = new List<string>();
        foreach (var b in Descendants<Button>(window))
        {
            var hasText = b.Content is string s && !string.IsNullOrWhiteSpace(s);
            if (!hasText && string.IsNullOrWhiteSpace(System.Windows.Automation.AutomationProperties.GetName(b)))
            {
                iconButtons.Add(b.Name.Length != 0 ? b.Name : b.Content?.GetType().Name ?? "Button");
            }
        }

        iconButtons.Should().BeEmpty(
            $"every non-text (icon) button on tab {tabIndex} ({theme}) must expose an AutomationProperties.Name");

        var unlabeledColumns = new List<string>();
        foreach (var grid in Descendants<DataGrid>(window))
        {
            foreach (var col in grid.Columns)
            {
                if (col.Header is null || (col.Header is string h && string.IsNullOrWhiteSpace(h)))
                {
                    unlabeledColumns.Add($"{grid.Name}[{grid.Columns.IndexOf(col)}]");
                }
            }
        }

        unlabeledColumns.Should().BeEmpty(
            $"every DataGrid column on tab {tabIndex} ({theme}) must have a header label");
    }

    private static void AssertLiveStatusReadouts(Window window, int tabIndex, string theme)
    {
        var missing = new List<string>();
        foreach (var text in Descendants<TextBlock>(window))
        {
            var path = BindingOperations.GetBinding(text, TextBlock.TextProperty)?.Path?.Path;
            if (string.IsNullOrWhiteSpace(path) || !IsStatusReadout(path))
            {
                continue;
            }

            if (System.Windows.Automation.AutomationProperties.GetLiveSetting(text)
                == System.Windows.Automation.AutomationLiveSetting.Off)
            {
                missing.Add(path);
            }
        }

        missing.Should().BeEmpty(
            $"status readouts on tab {tabIndex} ({theme}) must be polite live regions");
    }

    private static bool IsStatusReadout(string bindingPath)
        => bindingPath.Equals("ConnectionText", StringComparison.Ordinal)
            || bindingPath.Equals("StatusText", StringComparison.Ordinal)
            || bindingPath.EndsWith("StatusText", StringComparison.Ordinal);

    private static void AssertVisibleEmptyStatesExplainAction(Window window, int tabIndex, string theme)
    {
        var text = LogicalDescendants<TextBlock>(window)
            .Select(block => block.Text)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToArray();

        var expected = tabIndex switch
        {
            0 => new[] { "No DNS activity yet", "HostsGuard will fill this feed" },
            1 => new[] { "No alerts yet", "Alerts appear here when HostsGuard detects" },
            2 => new[] { "No managed domains", "Add a domain above" },
            3 => new[] { "No live connections", "Connections appear here when the monitor" },
            _ => Array.Empty<string>(),
        };

        foreach (var phrase in expected)
        {
            text.Should().Contain(
                value => value.Contains(phrase, StringComparison.Ordinal),
                $"major tab {tabIndex} ({theme}) must render an explanatory empty state containing '{phrase}'");
        }

        text.Where(value =>
                value.Contains("coming soon", StringComparison.OrdinalIgnoreCase) ||
                value.Contains("premium", StringComparison.OrdinalIgnoreCase))
            .Should().BeEmpty(
                $"visible empty states on tab {tabIndex} ({theme}) must explain the next action or system condition");
    }

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

                var mainTabs = (TabControl)window.FindName("MainTabs");

                // NET-088: walk every tab and assert screen-reader names on all
                // text/combo/password inputs (also realizes each tab's template).
                for (var tab = 0; tab < mainTabs.Items.Count; tab++)
                {
                    _stage = $"{theme}: a11y-scanning tab {tab}";
                    mainTabs.SelectedIndex = tab;
                    window.UpdateLayout();
                    AssertAllInputsNamed(window, mainTabs, tab, theme);
                    AssertTabAccessible(window, tab, theme);
                    AssertLiveStatusReadouts(window, tab, theme);
                    AssertVisibleEmptyStatesExplainAction(window, tab, theme);
                }

                mainTabs.SelectedIndex = 4; // FW Rules.
                window.UpdateLayout();
                LogicalDescendants<TextBlock>(window).Select(t => t.Text)
                    .Should().Contain("Create HostsGuard rule");

                mainTabs.SelectedIndex = 5; // Tools.
                window.UpdateLayout();
                LogicalDescendants<TextBlock>(window).Select(t => t.Text)
                    .Should().Contain(t => t.StartsWith("Use a domain, service target, or fw:HG_RuleName", StringComparison.Ordinal));
                var lockPassword = (PasswordBox)window.FindName("LockPasswordBox");
                PasswordBoxHelper.GetWatermark(lockPassword).Should().Be("Enter lock password");
                PasswordBoxHelper.GetIsEmpty(lockPassword).Should().BeTrue();
                lockPassword.Template.Triggers.OfType<Trigger>()
                    .Should().Contain(t => t.Property == PasswordBoxHelper.IsEmptyProperty && Equals(t.Value, true));

                _stage = $"{theme}: constructing ConsentWindow";
                var consent = new ConsentWindow(new ConnectionDecisionRequest
                {
                    Id = "smoke",
                    Application = @"C:\Program Files\nodejs\node.exe",
                    Direction = "Out",
                    RemoteAddress = "203.0.113.9",
                    RemotePort = 443,
                    Protocol = "TCP",
                    ProcessId = 4711,
                    CommandLine = @"node C:\dev\scraper\index.js",
                    ScriptPath = @"C:\dev\scraper\index.js",
                    ScriptBindingKey = @"c:\program files\nodejs\node.exe|c:\dev\scraper\index.js",
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
                var appName = (TextBlock)consent.FindName("AppName");
                appName.Text.Should().Be(@"node C:\dev\scraper\index.js");
                var scriptScope = (CheckBox)consent.FindName("ScopeCommandLine");
                scriptScope.Visibility.Should().Be(Visibility.Visible);
                scriptScope.IsChecked.Should().BeTrue();

                _stage = $"{theme}: constructing ConfirmDialog";
                var confirm = new ConfirmDialog("Delete firewall rule", "Delete HG_Test?");
                confirm.Measure(new Size(500, 260));
                confirm.Arrange(new Rect(0, 0, 500, 260));
                confirm.UpdateLayout();
                System.Windows.Automation.AutomationProperties.GetName(confirm)
                    .Should().Be("HostsGuard confirmation");

                _stage = $"{theme}: constructing InputDialog";
                var input = new InputDialog("Assign to rule group",
                    "Group name for 2 rules (blank removes them from all groups):", "Browsers");
                input.Measure(new Size(500, 260));
                input.Arrange(new Rect(0, 0, 500, 260));
                input.UpdateLayout();
                System.Windows.Automation.AutomationProperties.GetName(input)
                    .Should().Be("HostsGuard input");
                var inputBox = (TextBox)input.FindName("InputBox");
                System.Windows.Automation.AutomationProperties.GetHelpText(inputBox)
                    .Should().Contain("blank removes");

                _stage = $"{theme}: constructing AboutDialog";
                var about = new AboutDialog();
                about.Measure(new Size(560, 520));
                about.Arrange(new Rect(0, 0, 560, 520));
                about.UpdateLayout();
                System.Windows.Automation.AutomationProperties.GetName(about)
                    .Should().Be("About HostsGuard");
                var versionText = (TextBlock)about.FindName("VersionText");
                versionText.Text.Should().StartWith("v").And.Contain(".NET 10");

                vm.Dispose();
            }

            _stage = "done";
        });
    }
}

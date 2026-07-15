using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
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
    private static readonly Lazy<Dispatcher> WpfDispatcher = new(StartWpfDispatcher);

    private static void RunSta(Action action)
    {
        Exception? failure = null;
        WpfDispatcher.Value.Invoke(() =>
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            finally { }
        });
        failure.Should().BeNull();
    }

    private static Dispatcher StartWpfDispatcher()
    {
        Dispatcher? dispatcher = null;
        using var ready = new ManualResetEventSlim();
        var thread = new Thread(() =>
        {
            dispatcher = Dispatcher.CurrentDispatcher;
            _ = Application.Current ?? new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
            ready.Set();
            Dispatcher.Run();
        })
        {
            IsBackground = true,
            Name = "HostsGuard WPF smoke dispatcher",
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        ready.Wait(TimeSpan.FromSeconds(30)).Should().BeTrue("the WPF smoke dispatcher must start");
        return dispatcher!;
    }

    [Fact]
    public void Consent_evidence_is_exact_accessible_and_collapses_when_unknown()
    {
        RunSta(() =>
        {
            Application.Current!.Resources.MergedDictionaries.Clear();
            Application.Current.Resources.MergedDictionaries.Add(Load("Dark"));
            Application.Current.Resources.MergedDictionaries.Add(Load("Styles"));

            var lan = BuildConsent(new ConnectionDecisionRequest
            {
                Application = @"C:\apps\lan.exe",
                Direction = "Out",
                RemoteAddress = "192.168.1.1",
                RemotePort = 443,
                Protocol = "TCP",
                LocalAddress = "192.168.1.10",
                LocalPort = 53117,
                InterfaceIndex = 12,
                InterfaceName = "Ethernet",
                ActiveFirewallProfiles = { "Private" },
            });
            Evidence(lan, "LocalText").Should().Be(("192.168.1.10:53117", "Local endpoint: 192.168.1.10:53117"));
            Evidence(lan, "NetworkText").Should().Be((
                "Interface: Ethernet (index 12) · Active firewall profiles: Private",
                "Network evidence: Interface: Ethernet (index 12) · Active firewall profiles: Private"));

            var loopback = BuildConsent(new ConnectionDecisionRequest
            {
                Application = @"C:\apps\loopback.exe",
                Direction = "In",
                RemoteAddress = "::1",
                RemotePort = 53000,
                Protocol = "TCP",
                LocalAddress = "::1",
                LocalPort = 8080,
            });
            Evidence(loopback, "LocalText").Should().Be(("[::1]:8080", "Local endpoint: [::1]:8080"));
            Evidence(loopback, "RemoteText").Should().Be(("[::1]:53000 (TCP)", "Remote endpoint: [::1]:53000 (TCP)"));

            var foreign = BuildConsent(new ConnectionDecisionRequest
            {
                Application = @"C:\apps\vpn.exe",
                Direction = "Out",
                RemoteAddress = "203.0.113.9",
                RemotePort = 443,
                Protocol = "TCP",
                LocalAddress = "10.8.0.4",
                LocalPort = 50100,
                InterfaceIndex = 42,
                InterfaceName = "VPN",
                FilterOwner = "External firewall rule",
                FilterOrigin = "VendorBlockRule",
                ExternalFilter = true,
                ActiveFirewallProfiles = { "Public" },
            });
            Evidence(foreign, "OriginText").Should().Be((
                "Owner: External firewall rule · Origin: VendorBlockRule",
                "WFP evidence: Owner: External firewall rule · Origin: VendorBlockRule"));

            var unknown = BuildConsent(new ConnectionDecisionRequest
            {
                Application = @"C:\apps\unknown.exe",
                Direction = "Out",
                RemoteAddress = "198.51.100.4",
                RemotePort = 53,
                Protocol = "UDP",
            });
            foreach (var name in new[] { "LocalLabel", "LocalText", "NetworkLabel", "NetworkText", "OriginLabel", "OriginText" })
            {
                ((FrameworkElement)unknown.FindName(name)).Visibility.Should().Be(Visibility.Collapsed, name);
            }

            lan.Close();
            loopback.Close();
            foreign.Close();
            unknown.Close();
        });
    }

    private static ConsentWindow BuildConsent(ConnectionDecisionRequest request)
    {
        var window = new ConsentWindow(request);
        window.Measure(new Size(540, 720));
        window.Arrange(new Rect(0, 0, 540, 720));
        window.UpdateLayout();
        return window;
    }

    private static (string Text, string AccessibleName) Evidence(ConsentWindow window, string name)
    {
        var value = (TextBlock)window.FindName(name);
        value.Visibility.Should().Be(Visibility.Visible);
        return (value.Text, AutomationProperties.GetName(value));
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
            if (b.TemplatedParent is not null)
            {
                continue;
            }

            var hasText = b.Content is string s && !string.IsNullOrWhiteSpace(s)
                || b.Content is TextBlock contentText && !string.IsNullOrWhiteSpace(contentText.Text)
                || Descendants<TextBlock>(b).Any(text => !string.IsNullOrWhiteSpace(text.Text));
            if (!hasText && string.IsNullOrWhiteSpace(System.Windows.Automation.AutomationProperties.GetName(b)))
            {
                iconButtons.Add(b.Name.Length != 0
                    ? b.Name
                    : $"{b.Content?.GetType().Name ?? "Button"} (tooltip: {b.ToolTip ?? "none"})");
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
            if (!text.IsVisible)
            {
                continue;
            }

            if (HasVisualAncestor<DataGrid>(text))
            {
                continue;
            }

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

    private static bool HasVisualAncestor<T>(DependencyObject element) where T : DependencyObject
    {
        for (var current = VisualTreeHelper.GetParent(element); current is not null;
             current = VisualTreeHelper.GetParent(current))
        {
            if (current is T)
            {
                return true;
            }
        }
        return false;
    }

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
                vm.Alerts = new AlertsViewModel(client);
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

                mainTabs.SelectedIndex = 1; // Alerts.
                var alertsTabs = (TabControl)window.FindName("AlertsTabs");
                alertsTabs.SelectedIndex = 1; // Allowlist review.
                window.UpdateLayout();
                var allowlistReviewGrid = (DataGrid)window.FindName("AllowlistReviewGrid");
                allowlistReviewGrid.CanUserSortColumns.Should().BeTrue();
                BindingOperations.GetBinding(allowlistReviewGrid, ItemsControl.ItemsSourceProperty)?.Path.Path
                    .Should().Be(nameof(AlertsViewModel.AllowlistRecommendations));
                var actionColumn = allowlistReviewGrid.Columns.OfType<DataGridTemplateColumn>().Single();
                var allowButton = (Button)actionColumn.CellTemplate.LoadContent();
                BindingOperations.GetBinding(allowButton, Button.CommandProperty)?.Path.Path
                    .Should().Be("DataContext.AllowRecommendationCommand");

                mainTabs.SelectedIndex = 4; // FW Rules.
                window.UpdateLayout();
                LogicalDescendants<TextBlock>(window).Select(t => t.Text)
                    .Should().Contain("Create HostsGuard rule");

                mainTabs.SelectedIndex = 3; // FW Activity.
                window.UpdateLayout();
                var modeGroup = (StackPanel)window.FindName("FwActivityModeGroup");
                var viewGroup = (StackPanel)window.FindName("FwActivityViewGroup");
                var searchGroup = (StackPanel)window.FindName("FwActivitySearchGroup");
                System.Windows.Automation.AutomationProperties.GetName(modeGroup).Should().Be("Mode");
                System.Windows.Automation.AutomationProperties.GetName(viewGroup).Should().Be("View");
                System.Windows.Automation.AutomationProperties.GetName(searchGroup).Should().Be("Search & explain");
                Descendants<CheckBox>(modeGroup).Should().HaveCount(5);
                Descendants<CheckBox>(viewGroup).Should().HaveCount(4);
                Descendants<Button>(viewGroup).Should().ContainSingle();
                Descendants<TextBox>(searchGroup).Should().HaveCount(2);
                Descendants<Button>(searchGroup).Should().ContainSingle();

                mainTabs.SelectedIndex = 5; // Tools.
                window.UpdateLayout();
                LogicalDescendants<TextBlock>(window).Select(t => t.Text)
                    .Should().Contain(t => t.StartsWith("Use a domain, service target, or fw:HG_RuleName", StringComparison.Ordinal));
                var lockPassword = (PasswordBox)window.FindName("LockPasswordBox");
                PasswordBoxHelper.GetWatermark(lockPassword).Should().Be("Enter lock password");
                PasswordBoxHelper.GetIsEmpty(lockPassword).Should().BeTrue();
                lockPassword.Template.Triggers.OfType<Trigger>()
                    .Should().Contain(t => t.Property == PasswordBoxHelper.IsEmptyProperty && Equals(t.Value, true));
                var aiKey = (PasswordBox)window.FindName("AiKeyBox");
                PasswordBoxHelper.GetWatermark(aiKey)
                    .Should().Be("Enter a new API key (blank keeps the stored key)");
                PasswordBoxHelper.GetIsEmpty(aiKey).Should().BeTrue();
                var aiKeyStatus = (TextBlock)window.FindName("AiKeyStorageStatus");
                BindingOperations.GetBinding(aiKeyStatus, TextBlock.TextProperty)?.Path.Path
                    .Should().Be(nameof(ToolsViewModel.AiKeyStorageText));
                var localPreview = (Button)window.FindName("LocalBlocklistPreviewButton");
                BindingOperations.GetBinding(localPreview, Button.CommandProperty)?.Path.Path
                    .Should().Be("PreviewLocalFileCommand");
                var localImport = (Button)window.FindName("LocalBlocklistImportButton");
                BindingOperations.GetBinding(localImport, Button.CommandProperty)?.Path.Path
                    .Should().Be("ImportLocalPreviewCommand");
                var localSummary = (TextBlock)window.FindName("LocalBlocklistPreviewSummary");
                BindingOperations.GetBinding(localSummary, TextBlock.TextProperty)?.Path.Path
                    .Should().Be(nameof(BlocklistsViewModel.LocalPreviewSummary));
                var resolutionChain = (ItemsControl)window.FindName("ResolutionChainItems");
                BindingOperations.GetBinding(resolutionChain, ItemsControl.ItemsSourceProperty)?.Path.Path
                    .Should().Be(nameof(ActivityRowViewModel.ResolutionChain));
                var redirectDomain = (TextBox)window.FindName("RedirectDomainInput");
                BindingOperations.GetBinding(redirectDomain, TextBox.TextProperty)?.Path.Path
                    .Should().Be(nameof(HostsViewModel.NewRedirectDomain));
                var redirectIp = (TextBox)window.FindName("RedirectIpInput");
                BindingOperations.GetBinding(redirectIp, TextBox.TextProperty)?.Path.Path
                    .Should().Be(nameof(HostsViewModel.NewRedirectIp));
                var pinRedirect = (Button)window.FindName("PinRedirectButton");
                BindingOperations.GetBinding(pinRedirect, Button.CommandProperty)?.Path.Path
                    .Should().Be("PinRedirectCommand");
                var redirectsGrid = (DataGrid)window.FindName("HostsRedirectsGrid");
                BindingOperations.GetBinding(redirectsGrid, ItemsControl.ItemsSourceProperty)?.Path.Path
                    .Should().Be(nameof(HostsViewModel.Redirects));

                var trayProfiles = (MenuItem)window.FindName("TrayProfiles");
                vm.Tools.Profiles.Add("Home");
                vm.Tools.Profiles.Add("Work");
                vm.Tools.ActiveProfileName = "Work";
                window.RenderTrayProfiles(vm.Tools, "Switching", profilesEnabled: false);
                var trayProfileItems = trayProfiles.Items.OfType<MenuItem>()
                    .Where(item => item.Tag is string)
                    .ToList();
                trayProfileItems.Should().HaveCount(2)
                    .And.OnlyContain(item => item.IsCheckable && item.StaysOpenOnClick && !item.IsEnabled);
                trayProfileItems.Single(item => Equals(item.Tag, "Work")).IsChecked.Should().BeTrue();

                window.RenderTrayProfiles(vm.Tools, "Settings are locked");
                trayProfiles.Items.OfType<MenuItem>()
                    .Should().Contain(item => !item.IsEnabled && Equals(item.Header, "Settings are locked"));

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
                ((Button)confirm.FindName("CancelButton")).IsCancel.Should().BeTrue();
                ((Button)confirm.FindName("ConfirmButton")).IsDefault.Should().BeFalse(
                    "destructive mutation prompts must default to cancel");

                var warning = new ConfirmDialog(
                    "Decision not applied",
                    "The connection stays blocked.",
                    ThemedDialogKind.Warning);
                warning.Measure(new Size(500, 220));
                warning.Arrange(new Rect(0, 0, 500, 220));
                warning.UpdateLayout();
                System.Windows.Automation.AutomationProperties.GetName(warning)
                    .Should().Be("Decision not applied");
                ((Button)warning.FindName("CancelButton")).Visibility.Should().Be(Visibility.Collapsed);
                ((Border)warning.FindName("ActionNote")).Visibility.Should().Be(Visibility.Collapsed);
                var warningAction = (Button)warning.FindName("ConfirmButton");
                warningAction.Content.Should().Be("OK");
                warningAction.IsDefault.Should().BeTrue();

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

                if (theme == "Dark")
                {
                    var priorCulture = System.Globalization.CultureInfo.CurrentUICulture;
                    System.Globalization.CultureInfo.CurrentUICulture =
                        System.Globalization.CultureInfo.GetCultureInfo("qps-ploc");
                    try
                    {
                        vm.Activity.Rows.Add(new ActivityRowViewModel { Domain = "pseudo.example", Root = "pseudo.example" });
                        var pseudoWindow = new MainWindow(vm);
                        var pseudoTabs = (TabControl)pseudoWindow.FindName("MainTabs");
                        foreach (var scale in new[] { 90, 100, 125, 150 })
                        {
                            vm.UiScalePct = scale;
                            pseudoWindow.Measure(new Size(1600, 1000));
                            pseudoWindow.Arrange(new Rect(0, 0, 1600, 1000));
                            foreach (var tab in new[] { 0, 1, 2 })
                            {
                                pseudoTabs.SelectedIndex = tab;
                                pseudoWindow.UpdateLayout();
                                VisualSmokeRunner.FindPseudoLocaleLayoutFailures(pseudoWindow, $"owned tab {tab} at {scale}%")
                                    .Should().BeEmpty();
                            }
                        }
                    }
                    finally
                    {
                        System.Globalization.CultureInfo.CurrentUICulture = priorCulture;
                    }
                }

                vm.Dispose();
            }

            _stage = "done";
        });
    }

    [Fact]
    public void Release_visual_fixture_populates_every_primary_page_without_an_rpc()
    {
        RunSta(() =>
        {
            var config = new AppConfigStore(Path.Combine(
                Path.GetTempPath(), "hg_release_visual_" + Guid.NewGuid().ToString("N") + ".json"));
            var client = new HostsServiceClient(NamedPipeChannel.Create(
                SessionToken.Generate(), "hg-release-visual-" + Guid.NewGuid().ToString("N")));
            using var vm = new MainViewModel(() => client, config, new ThemeManager(), new FakeConfirm(true));
            vm.PrepareVisualSmokeFixture();

            vm.IsConnected.Should().BeTrue();
            vm.Activity!.Rows.Should().HaveCount(2);
            vm.Alerts!.Alerts.Should().ContainSingle();
            vm.Hosts!.Domains.Should().HaveCount(2);
            vm.FwActivity!.Rows.Should().HaveCount(2);
            vm.FwRules!.Rules.Should().HaveCount(2);
            vm.Tools!.Schedules.Should().ContainSingle();
        });
    }

    [Fact]
    public void Firewall_pseudo_locale_hotspots_use_wrapping_content_at_every_supported_scale()
    {
        var xaml = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "HostsGuard.App", "MainWindow.xaml"));
        var wrappedKeys = new[]
        {
            "Xaml_Inherit_to_children_86cbf611",
            "Xaml_Inbound_prompts_a42a5e5c",
            "Xaml_Close_TCP_on_block_b15d5697",
            "Xaml_Group_by_app_8d9fabe2",
            "Xaml_Group_by_country_20629707",
            "Xaml_Explain_55cbfd1b",
            "Xaml_Per_app_activity_217dcab5",
            "Xaml_Learning_review_e304e7cd",
            "Xaml_Discard_all_5b034df8",
            "Xaml_Sound_on_block_08d731f1",
            "ListenerExposure_Title",
            "Xaml_History_bandwidth_fb9e4b19",
            "FwRules_IncludeWindowsRules",
            "Xaml_HostsGuard_rules_only_a5afd2dd",
            "RuleAnalysis_Title",
        };

        foreach (var key in wrappedKeys)
        {
            var keyIndex = xaml.IndexOf($"Key={key}", StringComparison.Ordinal);
            keyIndex.Should().BeGreaterThanOrEqualTo(0, $"{key} must remain in the firewall layout");
            var elementEnd = xaml.IndexOf("/>", keyIndex, StringComparison.Ordinal);
            xaml[keyIndex..elementEnd].Should().Contain("TextWrapping=\"Wrap\"", $"{key} must survive pseudo-locale expansion");
        }

        var interfaceStatus = xaml.IndexOf("Text=\"{Binding InterfaceAliasStatus}\"", StringComparison.Ordinal);
        var interfaceStatusEnd = xaml.IndexOf("/>", interfaceStatus, StringComparison.Ordinal);
        xaml[interfaceStatus..interfaceStatusEnd].Should().Contain("TextWrapping=\"Wrap\"");

        AppConfigStore.UiScaleChoices.Should().Contain(new[] { 90, 100, 125, 150 });
    }

    [Fact]
    public void Pseudo_locale_layout_gate_detects_untrimmed_clipping_but_allows_wrapping()
    {
        RunSta(() =>
        {
            var clipped = new TextBlock
            {
                Text = "[!! VÃ©rÃ½ lÃ³Ã±g psÃ©ÃºdÃ³-lÃ³cÃ¡lÃ­zÃ©d sÃ©ttÃ­Ã±g lÃ¡bÃ©l !!]",
                Width = 90,
                HorizontalAlignment = HorizontalAlignment.Left,
                TextWrapping = TextWrapping.NoWrap,
            };
            var root = new Grid { Width = 90, Height = 40 };
            root.Children.Add(clipped);
            root.Measure(new Size(90, 40));
            root.Arrange(new Rect(0, 0, 90, 40));
            root.UpdateLayout();

            var measuredText = new FormattedText(
                clipped.Text,
                System.Globalization.CultureInfo.CurrentUICulture,
                clipped.FlowDirection,
                new Typeface(clipped.FontFamily, clipped.FontStyle, clipped.FontWeight, clipped.FontStretch),
                clipped.FontSize,
                Brushes.Black,
                VisualTreeHelper.GetDpi(clipped).PixelsPerDip);
            measuredText.WidthIncludingTrailingWhitespace.Should().BeGreaterThan(clipped.Width + 2);

            VisualSmokeRunner.FindPseudoLocaleLayoutFailures(root, "test")
                .Should().ContainSingle().Which.Should().Contain("clipped");

            clipped.TextWrapping = TextWrapping.Wrap;
            root.UpdateLayout();
            VisualSmokeRunner.FindPseudoLocaleLayoutFailures(root, "test").Should().BeEmpty();
        });
    }

    [Fact]
    public void Theme_manager_switches_the_live_application_into_and_out_of_contrast()
    {
        RunSta(() =>
        {
            var app = Application.Current!;
            app.Resources.Clear();
            app.Resources.MergedDictionaries.Add(Load("Dark"));
            app.Resources.MergedDictionaries.Add(Load("Styles"));
            using var manager = new ThemeManager();
            manager.Apply("light");
            manager.RefreshSystemContrast(false);

            var surface = new Border();
            surface.SetResourceReference(Control.BackgroundProperty, "Hg.Base");
            var sameSurface = surface;
            app.Resources.MergedDictionaries[0].Source!.OriginalString.Should().EndWith("Light.xaml");

            manager.RefreshSystemContrast(true);
            manager.Effective.Should().Be("contrast");
            manager.IsHighContrast.Should().BeTrue();
            app.Resources.MergedDictionaries[0].Source!.OriginalString.Should().EndWith("Contrast.xaml");
            surface.Should().BeSameAs(sameSurface, "contrast changes must not recreate the visual tree");
            surface.Background.Should().NotBeNull("the live DynamicResource must resolve through the contrast dictionary");

            manager.RefreshSystemContrast(false);
            manager.Effective.Should().Be("light");
            app.Resources.MergedDictionaries[0].Source!.OriginalString.Should().EndWith("Light.xaml");
        });
    }

    [Fact]
    public void Chart_series_have_distinct_non_color_line_patterns()
    {
        RunSta(() =>
        {
            var converter = new SeriesDashConverter();
            var patterns = Enumerable.Range(0, 5)
                .Select(index => (DoubleCollection)converter.Convert(
                    index, typeof(DoubleCollection), null, System.Globalization.CultureInfo.InvariantCulture))
                .Select(pattern => string.Join(",", pattern))
                .ToArray();

            patterns.Should().OnlyHaveUniqueItems();
            patterns[0].Should().BeEmpty("the first series is the solid baseline");
            patterns.Skip(1).Should().OnlyContain(pattern => !string.IsNullOrWhiteSpace(pattern));
        });
    }

    [Fact]
    public void Rendered_pairwise_matrix_covers_states_themes_scales_sizes_and_accessibility()
    {
        var cases = new[]
        {
            (State: "empty", Theme: "dark", Scale: 90, Width: 1280, Height: 800),
            (State: "populated", Theme: "light", Scale: 100, Width: 1600, Height: 1000),
            (State: "loading", Theme: "contrast-aquatic", Scale: 125, Width: 1280, Height: 800),
            (State: "disconnected", Theme: "contrast-desert", Scale: 150, Width: 1600, Height: 1000),
            (State: "error", Theme: "contrast-dusk", Scale: 90, Width: 1280, Height: 800),
            (State: "populated", Theme: "contrast-night-sky", Scale: 100, Width: 1600, Height: 1000),
        };

        cases.Select(item => item.State).Distinct().Should().BeEquivalentTo("empty", "populated", "loading", "disconnected", "error");
        cases.Select(item => item.Theme).Distinct().Should().BeEquivalentTo(
            "dark", "light", "contrast-aquatic", "contrast-desert", "contrast-dusk", "contrast-night-sky");
        cases.Select(item => item.Scale).Distinct().Should().Contain(new[] { 90, 100, 125, 150 });
        var sizes = cases.Select(item => (item.Width, item.Height)).Distinct().ToArray();
        sizes.Should().HaveCount(2);
        sizes.Should().Contain((1280, 800)).And.Contain((1600, 1000));

        RunSta(() =>
        {
            var priorCulture = System.Globalization.CultureInfo.CurrentUICulture;
            System.Globalization.CultureInfo.CurrentUICulture =
                System.Globalization.CultureInfo.GetCultureInfo("qps-ploc");
            try
            {
                var app = Application.Current!;
                var captureIds = new HashSet<string>(StringComparer.Ordinal);
                var nestedCaptureIds = new HashSet<string>(StringComparer.Ordinal);
                foreach (var item in cases)
                {
                    app.Resources.Clear();
                    app.Resources.MergedDictionaries.Add(Load("Dark"));
                    app.Resources.MergedDictionaries.Add(Load("Styles"));
                    using var previewTheme = new ThemeManager();
                    previewTheme.Apply(item.Theme);

                    using var client = new HostsServiceClient(NamedPipeChannel.Create(
                        SessionToken.Generate(), $"hg-matrix-{item.State}"));
                    var config = new AppConfigStore(Path.Combine(
                        Path.GetTempPath(), "hg_matrix_" + Guid.NewGuid().ToString("N") + ".json"));
                    using var vm = CreateMatrixShell(client, config);
                    vm.UiScalePct = item.Scale;
                    SeedShellState(vm, item.State);

                    var window = new MainWindow(vm);
                    window.WindowStartupLocation = WindowStartupLocation.Manual;
                    window.Left = -32000;
                    window.Top = -32000;
                    window.Width = item.Width;
                    window.Height = item.Height;
                    window.ShowActivated = false;
                    window.ShowInTaskbar = false;
                    window.Show();
                    window.UpdateLayout();
                    AssertRailServiceCommands(window, vm, item.State);
                    var tabs = (TabControl)window.FindName("MainTabs");
                    for (var tab = 0; tab < tabs.Items.Count; tab++)
                    {
                        tabs.SelectedIndex = tab;
                        window.UpdateLayout();
                        var label = $"{item.Theme}/{item.State}/{item.Scale}/{item.Width}x{item.Height}";
                        AssertAllInputsNamed(window, tabs, tab, label);
                        AssertTabAccessible(window, tab, label);
                        AssertLiveStatusReadouts(window, tab, label);
                        AssertLogicalFocus(window, tab, label);
                        if (item.Theme.StartsWith("contrast-", StringComparison.Ordinal))
                        {
                            AssertVisibleControlContrast(window, tab, label);
                        }
                        VisualSmokeRunner.FindPseudoLocaleLayoutFailures(window, $"{label}/tab-{tab}")
                            .Should().BeEmpty();
                        var captureId = $"{item.Theme}-{item.State}-{item.Scale}-{item.Width}x{item.Height}-tab-{tab}";
                        captureIds.Add(captureId).Should().BeTrue("capture identifiers must be unique");
                        AssertRenderedPixels((FrameworkElement)window.Content, item, captureId);

                        if (item.State == "populated" && tab is 0 or 3)
                        {
                            var groupName = tab == 0 ? "matrix.example" : "matrix.exe";
                            var group = Descendants<Expander>(window).Single(expander =>
                                expander.IsVisible && AutomationProperties.GetName(expander) == groupName);
                            group.Style.Should().BeSameAs(app.Resources["Hg.DataGridGroup"]);
                            group.IsExpanded.Should().BeTrue();
                            ((StackPanel)group.Header).Orientation.Should().Be(Orientation.Horizontal);

                            if (tab == 0)
                            {
                                var header = (StackPanel)group.Header;
                                header.Tag.Should().BeSameAs(window.FindName("ActivityGrid"));
                                var headerMenu = header.ContextMenu;
                                headerMenu.Should().NotBeNull("the Hosts group header retains its hide-root action");
                                headerMenu!.PlacementTarget = header;
                                var hide = headerMenu!.Items.OfType<MenuItem>().Single();
                                BindingOperations.GetBinding(hide, MenuItem.CommandParameterProperty)?.Path.Path
                                    .Should().Be("PlacementTarget.DataContext.Name");
                                hide.GetBindingExpression(MenuItem.CommandProperty)?.UpdateTarget();
                                hide.GetBindingExpression(MenuItem.CommandParameterProperty)?.UpdateTarget();
                                hide.Command.Should().BeSameAs(vm.Activity!.HideGroupCommand);
                                hide.CommandParameter.Should().Be("matrix.example");
                            }
                        }

                        foreach (var nested in Descendants<TabControl>(window)
                                     .Where(control => control != tabs && control.IsVisible))
                        {
                            for (var nestedIndex = 0; nestedIndex < nested.Items.Count; nestedIndex++)
                            {
                                nested.SelectedIndex = nestedIndex;
                                window.UpdateLayout();
                                var nestedId = $"{captureId}-nested-{nestedIndex}";
                                nestedCaptureIds.Add(nestedId).Should().BeTrue();
                                AssertRenderedPixels((FrameworkElement)window.Content, item, nestedId);
                            }
                        }
                    }

                    if (item.State == "populated")
                    {
                        tabs.SelectedIndex = 5;
                        window.UpdateLayout();
                        var toolsTabs = (TabControl)window.FindName("ToolsTabs");
                        toolsTabs.Items.Count.Should().Be(5);
                        var cardCount = 0;
                        for (var toolsTab = 0; toolsTab < toolsTabs.Items.Count; toolsTab++)
                        {
                            toolsTabs.SelectedIndex = toolsTab;
                            window.UpdateLayout();
                            var cards = Descendants<Border>(toolsTabs)
                                .Where(border => border.IsVisible && Equals(border.Style, app.Resources["Hg.Card"]))
                                .ToArray();
                            cards.Should().NotBeEmpty("every Tools section must expose at least one card");
                            cardCount += cards.Length;
                            for (var cardIndex = 0; cardIndex < cards.Length; cardIndex++)
                            {
                                cards[cardIndex].BringIntoView();
                                window.UpdateLayout();
                                var toolsId = $"{item.Theme}-tools-tab-{toolsTab}-card-{cardIndex}";
                                nestedCaptureIds.Add(toolsId).Should().BeTrue();
                                AssertRenderedPixels((FrameworkElement)window.Content, item, toolsId);
                            }
                        }

                        cardCount.Should().BeGreaterThan(20, "all major Tools cards must be part of the section matrix");
                    }

                    var baseBrush = ((SolidColorBrush)app.Resources["Hg.Base"]).Color;
                    var textBrush = ((SolidColorBrush)app.Resources["Hg.Text"]).Color;
                    ContrastRatio(baseBrush, textBrush).Should().BeGreaterThanOrEqualTo(
                        item.Theme.StartsWith("contrast-", StringComparison.Ordinal) ? 7 : 4.5,
                        $"{item.Theme} primary text must remain readable");
                    window.CloseForSmoke();
                }

                captureIds.Should().HaveCount(cases.Length * 6,
                    "every state/theme/scale/size case must capture all six primary tabs");
                nestedCaptureIds.Should().NotBeEmpty("nested Hosts tabs and every major Tools card must be captured");
            }
            finally
            {
                System.Globalization.CultureInfo.CurrentUICulture = priorCulture;
            }
        });
    }

    private static MainViewModel CreateMatrixShell(HostsServiceClient client, AppConfigStore config)
    {
        var vm = new MainViewModel(() => client, config, new ThemeManager(), new FakeConfirm(true));
        vm.PrepareVisualSmokeConnectionFixture();
        return vm;
    }

    private static void SeedShellState(MainViewModel vm, string state)
    {
        vm.IsConnected = state is "empty" or "populated" or "loading";
        vm.FilteringModeText = vm.IsConnected ? "Normal - deterministic state" : string.Empty;
        vm.EnforcementPauseText = vm.IsConnected ? "Hosts and firewall enforcement active." : string.Empty;
        vm.ConnectionText = state switch
        {
            "loading" => "Loading deterministic service data...",
            "disconnected" => "Disconnected - deterministic service unavailable",
            "error" => "Error - deterministic service request failed",
            _ => "Connected - deterministic visual state",
        };
        if (state == "populated")
        {
            vm.HostsBlocked = 42;
            vm.DbBlocked = 40;
            vm.DbAllowed = 2;
            vm.Activity!.Rows.Add(new ActivityRowViewModel { Domain = "matrix.example", Root = "matrix.example" });
            vm.Activity.GroupByRoot = true;
            vm.FwActivity!.Rows.Add(new ConnectionRowViewModel
            {
                Process = "matrix.exe",
                Protocol = "TCP",
                RemoteAddr = "203.0.113.10",
                RemotePort = 443,
            });
            vm.FwActivity.GroupByApp = true;
            vm.Alerts!.AllowlistRecommendations.Add(new AllowlistRecommendationViewModel(
                "assets.example.test",
                25,
                85,
                "child.exe",
                "launcher.exe",
                "edge.cloudfront.net (CDN)",
                "trusted folder: TrustedApps"));
        }
    }

    private static void AssertRailServiceCommands(Window window, MainViewModel vm, string state)
    {
        var commands = new HashSet<ICommand>
        {
            vm.SetFilteringModeCommand,
            vm.SetGlobalModeCommand,
            vm.PauseEnforcementCommand,
            vm.RestoreSafeNetworkPostureCommand,
            vm.RunDiagnosticsCommand,
            vm.Tools!.FlushDnsCommand,
            vm.Alerts!.RefreshCommand,
        };
        var buttons = Descendants<Button>(window)
            .Where(button => button.Command is not null && commands.Contains(button.Command))
            .ToArray();

        buttons.Should().HaveCount(10,
            "the status surfaces must expose filtering, posture, three pause, DNS, diagnostics, and alert actions");
        var connected = state is "empty" or "populated" or "loading";
        buttons.Should().OnlyContain(button => button.IsEnabled == connected);
        if (!connected)
        {
            var missingHelp = buttons
                .Where(button => !string.Equals(
                    AutomationProperties.GetHelpText(button),
                    vm.ServiceCommandAvailabilityText,
                    StringComparison.Ordinal))
                .Select(button => $"{AutomationProperties.GetName(button)}: '{AutomationProperties.GetHelpText(button)}'")
                .ToArray();
            missingHelp.Should().BeEmpty("disabled service actions must explain that reconnect is required");
        }
    }

    private static void AssertRenderedPixels(FrameworkElement surface,
        (string State, string Theme, int Scale, int Width, int Height) item,
        string captureId)
    {
        var bitmap = new RenderTargetBitmap(item.Width, item.Height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(surface);
        var stride = item.Width * 4;
        var pixels = new byte[stride * item.Height];
        bitmap.CopyPixels(pixels, stride, 0);
        pixels.Where((_, index) => index % 4 != 3).Distinct().Count().Should().BeGreaterThan(8,
            $"{item.Theme}/{item.State}/{item.Scale}% must render non-blank pixel detail");
        var outputDir = Path.Combine(Path.GetTempPath(), "hostsguard-rendered-matrix");
        Directory.CreateDirectory(outputDir);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = File.Create(Path.Combine(outputDir, captureId + ".png"));
        encoder.Save(stream);
    }

    private static void AssertLogicalFocus(Window window, int tabIndex, string label)
    {
        var target = Descendants<Control>(window).FirstOrDefault(control =>
            control.IsVisible && control.IsEnabled && control.Focusable && KeyboardNavigation.GetIsTabStop(control));
        target.Should().NotBeNull($"tab {tabIndex} ({label}) must expose a keyboard-focusable control");
        FocusManager.SetFocusedElement(window, target);
        FocusManager.GetFocusedElement(window).Should().BeSameAs(target,
            $"tab {tabIndex} ({label}) must accept deterministic logical focus without desktop activation");
        Application.Current!.Resources.Contains("Hg.Focus").Should().BeTrue("the active theme must define a focus token");
    }

    private static void AssertVisibleControlContrast(Window window, int tabIndex, string label)
    {
        var failures = new List<string>();
        foreach (var element in Descendants<FrameworkElement>(window).Where(element =>
                     element.IsVisible && element.IsEnabled &&
                     (element is Button or TextBox or ComboBox || element is TextBlock { Text.Length: > 0 })))
        {
            var foregroundBrush = element switch
            {
                Control control => control.Foreground,
                TextBlock text => text.Foreground,
                _ => null,
            };
            if (foregroundBrush is not SolidColorBrush foreground ||
                ResolveVisibleBackground(element) is not SolidColorBrush background)
            {
                failures.Add($"{element.GetType().Name}: unresolved solid foreground/background");
                continue;
            }

            var ratio = ContrastRatio(foreground.Color, background.Color);
            if (ratio < 4.5)
            {
                var identity = element is ContentControl content
                    ? content.Content?.ToString()
                    : element is TextBlock text ? text.Text : System.Windows.Automation.AutomationProperties.GetName(element);
                failures.Add($"{element.GetType().Name} '{identity}': {ratio:F2}:1 ({foreground.Color} on {background.Color}; backgrounds {DescribeBackgroundPath(element)}; foregrounds {DescribeForegroundPath(element)})");
            }
        }

        failures.Should().BeEmpty($"visible controls on tab {tabIndex} ({label}) must meet 4.5:1 text contrast");
    }

    private static Brush? ResolveVisibleBackground(DependencyObject element)
    {
        for (var current = element; current is not null; current = VisualTreeHelper.GetParent(current))
        {
            Brush? brush = current switch
            {
                Control control => control.Background,
                Panel panel => panel.Background,
                Border border => border.Background,
                _ => null,
            };
            if (brush is SolidColorBrush { Color.A: > 0 })
            {
                return brush;
            }
        }
        return null;
    }

    private static string DescribeBackgroundPath(DependencyObject element)
    {
        var owners = new List<string>();
        for (var current = element; current is not null && owners.Count < 4; current = VisualTreeHelper.GetParent(current))
        {
            var brush = current switch
            {
                Control control => control.Background,
                Panel panel => panel.Background,
                Border border => border.Background,
                _ => null,
            };
            if (brush is SolidColorBrush { Color.A: > 0 } solid)
            {
                owners.Add($"{current.GetType().Name}={solid.Color}");
            }
        }
        return string.Join(" <- ", owners);
    }

    private static string DescribeForegroundPath(DependencyObject element)
    {
        var owners = new List<string>();
        for (var current = element; current is not null && owners.Count < 5; current = VisualTreeHelper.GetParent(current))
        {
            var brush = current switch
            {
                TextBlock text => text.Foreground,
                Control control => control.Foreground,
                _ => null,
            };
            if (brush is SolidColorBrush solid)
            {
                owners.Add($"{current.GetType().Name}={solid.Color}");
            }
        }
        return string.Join(" <- ", owners);
    }

    private static double ContrastRatio(Color first, Color second)
    {
        static double Luminance(Color color)
        {
            static double Channel(byte value)
            {
                var normalized = value / 255d;
                return normalized <= 0.03928 ? normalized / 12.92 : Math.Pow((normalized + 0.055) / 1.055, 2.4);
            }
            return 0.2126 * Channel(color.R) + 0.7152 * Channel(color.G) + 0.0722 * Channel(color.B);
        }

        var a = Luminance(first);
        var b = Luminance(second);
        return (Math.Max(a, b) + 0.05) / (Math.Min(a, b) + 0.05);
    }
}

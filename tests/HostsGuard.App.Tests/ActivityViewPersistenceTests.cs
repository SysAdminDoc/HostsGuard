using System.IO;
using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>
/// Hosts Activity view toggles persist across restarts, and the reverse-DNS
/// filter recognizes PTR domains. Lazy channel — nothing here hits the wire.
/// </summary>
public sealed class ActivityViewPersistenceTests : IDisposable
{
    private readonly string _dir;
    private readonly string _configPath;

    public ActivityViewPersistenceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_actcfg_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _configPath = Path.Combine(_dir, "config.json");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private static HostsServiceClient LazyClient()
        => new(NamedPipeChannel.Create(SessionToken.Generate(), "hg-actcfg-none"));

    [Fact]
    public void View_flags_round_trip_through_config()
    {
        var store = new AppConfigStore(_configPath);
        store.GetViewFlag("activity_hide_blocked").Should().BeFalse();

        store.SaveViewFlag("activity_hide_blocked", true);
        store.SaveViewFlag("fw_group_by_app", false);

        // A fresh store (simulating a restart) reads the persisted values.
        var reopened = new AppConfigStore(_configPath);
        reopened.GetViewFlag("activity_hide_blocked").Should().BeTrue();
        reopened.GetViewFlag("fw_group_by_app", true).Should().BeFalse();
    }

    [Fact]
    public void Toggles_persist_and_a_new_view_model_restores_them()
    {
        var store = new AppConfigStore(_configPath);
        var vm = new HostsActivityViewModel(LazyClient(), store);
        vm.HideBlocked.Should().BeFalse();

        vm.HideReverseDns = true;
        vm.GroupByRoot = true;
        vm.BlockedOnly = true;

        var restored = new HostsActivityViewModel(LazyClient(), new AppConfigStore(_configPath));
        restored.HideReverseDns.Should().BeTrue();
        restored.GroupByRoot.Should().BeTrue();
        restored.HideBlocked.Should().BeFalse();
        restored.BlockedOnly.Should().BeTrue();
    }

    [Fact]
    public void Config_writes_preserve_unrelated_keys()
    {
        File.WriteAllText(_configPath, """{"theme":"light","ui_scale_pct":125}""");
        var store = new AppConfigStore(_configPath);

        store.SaveViewFlag("activity_group_by_root", true);

        var reopened = new AppConfigStore(_configPath);
        reopened.Load();
        reopened.Theme.Should().Be("light");
        reopened.UiScalePct.Should().Be(125);
        reopened.GetViewFlag("activity_group_by_root").Should().BeTrue();
    }
}

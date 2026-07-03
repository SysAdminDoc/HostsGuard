using System.IO;
using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Data;
using HostsGuard.Ipc;
using HostsGuard.Service;
using HostsGuard.Windows;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.App.Tests;

internal sealed class FakePicker : IFilePicker
{
    public string? OpenPath { get; set; }

    public string? SavePath { get; set; }

    public string? PickFile(string title, string? initialPath = null, string? filter = null) => OpenPath;

    public string? SaveFile(string title, string defaultName, string? filter = null) => SavePath;
}

/// <summary>File-menu import/export and the View-menu reset, over a live in-proc service.</summary>
[SupportedOSPlatform("windows")]
public sealed class MenuCommandTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private HostsServiceClient _client = null!;
    private readonly FakePicker _picker = new();

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_menu_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n0.0.0.0 existing.example.com\n");

        _state = new ServiceState(new HostsEngine(hostsPath), new HostsDatabase(Path.Combine(_dir, "db.sqlite")),
            dataDir: _dir);
        var token = SessionToken.Generate();
        var pipe = "HostsGuard.MenuTest." + Guid.NewGuid().ToString("N");
        _app = ServiceHost.Build(_state, token, pipe);
        await _app.StartAsync();
        _client = new HostsServiceClient(NamedPipeChannel.Create(token, pipe));
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _app.DisposeAsync();
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private MainViewModel CreateVm() => new(
        () => _client,
        new AppConfigStore(Path.Combine(_dir, "config_" + Guid.NewGuid().ToString("N") + ".json")),
        new ThemeManager(),
        new FakeConfirm(true),
        _picker);

    [Fact]
    public async Task Export_then_import_round_trips_the_hosts_file()
    {
        using var vm = CreateVm();
        await vm.ConnectAsync();
        vm.IsConnected.Should().BeTrue();

        var exportPath = Path.Combine(_dir, "exported_hosts.txt");
        _picker.SavePath = exportPath;
        await vm.ExportHostsFileCommand.ExecuteAsync(null);
        File.ReadAllText(exportPath).Should().Contain("existing.example.com");

        var importPath = Path.Combine(_dir, "replacement_hosts.txt");
        File.WriteAllText(importPath, "# replaced\n0.0.0.0 imported.example.com\n");
        _picker.OpenPath = importPath;
        await vm.ImportHostsFileCommand.ExecuteAsync(null);

        _state.Hosts.GetBlocked().Should().Contain("imported.example.com").And.NotContain("existing.example.com");
        // The import snapshots the previous file first.
        Directory.GetFiles(Path.Combine(_dir, "backups"), "*.bak").Should().NotBeEmpty();
    }

    [Fact]
    public async Task Export_domains_writes_policy_json()
    {
        await _client.Hosts.BlockAsync(new Contracts.DomainRequest { Domain = "json.example.com" });
        using var vm = CreateVm();
        await vm.ConnectAsync();
        var path = Path.Combine(_dir, "domains.json");
        _picker.SavePath = path;

        await vm.ExportDomainsCommand.ExecuteAsync(null);

        File.ReadAllText(path).Should().Contain("json.example.com").And.Contain("\"status\"");
    }

    [Fact]
    public async Task Export_to_an_unwritable_path_reports_cleanly_without_throwing()
    {
        using var vm = CreateVm();
        await vm.ConnectAsync();
        // A path under a non-existent directory: the write throws a file I/O
        // error that must be caught and surfaced, not escape to the global
        // handler (which would misreport it as a lost service connection).
        _picker.SavePath = Path.Combine(_dir, "no-such-dir", "sub", "out.txt");

        await vm.ExportHostsFileCommand.ExecuteAsync(null);

        vm.ConnectionText.Should().Contain("Couldn't write");
        vm.IsConnected.Should().BeTrue("the service is fine — only the file write failed");
    }

    [Fact]
    public void Reset_view_returns_every_toggle_and_filter_to_defaults()
    {
        var vm = CreateVm();
        vm.Activity = new HostsActivityViewModel(_client);
        vm.Hosts = new HostsViewModel(_client, new FakeConfirm(true));
        vm.FwActivity = new FwActivityViewModel(_client, new FakeConfirm(true));
        vm.FwRules = new FwRulesViewModel(_client, new FakeConfirm(true));

        vm.Activity.Filter = "x";
        vm.Activity.GroupByRoot = true;
        vm.Activity.HideBlocked = true;
        vm.Hosts.StatusFilter = "blocked";
        vm.FwActivity.GroupByApp = false;
        vm.FwActivity.ResolveIps = true;
        vm.FwRules.HostsGuardOnly = false;
        vm.UiScalePct = 125;

        vm.ResetViewCommand.Execute(null);

        vm.Activity.Filter.Should().BeEmpty();
        vm.Activity.GroupByRoot.Should().BeFalse();
        vm.Activity.HideBlocked.Should().BeFalse();
        vm.Hosts.StatusFilter.Should().Be("All");
        vm.FwActivity.GroupByApp.Should().BeTrue();
        vm.FwActivity.ResolveIps.Should().BeFalse();
        vm.FwRules.HostsGuardOnly.Should().BeTrue();
        vm.UiScalePct.Should().Be(100);
    }
}

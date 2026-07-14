using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

[SupportedOSPlatform("windows")]
public sealed class UpdateRecoveryCoordinatorTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "hg_update_recovery_" + Guid.NewGuid().ToString("N"));
    private readonly string _dataDir;
    private readonly string _installRoot;
    private readonly string _helper;

    public UpdateRecoveryCoordinatorTests()
    {
        _dataDir = Path.Combine(_root, "data");
        _installRoot = Path.Combine(_root, "Program Files", "HostsGuard");
        _helper = Path.Combine(_root, "new-helper.exe");
        Directory.CreateDirectory(Path.Combine(_installRoot, "service"));
        Directory.CreateDirectory(Path.Combine(_installRoot, "cli"));
        File.WriteAllText(Path.Combine(_installRoot, "service", "HostsGuard.Service.exe"), "old-service");
        File.WriteAllText(Path.Combine(_installRoot, "cli", "HostsGuard.Cli.exe"), "old-cli");
        File.WriteAllText(Path.Combine(_installRoot, "old-only.txt"), "old-only");
        File.WriteAllText(_helper, "new-helper");
    }

    [Fact]
    public void Stop_or_permission_failure_aborts_before_backup_or_attempt()
    {
        var service = new FakeServiceControl { StopError = new UnauthorizedAccessException("access denied") };

        var result = UpdateRecoveryCoordinator.Prepare(_dataDir, _installRoot, "9.9.9", _helper, service);

        result.Ok.Should().BeFalse();
        result.Message.Should().Contain("access denied");
        UpdateRecoveryCoordinator.ReadAttempt(_dataDir).Should().BeNull();
        Directory.Exists(Path.Combine(_dataDir, "updates")).Should().BeFalse();
        File.ReadAllText(Path.Combine(_installRoot, "service", "HostsGuard.Service.exe")).Should().Be("old-service");
        service.StartCalls.Should().Be(0);
    }

    [Fact]
    public void Rollback_restores_exact_tree_and_service_configuration_once()
    {
        var service = new FakeServiceControl();
        UpdateRecoveryCoordinator.Prepare(_dataDir, _installRoot, "9.9.9", _helper, service).Ok.Should().BeTrue();
        var attempt = UpdateRecoveryCoordinator.ReadAttempt(_dataDir)!;
        attempt.BackupRoot.Should().Contain("previous-unknown-");

        File.WriteAllText(Path.Combine(_installRoot, "service", "HostsGuard.Service.exe"), "broken-new-service");
        File.Delete(Path.Combine(_installRoot, "old-only.txt"));
        File.WriteAllText(Path.Combine(_installRoot, "new-only.txt"), "must disappear");

        var first = UpdateRecoveryCoordinator.Rollback(_dataDir, service);
        var second = UpdateRecoveryCoordinator.Rollback(_dataDir, service);

        first.Ok.Should().BeTrue();
        second.Ok.Should().BeFalse();
        second.Message.Should().Contain("already attempted");
        File.ReadAllText(Path.Combine(_installRoot, "service", "HostsGuard.Service.exe")).Should().Be("old-service");
        File.ReadAllText(Path.Combine(_installRoot, "old-only.txt")).Should().Be("old-only");
        File.Exists(Path.Combine(_installRoot, "new-only.txt")).Should().BeFalse();
        service.Restored.Should().BeEquivalentTo(FakeServiceControl.Configuration);
        service.StopCalls.Should().Be(2, "prepare and rollback each stop exactly once");
        service.StartCalls.Should().Be(1);
        UpdateRecoveryCoordinator.ReadAttempt(_dataDir)!.Status.Should().Be("rolled_back");
    }

    [Fact]
    public void Healthy_completion_logs_and_removes_attempt_backup_and_helper()
    {
        var service = new FakeServiceControl();
        UpdateRecoveryCoordinator.Prepare(_dataDir, _installRoot, "9.9.9", _helper, service).Ok.Should().BeTrue();
        var attempt = UpdateRecoveryCoordinator.ReadAttempt(_dataDir)!;
        File.Exists(UpdateRecoveryCoordinator.RollbackHelperPath(_dataDir)).Should().BeTrue();
        using var db = new HostsDatabase(Path.Combine(_dataDir, "hostsguard.db"));

        var result = UpdateRecoveryCoordinator.CompleteHealthy(_dataDir, "v9.9.9", db);

        result.Ok.Should().BeTrue();
        UpdateRecoveryCoordinator.ReadAttempt(_dataDir).Should().BeNull();
        Directory.Exists(attempt.BackupRoot).Should().BeFalse();
        File.Exists(UpdateRecoveryCoordinator.RollbackHelperPath(_dataDir)).Should().BeFalse();
        db.GetLog(limit: 20).Should().Contain(row => row.Action == "update_healthy");
    }

    [Fact]
    public void Restored_service_records_rollback_and_clears_recovery_state()
    {
        var service = new FakeServiceControl();
        UpdateRecoveryCoordinator.Prepare(_dataDir, _installRoot, "9.9.9", _helper, service).Ok.Should().BeTrue();
        UpdateRecoveryCoordinator.Rollback(_dataDir, service).Ok.Should().BeTrue();
        var backup = UpdateRecoveryCoordinator.ReadAttempt(_dataDir)!.BackupRoot;
        using var db = new HostsDatabase(Path.Combine(_dataDir, "hostsguard.db"));

        UpdateRecoveryCoordinator.ReconcileOnServiceStart(_dataDir, db);

        UpdateRecoveryCoordinator.ReadAttempt(_dataDir).Should().BeNull();
        Directory.Exists(backup).Should().BeFalse();
        db.GetLog(limit: 20).Should().Contain(row => row.Action == "update_rolled_back");
    }

    [Fact]
    public void Installer_source_gates_preflight_service_actions_health_and_rollback()
    {
        var root = FindRepositoryRoot();
        var installer = File.ReadAllText(Path.Combine(root, "installer-dotnet.iss"));

        installer.Should().Contain("function PrepareToInstall");
        installer.Should().Contain("--prepare-update");
        installer.Should().Contain("ConfigureAndStartService");
        installer.Should().Contain("RunAndCheck");
        installer.Should().Contain("update health --expected");
        installer.Should().Contain("--rollback-update");
        installer.Should().Contain("--complete-update");
        installer.Should().Contain("function GetCustomSetupExitCode");
        installer.Should().NotContain("Filename: \"{sys}\\sc.exe\"; Parameters: \"start");
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "installer-dotnet.iss")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("repository root was not found");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private sealed class FakeServiceControl : IWindowsServiceUpdateControl
    {
        public static readonly WindowsServiceConfiguration Configuration = new(
            @"C:\Program Files\HostsGuard\service\HostsGuard.Service.exe",
            0x10,
            2,
            1,
            "LocalSystem",
            "HostsGuard Service",
            ["MpsSvc"],
            "previous description",
            86400,
            string.Empty,
            string.Empty,
            [
                new WindowsServiceFailureAction(1, 5000),
                new WindowsServiceFailureAction(1, 10000),
                new WindowsServiceFailureAction(1, 30000),
            ]);

        public Exception? StopError { get; init; }

        public int StopCalls { get; private set; }

        public int StartCalls { get; private set; }

        public WindowsServiceConfiguration? Restored { get; private set; }

        public WindowsServiceConfiguration Capture() => Configuration;

        public void StopAndWait(TimeSpan timeout)
        {
            StopCalls++;
            if (StopError is not null)
            {
                throw StopError;
            }
        }

        public void Restore(WindowsServiceConfiguration configuration) => Restored = configuration;

        public void StartAndWait(TimeSpan timeout) => StartCalls++;
    }
}

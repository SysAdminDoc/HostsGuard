using System.Text.Json;
using FluentAssertions;
using HostsGuard.Data;
using Xunit;

namespace HostsGuard.Service.Tests;

public sealed class StateSnapshotCoordinatorTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "hg_state_snapshot_" + Guid.NewGuid().ToString("N"));
    private readonly string _databasePath;
    private readonly string _hostsPath;
    private readonly string _snapshotRoot;

    public StateSnapshotCoordinatorTests()
    {
        Directory.CreateDirectory(_dir);
        _databasePath = Path.Combine(_dir, "hostsguard.db");
        _hostsPath = Path.Combine(_dir, "hosts");
        _snapshotRoot = Path.Combine(_dir, "snapshots");
        File.WriteAllText(_hostsPath, "# baseline\n0.0.0.0 initial.example\n");
    }

    [Fact]
    public void Create_hashes_full_non_secret_state_and_excludes_secrets()
    {
        File.WriteAllText(Path.Combine(_dir, "consent_state.json"), "{\"mode\":\"Notify\"}");
        File.WriteAllText(Path.Combine(_dir, "killswitch_state.json"), "{\"engaged\":true}");
        File.WriteAllText(Path.Combine(_dir, "ai_config.json"), "{\"apiKey\":\"secret\"}");
        File.WriteAllText(Path.Combine(_dir, "webhooks.json"), "{\"secret\":\"secret\"}");
        File.WriteAllText(Path.Combine(_dir, "lock_state.json"), "{\"passwordHash\":\"secret\"}");
        File.WriteAllText(Path.Combine(_dir, "loopback_token"), "secret");

        using var database = new HostsDatabase(_databasePath);
        database.SetMeta("snapshot_probe", "present");
        var coordinator = Coordinator(database);

        var created = coordinator.Create();

        created.Verified.Should().BeTrue();
        created.AppVersion.Should().Be("9.8.7");
        created.DatabaseSchemaVersion.Should().Be(HostsDatabase.SchemaVersion);
        created.Sha256.Should().MatchRegex("^[0-9a-f]{64}$");
        created.SizeBytes.Should().BeGreaterThan(0);
        created.Components.Should().Contain(new[]
        {
            "database", "hosts", "state:consent_state.json", "state:killswitch_state.json",
        });

        var files = Directory.EnumerateFiles(Path.Combine(_snapshotRoot, created.Id), "*", SearchOption.AllDirectories)
            .Select(Path.GetFileName)
            .ToArray();
        files.Should().NotContain(new[] { "ai_config.json", "webhooks.json", "lock_state.json", "loopback_token" });
        coordinator.List().Should().ContainSingle().Which.Should().BeEquivalentTo(created);
    }

    [Fact]
    public void Preview_reports_component_changes_and_rejects_tampered_payload()
    {
        File.WriteAllText(Path.Combine(_dir, "consent_state.json"), "{\"mode\":\"Normal\"}");
        using var database = new HostsDatabase(_databasePath);
        var coordinator = Coordinator(database);
        var created = coordinator.Create();

        File.WriteAllText(_hostsPath, "# changed\n");
        File.WriteAllText(Path.Combine(_dir, "consent_state.json"), "{\"mode\":\"Learning\"}");
        var preview = coordinator.Preview(created.Id);
        preview.Snapshot.Verified.Should().BeTrue();
        preview.Changes.Should().Contain(change => change.Component == "hosts" && change.ChangeKind == "replace");
        preview.Changes.Should().Contain(change =>
            change.Component == "state:consent_state.json" && change.ChangeKind == "replace");

        File.AppendAllText(Path.Combine(_snapshotRoot, created.Id, "hosts", "hosts"), "tampered");
        var act = () => coordinator.Preview(created.Id);
        act.Should().Throw<StateSnapshotException>().WithMessage("*integrity verification failed*");
        coordinator.List().Should().ContainSingle().Which.Verified.Should().BeFalse();
    }

    [Fact]
    public void Restore_requires_manifest_hash_and_restores_database_hosts_and_json()
    {
        var statePath = Path.Combine(_dir, "consent_state.json");
        File.WriteAllText(statePath, "{\"mode\":\"Normal\"}");
        using var database = new HostsDatabase(_databasePath);
        database.SetMeta("snapshot_probe", "before");
        var coordinator = Coordinator(database);
        var snapshot = coordinator.Create();

        database.SetMeta("snapshot_probe", "after");
        File.WriteAllText(_hostsPath, "# after\n0.0.0.0 after.example\n");
        File.WriteAllText(statePath, "{\"mode\":\"Learning\"}");

        var wrongHash = new string('0', 64);
        var mismatch = () => coordinator.Restore(snapshot.Id, wrongHash);
        mismatch.Should().Throw<StateSnapshotException>().WithMessage("*confirmation hash*");

        var restored = coordinator.Restore(snapshot.Id, snapshot.Sha256);
        restored.RolledBack.Should().BeFalse();
        restored.PreRestoreSnapshotId.Should().StartWith("pre-restore-");
        database.GetMeta("snapshot_probe").Should().Be("before");
        File.ReadAllText(_hostsPath).Should().Contain("initial.example").And.NotContain("after.example");
        File.ReadAllText(statePath).Should().Contain("Normal");
    }

    [Fact]
    public void Failed_live_validation_rolls_back_to_automatic_pre_restore_snapshot()
    {
        var statePath = Path.Combine(_dir, "consent_state.json");
        File.WriteAllText(statePath, "{\"mode\":\"Normal\"}");
        using var database = new HostsDatabase(_databasePath);
        database.SetMeta("snapshot_probe", "target");
        var target = Coordinator(database).Create();

        database.SetMeta("snapshot_probe", "current");
        File.WriteAllText(_hostsPath, "# current\n0.0.0.0 current.example\n");
        File.WriteAllText(statePath, "{\"mode\":\"Learning\"}");
        var coordinator = Coordinator(database, _ => false);

        var restore = () => coordinator.Restore(target.Id, target.Sha256);
        restore.Should().Throw<StateSnapshotException>().WithMessage("*rolled back*");
        database.GetMeta("snapshot_probe").Should().Be("current");
        File.ReadAllText(_hostsPath).Should().Contain("current.example");
        File.ReadAllText(statePath).Should().Contain("Learning");
        coordinator.List().Should().Contain(info => info.Id.StartsWith("pre-restore-", StringComparison.Ordinal));
    }

    [Fact]
    public void Staged_startup_restore_applies_before_long_lived_database_open()
    {
        StateSnapshotInfo target;
        using (var database = new HostsDatabase(_databasePath))
        {
            database.SetMeta("snapshot_probe", "target");
            target = Coordinator(database).Create();
            database.SetMeta("snapshot_probe", "current");
            Coordinator(database).StageForStartup(target.Id, target.Sha256);
        }

        File.WriteAllText(_hostsPath, "# current\n0.0.0.0 current.example\n");
        var result = StateSnapshotCoordinator.ApplyPendingAtStartup(
            _databasePath, _hostsPath, _dir, "9.8.7", _snapshotRoot,
            context => File.ReadAllText(context.HostsPath).Contains("initial.example", StringComparison.Ordinal));

        result.Should().Match<StartupStateRestoreResult>(value => value.Restored && !value.RolledBack);
        File.Exists(Path.Combine(_dir, "pending_state_restore.json")).Should().BeFalse();
        using var restored = new HostsDatabase(_databasePath);
        restored.GetMeta("snapshot_probe").Should().Be("target");
        File.ReadAllText(_hostsPath).Should().Contain("initial.example");
    }

    [Fact]
    public void Failed_startup_validation_restores_durable_pre_start_state()
    {
        StateSnapshotInfo target;
        using (var database = new HostsDatabase(_databasePath))
        {
            database.SetMeta("snapshot_probe", "target");
            target = Coordinator(database).Create();
            database.SetMeta("snapshot_probe", "current");
            Coordinator(database).StageForStartup(target.Id, target.Sha256);
        }

        File.WriteAllText(_hostsPath, "# current\n0.0.0.0 current.example\n");
        var restore = () => StateSnapshotCoordinator.ApplyPendingAtStartup(
            _databasePath, _hostsPath, _dir, "9.8.7", _snapshotRoot, _ => false);

        restore.Should().Throw<StateSnapshotException>().WithMessage("*rolled back*");
        File.Exists(Path.Combine(_dir, "pending_state_restore.json")).Should().BeFalse();
        using var rolledBack = new HostsDatabase(_databasePath);
        rolledBack.GetMeta("snapshot_probe").Should().Be("current");
        File.ReadAllText(_hostsPath).Should().Contain("current.example");
    }

    [Fact]
    public void Interrupted_startup_apply_prefers_durable_fallback_over_partial_target()
    {
        StateSnapshotInfo target;
        StateSnapshotInfo fallback;
        using (var database = new HostsDatabase(_databasePath))
        {
            database.SetMeta("snapshot_probe", "target");
            target = Coordinator(database).Create();

            database.SetMeta("snapshot_probe", "fallback");
            File.WriteAllText(_hostsPath, "# fallback\n0.0.0.0 fallback.example\n");
            fallback = Coordinator(database).Create();
        }

        // Model a process loss after recording the fallback and replacing only
        // one component. The next start must not attempt to continue an unknown
        // partial copy.
        File.WriteAllText(_hostsPath, "# partial target\n0.0.0.0 initial.example\n");
        File.WriteAllText(
            Path.Combine(_dir, "pending_state_restore.json"),
            $$"""
            {
              "snapshotId": "{{target.Id}}",
              "expectedSha256": "{{target.Sha256}}",
              "preRestoreSnapshotId": "{{fallback.Id}}",
              "phase": "preparing"
            }
            """);

        var result = StateSnapshotCoordinator.ApplyPendingAtStartup(
            _databasePath, _hostsPath, _dir, "9.8.7", _snapshotRoot);

        result.RolledBack.Should().BeTrue();
        result.Restored.Should().BeFalse();
        File.Exists(Path.Combine(_dir, "pending_state_restore.json")).Should().BeFalse();
        using var rolledBack = new HostsDatabase(_databasePath);
        rolledBack.GetMeta("snapshot_probe").Should().Be("fallback");
        File.ReadAllText(_hostsPath).Should().Contain("fallback.example");
    }

    private StateSnapshotCoordinator Coordinator(
        HostsDatabase database,
        Func<StateRestoreValidationContext, bool>? validation = null) =>
        new(database, _hostsPath, _dir, "9.8.7", _snapshotRoot, validation);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
            // Best effort for antivirus-held SQLite sidecars.
        }
    }
}

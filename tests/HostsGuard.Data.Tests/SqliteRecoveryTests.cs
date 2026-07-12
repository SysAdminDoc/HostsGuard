using Dapper;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Data.Tests;

public sealed class SqliteRecoveryTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "hg_sqlite_recovery_" + Guid.NewGuid().ToString("N"));

    public SqliteRecoveryTests() => Directory.CreateDirectory(_dir);

    [Fact]
    public async Task Concurrent_writes_and_restart_checkpoints_preserve_every_commit()
    {
        var path = Path.Combine(_dir, "checkpoint.db");
        var connectionString = $"Data Source={path};Pooling=False;Default Timeout=5";
        using (var setup = new SqliteConnection(connectionString))
        {
            setup.Open();
            setup.Execute("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT NOT NULL);");
        }

        using var start = new ManualResetEventSlim(false);
        var writer = Task.Run(() =>
        {
            using var connection = new SqliteConnection(connectionString);
            connection.Open();
            connection.Execute("PRAGMA wal_autocheckpoint=0; PRAGMA busy_timeout=5000;");
            start.Wait();
            for (var id = 1; id <= 100; id++)
            {
                connection.Execute("INSERT INTO items(id,value) VALUES(@id,@value)", new { id, value = $"row-{id}" });
            }
        });
        var checkpointer = Task.Run(() =>
        {
            using var connection = new SqliteConnection(connectionString);
            connection.Open();
            connection.Execute("PRAGMA busy_timeout=5000;");
            start.Wait();
            for (var i = 0; i < 40; i++)
            {
                connection.Query("PRAGMA wal_checkpoint(RESTART)").ToList();
            }
        });

        start.Set();
        await Task.WhenAll(writer, checkpointer);

        using (var checkpoint = new SqliteConnection(connectionString))
        {
            checkpoint.Open();
            checkpoint.Query("PRAGMA wal_checkpoint(TRUNCATE)").ToList();
        }

        using var reopened = new SqliteConnection(connectionString);
        reopened.Open();
        reopened.ExecuteScalar<long>("SELECT COUNT(*) FROM items").Should().Be(100);
        reopened.ExecuteScalar<string>("PRAGMA integrity_check").Should().Be("ok");
    }

    [Fact]
    public void Uncheckpointed_wal_image_recovers_committed_rows_after_reopen()
    {
        var sourcePath = Path.Combine(_dir, "live.db");
        var recoveredPath = Path.Combine(_dir, "recovered.db");
        using var live = new SqliteConnection($"Data Source={sourcePath};Pooling=False");
        live.Open();
        live.Execute("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE events(id INTEGER PRIMARY KEY, value TEXT NOT NULL);");
        live.Query("PRAGMA wal_checkpoint(TRUNCATE)").ToList();
        live.Execute("INSERT INTO events(value) VALUES('committed-only-in-wal')");
        File.Exists(sourcePath + "-wal").Should().BeTrue();

        File.Copy(sourcePath, recoveredPath);
        File.Copy(sourcePath + "-wal", recoveredPath + "-wal");

        using var recovered = new SqliteConnection($"Data Source={recoveredPath};Pooling=False");
        recovered.Open();
        recovered.ExecuteScalar<string>("SELECT value FROM events").Should().Be("committed-only-in-wal");
        recovered.ExecuteScalar<string>("PRAGMA integrity_check").Should().Be("ok");
    }

    [Fact]
    public void Online_backup_restores_schema_and_policy_state()
    {
        var sourcePath = Path.Combine(_dir, "source.db");
        var backupPath = Path.Combine(_dir, "backup.db");
        using (var database = new HostsDatabase(sourcePath))
        {
            database.SetMeta("backup_probe", "preserved");
            using var source = new SqliteConnection($"Data Source={sourcePath};Pooling=False");
            using var backup = new SqliteConnection($"Data Source={backupPath};Pooling=False");
            source.Open();
            backup.Open();
            source.BackupDatabase(backup);
        }

        SqliteConnection.ClearAllPools();
        using var restored = new HostsDatabase(backupPath);
        restored.GetMeta("backup_probe").Should().Be("preserved");
        restored.SchemaVersionOnDisk().Should().Be(HostsDatabase.SchemaVersion);
        using var verify = new SqliteConnection($"Data Source={backupPath};Pooling=False");
        verify.Open();
        verify.ExecuteScalar<string>("PRAGMA integrity_check").Should().Be("ok");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_dir, true);
        }
        catch (IOException)
        {
            // Best effort.
        }
    }
}

using FluentAssertions;

namespace HostsGuard.Windows.Tests;

public sealed class LocalDataPurgerTests : IDisposable
{
    private readonly string _tempRoot = Path.Combine(
        Path.GetTempPath(), $"HostsGuard-purge-tests-{Guid.NewGuid():N}");

    [Fact]
    public void Purge_removes_nested_data_root()
    {
        var nested = Path.Combine(_tempRoot, "nested");
        Directory.CreateDirectory(nested);
        File.WriteAllText(Path.Combine(nested, "state.json"), "state");

        var result = LocalDataPurger.PurgeRootsForTesting([_tempRoot], _ => false);

        result.Complete.Should().BeTrue();
        result.DeletedFiles.Should().Be(1);
        result.DeletedDirectories.Should().Be(2);
        Directory.Exists(_tempRoot).Should().BeFalse();
    }

    [Fact]
    public void Locked_entries_are_deferred_and_reported()
    {
        Directory.CreateDirectory(_tempRoot);
        var lockedPath = Path.Combine(_tempRoot, "hostsguard.db");
        File.WriteAllText(lockedPath, "state");
        var scheduled = new List<string>();

        LocalDataPurgeResult result;
        using (File.Open(lockedPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            result = LocalDataPurger.PurgeRootsForTesting(
                [_tempRoot],
                path =>
                {
                    scheduled.Add(path);
                    return true;
                });
        }

        result.Complete.Should().BeFalse();
        result.Errors.Should().BeEmpty();
        result.DeferredEntries.Should().BeGreaterThan(0);
        scheduled.Should().Contain(lockedPath);
    }

    [Fact]
    public void Reparse_directories_are_never_traversal_candidates()
    {
        LocalDataPurger.ShouldTraverseDirectory(FileAttributes.Directory).Should().BeTrue();
        LocalDataPurger.ShouldTraverseDirectory(
            FileAttributes.Directory | FileAttributes.ReparsePoint).Should().BeFalse();
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempRoot))
        {
            Directory.Delete(_tempRoot, recursive: true);
        }
    }
}

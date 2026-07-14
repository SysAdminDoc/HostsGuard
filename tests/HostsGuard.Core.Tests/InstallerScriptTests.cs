using FluentAssertions;

namespace HostsGuard.Core.Tests;

public sealed class InstallerScriptTests
{
    [Fact]
    public void Installer_restores_and_verifies_safe_posture_before_launching_the_app()
    {
        var script = File.ReadAllText(RepoFile("installer-dotnet.iss"));

        var serviceStart = script.IndexOf("Parameters: \"start {#MyServiceName}\"", StringComparison.Ordinal);
        var safePosture = script.IndexOf("Parameters: \"safe-posture\"", StringComparison.Ordinal);
        var safeSmoke = script.IndexOf("Parameters: \"safe-posture-smoke\"", StringComparison.Ordinal);
        var launchApp = script.IndexOf("Description: \"Launch HostsGuard\"", StringComparison.Ordinal);

        serviceStart.Should().BeGreaterThanOrEqualTo(0);
        safePosture.Should().BeGreaterThan(serviceStart);
        safeSmoke.Should().BeGreaterThan(safePosture);
        launchApp.Should().BeGreaterThan(safeSmoke);
        script.Should().Contain("leaves hosts-file blocks");
        script.Should().Contain("StatusMsg: \"Restoring safe network posture...\"");
        script.Should().Contain("StatusMsg: \"Verifying safe network posture...\"");
    }

    [Fact]
    public void Installer_packages_the_runtime_specific_migrator()
    {
        var script = File.ReadAllText(RepoFile("installer-dotnet.iss"));

        script.Should().Contain(
            "Source: \"dist\\dotnet\\{#TargetRid}\\migrator\\*\"; DestDir: \"{app}\\migrator\"");
    }

    private static string RepoFile(string name)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, name);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            dir = dir.Parent;
        }

        throw new FileNotFoundException($"Could not find {name} above {AppContext.BaseDirectory}");
    }
}

using FluentAssertions;

namespace HostsGuard.Core.Tests;

public sealed class InstallerScriptTests
{
    [Fact]
    public void Installer_health_checks_upgrades_without_resetting_posture_and_safes_fresh_installs()
    {
        var script = File.ReadAllText(RepoFile("installer-dotnet.iss"));

        script.Should().Contain("'start {#MyServiceName}'");
        script.Should().Contain("update health --expected");
        script.Should().Contain("if WasUpgrade then");
        script.Should().Contain("'safe-posture'");
        script.Should().Contain("'safe-posture-smoke'");
        script.Should().Contain("Upgrades intentionally skip");
        script.Should().Contain("Check: CanLaunchApp");
        script.Should().NotContain("Filename: \"{app}\\cli\\HostsGuard.Cli.exe\"; Parameters: \"safe-posture\"");
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

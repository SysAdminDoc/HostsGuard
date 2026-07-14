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

    [Fact]
    public void Uninstaller_defaults_to_retention_and_requires_an_explicit_silent_purge()
    {
        var script = File.ReadAllText(RepoFile("installer-dotnet.iss"));

        script.Should().Contain("/PURGELOCALDATA");
        script.Should().Contain("/RETAINLOCALDATA");
        script.Should().Contain("Silent uninstall defaults to retention");
        script.Should().Contain("Retain for reinstall (default)");
        script.Should().Contain("Purge all HostsGuard local data");
        script.Should().Contain("{commonappdata}\\HostsGuard");
        script.Should().Contain("{userappdata}\\HostsGuard");
    }

    [Fact]
    public void Uninstaller_runs_bounded_purge_and_reports_reboot_deferment()
    {
        var script = File.ReadAllText(RepoFile("installer-dotnet.iss"));

        script.Should().Contain("'purge-local-data'");
        script.Should().Contain("if ResultCode = 3 then");
        script.Should().Contain("scheduled for deletion at the next Windows restart");
        script.Should().Contain("function UninstallNeedRestart(): Boolean;");
        script.Should().NotContain("[UninstallRun]");
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

using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public sealed class InterpreterCommandLineTests
{
    [Theory]
    [InlineData(@"C:\Program Files\nodejs\node.exe", "\"C:\\Program Files\\nodejs\\node.exe\" C:\\dev\\scraper\\index.js", "node C:\\dev\\scraper\\index.js", "C:\\dev\\scraper\\index.js")]
    [InlineData(@"C:\Python312\python.exe", "python.exe -m http.server", "python -m http.server", "-m http.server")]
    [InlineData(@"C:\Program Files\PowerShell\7\pwsh.exe", "pwsh.exe -NoProfile -File C:\\ops\\sync.ps1", "pwsh C:\\ops\\sync.ps1", "C:\\ops\\sync.ps1")]
    [InlineData(@"C:\Program Files\Eclipse Adoptium\bin\java.exe", "java.exe -Xmx1g -jar C:\\apps\\server.jar", "java C:\\apps\\server.jar", "C:\\apps\\server.jar")]
    [InlineData(@"C:\Windows\System32\wscript.exe", "wscript.exe //B C:\\scripts\\legacy.vbs", "wscript C:\\scripts\\legacy.vbs", "C:\\scripts\\legacy.vbs")]
    public void TryCreate_extracts_script_identity_for_interpreters(string app, string cmd, string display, string script)
    {
        var binding = InterpreterCommandLine.TryCreate(app, cmd);

        binding.Should().NotBeNull();
        binding!.Display.Should().Be(display);
        binding.ScriptPath.Should().Be(script);
        binding.ScriptKey.Should().Contain(script.ToLowerInvariant());
    }

    [Theory]
    [InlineData(@"C:\apps\curl.exe", "curl.exe https://example.com")]
    [InlineData(@"C:\Program Files\nodejs\node.exe", "node.exe -e \"console.log(1)\"")]
    [InlineData(@"C:\Program Files\PowerShell\7\pwsh.exe", "pwsh.exe -Command Get-Date")]
    public void TryCreate_ignores_non_interpreter_or_inline_commands(string app, string cmd)
        => InterpreterCommandLine.TryCreate(app, cmd).Should().BeNull();
}

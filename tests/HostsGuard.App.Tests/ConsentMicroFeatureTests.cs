using System.IO;
using FluentAssertions;
using HostsGuard.App.Services;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>NET-085: the sound-on-block config toggle round-trip.</summary>
public sealed class ConsentMicroFeatureTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("hg_micro_").FullName;

    private string ConfigPath => Path.Combine(_dir, "config.json");

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, true);
        }
        catch (IOException)
        {
            // best effort
        }
    }

    [Fact]
    public void Sound_on_block_defaults_off_and_round_trips()
    {
        var store = new AppConfigStore(ConfigPath);
        store.Load();
        store.SoundOnBlock.Should().BeFalse();

        store.SaveSoundOnBlock(true);

        var reread = new AppConfigStore(ConfigPath);
        reread.Load();
        reread.SoundOnBlock.Should().BeTrue();
    }

    [Fact]
    public void Sound_toggle_preserves_foreign_keys()
    {
        File.WriteAllText(ConfigPath, """{"theme":"light","learning_mode":true,"webhook_url":"https://x"}""");
        var store = new AppConfigStore(ConfigPath);
        store.Load();

        store.SaveSoundOnBlock(true);

        var text = File.ReadAllText(ConfigPath);
        text.Should().Contain("webhook_url").And.Contain("learning_mode");
    }
}

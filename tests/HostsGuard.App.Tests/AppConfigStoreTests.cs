using System.IO;
using FluentAssertions;
using HostsGuard.App.Services;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class AppConfigStoreTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("hg_cfg_").FullName;

    private string ConfigPath => Path.Combine(_dir, "config.json");

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public void Defaults_are_dark_100()
    {
        var store = new AppConfigStore(ConfigPath);
        store.Load();

        store.Theme.Should().Be("dark");
        store.UiScalePct.Should().Be(100);
    }

    [Fact]
    public void Save_preserves_keys_owned_by_the_python_build()
    {
        // The Python app owns many other keys in the same file — a UI-settings
        // save must never clobber them.
        File.WriteAllText(ConfigPath,
            """{"theme": "light", "ui_scale_pct": 125, "doh_block": true, "schedules": [{"target": "x"}]}""");

        var store = new AppConfigStore(ConfigPath);
        store.Load();
        store.Theme.Should().Be("light");
        store.UiScalePct.Should().Be(125);

        store.Save("dark", 150);

        var text = File.ReadAllText(ConfigPath);
        text.Should().Contain("\"doh_block\"").And.Contain("\"schedules\"");
        var reread = new AppConfigStore(ConfigPath);
        reread.Load();
        reread.Theme.Should().Be("dark");
        reread.UiScalePct.Should().Be(150);
    }

    [Fact]
    public void Corrupt_config_falls_back_to_defaults_without_clobbering()
    {
        File.WriteAllText(ConfigPath, "{not json");

        var store = new AppConfigStore(ConfigPath);
        store.Load();

        store.Theme.Should().Be("dark");
        store.UiScalePct.Should().Be(100);
        File.ReadAllText(ConfigPath).Should().Be("{not json"); // load alone never writes
    }

    [Theory]
    [InlineData(null, 100)]
    [InlineData("garbage", 100)]
    [InlineData("100", 100)]
    [InlineData("125%", 125)]
    [InlineData("118", 125)]   // snaps to the nearest supported step
    [InlineData("55", 90)]
    [InlineData("400", 150)]
    public void Ui_scale_coerces_like_the_python_build(string? raw, int expected)
        => AppConfigStore.CoerceUiScale(raw).Should().Be(expected);

    [Fact]
    public void Modes_round_trip_python_keys_and_preserve_foreign_state()
    {
        // learning_mode / observe_mode are the exact keys LearnDB uses; the
        // Python-owned trust lists in the same file must survive a mode save.
        File.WriteAllText(ConfigPath,
            """{"learning_mode": true, "observe_mode": false, "trusted_procs": ["chrome.exe"]}""");

        var store = new AppConfigStore(ConfigPath);
        store.Load();
        store.LearningMode.Should().BeTrue();
        store.ObserveMode.Should().BeFalse();

        store.SaveModes(learning: false, observe: true);

        File.ReadAllText(ConfigPath).Should().Contain("\"trusted_procs\"").And.Contain("chrome.exe");
        var reread = new AppConfigStore(ConfigPath);
        reread.Load();
        reread.LearningMode.Should().BeFalse();
        reread.ObserveMode.Should().BeTrue();
    }
}

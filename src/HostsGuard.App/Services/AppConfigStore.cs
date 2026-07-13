using System.IO;
using System.Text.Json.Nodes;

namespace HostsGuard.App.Services;

/// <summary>
/// UI settings persisted in the same %APPDATA%\HostsGuard\config.json the
/// Python build uses (keys: <c>theme</c>, <c>ui_scale_pct</c>), so a user's
/// look-and-feel survives the .NET cutover. Reads and writes preserve every
/// key we don't own — the file is shared state, never ours to rewrite.
/// </summary>
public sealed class AppConfigStore
{
    public static readonly IReadOnlyList<int> UiScaleChoices = new[] { 90, 100, 110, 125, 150 };

    private readonly string _path;

    public AppConfigStore(string? path = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "HostsGuard", "config.json");
    }

    public string FilePath => _path;

    public string Theme { get; private set; } = "dark";

    public int UiScalePct { get; private set; } = 100;

    /// <summary>UI language BCP-47 tag ("" = follow the Windows display language) — NET-098.</summary>
    public string Language { get; private set; } = string.Empty;

    /// <summary>Offered UI languages: (tag, English name). "" = system default.</summary>
    public static readonly IReadOnlyList<(string Tag, string Name)> Languages = new[]
    {
        ("", "System default"),
        ("en", "English"),
        ("es", "Español"),
        ("de", "Deutsch"),
        ("fr", "Français"),
    };

    /// <summary>Canonical bound language menu shown by the shell.</summary>
    public static readonly IReadOnlyList<LanguageOption> LanguageOptions = new[]
    {
        new LanguageOption("", "Language_System", "System default"),
        new LanguageOption("en", "Language_English", "English"),
        new LanguageOption("es", "Language_Spanish", "EspaÃ±ol"),
        new LanguageOption("de", "Language_German", "Deutsch"),
        new LanguageOption("fr", "Language_French", "FranÃ§ais"),
    };

    /// <summary>Learning mode: surface trust prompts for unknown processes.</summary>
    public bool LearningMode { get; private set; }

    /// <summary>Observe mode: record decisions silently instead of prompting.</summary>
    public bool ObserveMode { get; private set; }

    /// <summary>Play a system sound when a connection is blocked/prompted (NET-085).</summary>
    public bool SoundOnBlock { get; private set; }

    /// <summary>Clamp any persisted value to the nearest supported scale step.</summary>
    public static int CoerceUiScale(object? value)
    {
        var text = value?.ToString()?.Replace("%", "", StringComparison.Ordinal).Trim();
        if (!int.TryParse(text, out var pct))
        {
            return 100;
        }

        return UiScaleChoices.Contains(pct)
            ? pct
            : UiScaleChoices.MinBy(c => Math.Abs(c - pct));
    }

    public void Load()
    {
        var root = ReadRoot();
        Theme = root["theme"]?.GetValue<string>() == "light" ? "light" : "dark";
        UiScalePct = CoerceUiScale(root["ui_scale_pct"]?.ToString());
        LearningMode = ReadBool(root, "learning_mode");
        ObserveMode = ReadBool(root, "observe_mode");
        SoundOnBlock = ReadBool(root, "sound_on_block");
        Language = root["language"]?.GetValue<string>() ?? string.Empty;
    }

    /// <summary>Persist the UI language tag (NET-098); "" follows the system.</summary>
    public void SaveLanguage(string tag)
    {
        Language = tag ?? string.Empty;
        var root = ReadRoot();
        root["language"] = Language;
        WriteRoot(root);
    }

    /// <summary>Persist the block-sound toggle (NET-085).</summary>
    public void SaveSoundOnBlock(bool enabled)
    {
        SoundOnBlock = enabled;
        var root = ReadRoot();
        root["sound_on_block"] = enabled;
        WriteRoot(root);
    }

    public void Save(string theme, int uiScalePct)
    {
        Theme = theme == "light" ? "light" : "dark";
        UiScalePct = CoerceUiScale(uiScalePct);

        var root = ReadRoot();
        root["theme"] = Theme;
        root["ui_scale_pct"] = UiScalePct;
        WriteRoot(root);
    }

    /// <summary>
    /// Persist the learning/observe flags under the exact keys the Python build
    /// uses (<c>learning_mode</c>, <c>observe_mode</c>) so the modes survive the
    /// cutover in both directions.
    /// </summary>
    public void SaveModes(bool learning, bool observe)
    {
        LearningMode = learning;
        ObserveMode = observe;

        var root = ReadRoot();
        root["learning_mode"] = learning;
        root["observe_mode"] = observe;
        WriteRoot(root);
    }

    /// <summary>Read a persisted boolean view toggle (e.g. "activity_hide_blocked").</summary>
    public bool GetViewFlag(string key, bool defaultValue = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        var root = ReadRoot();
        return root[key] is JsonValue value && value.TryGetValue<bool>(out var b) ? b : defaultValue;
    }

    /// <summary>Persist a boolean view toggle, preserving every other key in the file.</summary>
    public void SaveViewFlag(string key, bool value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        var root = ReadRoot();
        root[key] = value;
        WriteRoot(root);
    }

    private static bool ReadBool(JsonObject root, string key)
        => root[key] is JsonValue value && value.TryGetValue<bool>(out var b) && b;

    private void WriteRoot(JsonObject root)
    {
        var dir = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var tmp = _path + "." + Environment.CurrentManagedThreadId + ".tmp";
        File.WriteAllText(tmp, root.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        File.Move(tmp, _path, overwrite: true);
    }

    private JsonObject ReadRoot()
    {
        try
        {
            if (File.Exists(_path))
            {
                return JsonNode.Parse(File.ReadAllText(_path)) as JsonObject ?? new JsonObject();
            }
        }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or UnauthorizedAccessException)
        {
            // Unreadable/corrupt config falls back to defaults; we never clobber
            // the file with defaults unless the user actually saves a setting.
        }

        return new JsonObject();
    }
}

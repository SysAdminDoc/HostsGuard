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
    }

    public void Save(string theme, int uiScalePct)
    {
        Theme = theme == "light" ? "light" : "dark";
        UiScalePct = CoerceUiScale(uiScalePct);

        var root = ReadRoot();
        root["theme"] = Theme;
        root["ui_scale_pct"] = UiScalePct;

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

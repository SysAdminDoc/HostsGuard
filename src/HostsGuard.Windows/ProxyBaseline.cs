using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace HostsGuard.Windows;

public enum ProxyStateScope
{
    WinInetUser,
    WinHttpMachine,
}

/// <summary>
/// A normalized, persistence-safe proxy configuration. Credentials in proxy
/// endpoints and query/fragment data in PAC URLs are never returned. The
/// fingerprint still changes when a redacted value changes.
/// </summary>
public sealed record ProxySettings(
    bool ProxyEnabled,
    string ProxyServer,
    string ProxyBypass,
    bool AutoConfigEnabled,
    string AutoConfigUrl,
    bool AutoDetect,
    bool PerUserProxySettings,
    bool Available,
    string Error,
    string Fingerprint);

public sealed record ProxyStateEntry(ProxyStateScope Scope, string Identity, ProxySettings Settings);

public sealed record ProxyBaselineSnapshot(IReadOnlyList<ProxyStateEntry> Entries);

public sealed record ProxyStateChange(
    ProxyStateScope Scope,
    string Identity,
    ProxySettings? Before,
    ProxySettings? After);

/// <summary>
/// Captures loaded-user WinINET proxy/PAC state and machine WinHTTP advanced
/// proxy/PAC state without mutating either surface. Loaded HKEY_USERS profiles
/// are used instead of HKCU because the caller normally runs as LocalSystem.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProxyBaselineSnapshotter
{
    private readonly IProxyStateSource _source;

    public ProxyBaselineSnapshotter()
        : this(new WindowsProxyStateSource())
    {
    }

    internal ProxyBaselineSnapshotter(IProxyStateSource source)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
    }

    public ProxyBaselineSnapshot Capture()
    {
        var entries = _source.CaptureWinInetUsers()
            .Append(_source.CaptureWinHttpMachine())
            .OrderBy(e => e.Scope)
            .ThenBy(e => e.Identity, StringComparer.Ordinal)
            .ToArray();
        return new ProxyBaselineSnapshot(entries);
    }

    public static IReadOnlyList<ProxyStateChange> Diff(
        ProxyBaselineSnapshot before,
        ProxyBaselineSnapshot after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);

        var oldEntries = ToMap(before.Entries);
        var newEntries = ToMap(after.Entries);
        var keys = new SortedSet<(ProxyStateScope Scope, string Identity)>(
            Comparer<(ProxyStateScope Scope, string Identity)>.Create((left, right) =>
            {
                var scope = left.Scope.CompareTo(right.Scope);
                return scope != 0 ? scope : StringComparer.Ordinal.Compare(left.Identity, right.Identity);
            }));
        keys.UnionWith(oldEntries.Keys);
        keys.UnionWith(newEntries.Keys);

        var changes = new List<ProxyStateChange>();
        foreach (var key in keys)
        {
            oldEntries.TryGetValue(key, out var oldEntry);
            newEntries.TryGetValue(key, out var newEntry);
            if (oldEntry?.Settings != newEntry?.Settings)
            {
                changes.Add(new ProxyStateChange(key.Scope, key.Identity, oldEntry?.Settings, newEntry?.Settings));
            }
        }

        return changes;
    }

    private static Dictionary<(ProxyStateScope Scope, string Identity), ProxyStateEntry> ToMap(
        IReadOnlyList<ProxyStateEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var map = new Dictionary<(ProxyStateScope Scope, string Identity), ProxyStateEntry>();
        foreach (var entry in entries)
        {
            var key = (entry.Scope, entry.Identity);
            if (!map.TryAdd(key, entry))
            {
                throw new ArgumentException($"Duplicate proxy snapshot entry: {entry.Scope}/{entry.Identity}", nameof(entries));
            }
        }

        return map;
    }
}

internal interface IProxyStateSource
{
    IReadOnlyList<ProxyStateEntry> CaptureWinInetUsers();
    ProxyStateEntry CaptureWinHttpMachine();
}

[SupportedOSPlatform("windows")]
internal sealed class WindowsProxyStateSource : IProxyStateSource
{
    private const string InternetSettingsPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    public IReadOnlyList<ProxyStateEntry> CaptureWinInetUsers()
    {
        var identities = LoadedUserSids();
        var entries = new List<ProxyStateEntry>(identities.Count);
        foreach (var sid in identities)
        {
            try
            {
                using var key = Registry.Users.OpenSubKey($@"{sid}\{InternetSettingsPath}");
                var enabled = ReadBoolean(key?.GetValue("ProxyEnable"));
                var server = ReadString(key?.GetValue("ProxyServer"));
                var bypass = ReadString(key?.GetValue("ProxyOverride"));
                var pac = ReadString(key?.GetValue("AutoConfigURL"));
                entries.Add(new ProxyStateEntry(
                    ProxyStateScope.WinInetUser,
                    sid,
                    ProxyStateNormalizer.Create(
                        enabled,
                        server,
                        bypass,
                        autoConfigEnabled: pac.Length != 0,
                        pac,
                        autoDetect: false,
                        perUserProxySettings: true)));
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                entries.Add(new ProxyStateEntry(
                    ProxyStateScope.WinInetUser,
                    sid,
                    ProxyStateNormalizer.Unavailable($"{ex.GetType().Name}: WinINET proxy state unavailable.")));
            }
        }

        return entries;
    }

    public ProxyStateEntry CaptureWinHttpMachine()
    {
        try
        {
            var result = NetshRunner.RunAdvancedProxyQuery();
            if (result.ExitCode == 0 && ProxyStateNormalizer.TryParseWinHttpAdvancedJson(result.StandardOutput, out var settings))
            {
                return new ProxyStateEntry(ProxyStateScope.WinHttpMachine, "machine", settings);
            }

            var fallback = CaptureWinHttpLegacy();
            var detail = result.TimedOut
                ? "Advanced WinHTTP proxy query timed out; captured legacy manual proxy state."
                : $"Advanced WinHTTP proxy query unavailable; captured legacy manual proxy state (exit {result.ExitCode}).";
            return new ProxyStateEntry(
                ProxyStateScope.WinHttpMachine,
                "machine",
                fallback with { Error = detail });
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException)
        {
            return new ProxyStateEntry(
                ProxyStateScope.WinHttpMachine,
                "machine",
                ProxyStateNormalizer.Unavailable($"{ex.GetType().Name}: WinHTTP proxy state unavailable."));
        }
    }

    private static List<string> LoadedUserSids()
    {
        var sids = Registry.Users.GetSubKeyNames()
            .Where(IsUserSid)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(s => s, StringComparer.Ordinal)
            .ToList();

        // A normal unelevated process always maps HKCU under HKEY_USERS, but
        // retain the current SID if a constrained registry view omitted it.
        using var identity = WindowsIdentity.GetCurrent();
        var current = identity.User?.Value;
        if (current is not null && !sids.Contains(current, StringComparer.Ordinal))
        {
            sids.Add(current);
            sids.Sort(StringComparer.Ordinal);
        }

        return sids;
    }

    internal static bool IsUserSid(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            _ = new SecurityIdentifier(value);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool ReadBoolean(object? value)
    {
        try
        {
            return value is not null && Convert.ToInt64(value, CultureInfo.InvariantCulture) != 0;
        }
        catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException)
        {
            return false;
        }
    }

    private static string ReadString(object? value)
        => Convert.ToString(value, CultureInfo.InvariantCulture)?.Trim() ?? string.Empty;

    private static ProxySettings CaptureWinHttpLegacy()
    {
        if (!WinHttpGetDefaultProxyConfiguration(out var info))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            var server = Marshal.PtrToStringUni(info.Proxy) ?? string.Empty;
            var bypass = Marshal.PtrToStringUni(info.ProxyBypass) ?? string.Empty;
            return ProxyStateNormalizer.Create(
                proxyEnabled: info.AccessType == WinHttpAccessTypeNamedProxy,
                server,
                bypass,
                autoConfigEnabled: false,
                autoConfigUrl: string.Empty,
                autoDetect: false,
                perUserProxySettings: false);
        }
        finally
        {
            if (info.Proxy != IntPtr.Zero)
            {
                _ = GlobalFree(info.Proxy);
            }

            if (info.ProxyBypass != IntPtr.Zero)
            {
                _ = GlobalFree(info.ProxyBypass);
            }
        }
    }

    private const int WinHttpAccessTypeNamedProxy = 3;

    [StructLayout(LayoutKind.Sequential)]
    private struct WinHttpProxyInfo
    {
        public int AccessType;
        public IntPtr Proxy;
        public IntPtr ProxyBypass;
    }

    [DllImport("winhttp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinHttpGetDefaultProxyConfiguration(out WinHttpProxyInfo proxyInfo);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GlobalFree(IntPtr memory);
}

internal static class ProxyStateNormalizer
{
    internal static ProxySettings Create(
        bool proxyEnabled,
        string proxyServer,
        string proxyBypass,
        bool autoConfigEnabled,
        string autoConfigUrl,
        bool autoDetect,
        bool perUserProxySettings)
    {
        proxyServer = proxyServer.Trim();
        proxyBypass = proxyBypass.Trim();
        autoConfigUrl = autoConfigUrl.Trim();
        var fingerprint = Fingerprint(
            proxyEnabled,
            proxyServer,
            proxyBypass,
            autoConfigEnabled,
            autoConfigUrl,
            autoDetect,
            perUserProxySettings);

        return new ProxySettings(
            proxyEnabled,
            RedactProxyCredentials(proxyServer),
            proxyBypass,
            autoConfigEnabled,
            SanitizePacUrl(autoConfigUrl),
            autoDetect,
            perUserProxySettings,
            Available: true,
            Error: string.Empty,
            fingerprint);
    }

    internal static ProxySettings Unavailable(string error)
        => new(
            ProxyEnabled: false,
            ProxyServer: string.Empty,
            ProxyBypass: string.Empty,
            AutoConfigEnabled: false,
            AutoConfigUrl: string.Empty,
            AutoDetect: false,
            PerUserProxySettings: false,
            Available: false,
            Error: NormalizeError(error),
            Fingerprint: string.Empty);

    internal static bool TryParseWinHttpAdvancedJson(string output, out ProxySettings settings)
    {
        settings = Unavailable("Invalid WinHTTP advanced proxy response.");
        var start = output.IndexOf('{');
        var end = output.LastIndexOf('}');
        if (start < 0 || end <= start)
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(output[start..(end + 1)], new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
            });
            var root = document.RootElement;
            settings = Create(
                ReadBool(root, "ProxyIsEnabled"),
                ReadText(root, "Proxy"),
                ReadText(root, "ProxyBypass"),
                ReadBool(root, "AutoConfigIsEnabled"),
                ReadText(root, "AutoConfigUrl"),
                ReadBool(root, "AutoDetect"),
                ReadBool(root, "PerUserProxySettings"));
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool ReadBool(JsonElement root, string name)
        => root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;

    private static string ReadText(JsonElement root, string name)
        => root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;

    internal static string RedactProxyCredentials(string value)
    {
        if (value.Length == 0)
        {
            return value;
        }

        return string.Join(';', value.Split(';').Select(segment =>
        {
            var at = segment.LastIndexOf('@');
            if (at < 0)
            {
                return segment.Trim();
            }

            var equals = segment.IndexOf('=');
            var scheme = segment.IndexOf("://", StringComparison.Ordinal);
            var credentialStart = Math.Max(equals + 1, scheme >= 0 ? scheme + 3 : 0);
            return credentialStart < at
                ? string.Concat(segment.AsSpan(0, credentialStart), "[redacted]@", segment.AsSpan(at + 1)).Trim()
                : segment.Trim();
        }));
    }

    internal static string SanitizePacUrl(string value)
    {
        if (value.Length == 0)
        {
            return value;
        }

        if (Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            var builder = new UriBuilder(uri)
            {
                UserName = string.Empty,
                Password = string.Empty,
                Query = string.Empty,
                Fragment = string.Empty,
            };
            return builder.Uri.GetLeftPart(UriPartial.Path);
        }

        var boundary = value.IndexOfAny(['?', '#']);
        return RedactProxyCredentials(boundary < 0 ? value : value[..boundary]);
    }

    private static string Fingerprint(params object[] values)
    {
        var canonical = string.Join('\n', values.Select(value => Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private static string NormalizeError(string value)
    {
        var normalized = string.Join(' ', value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return normalized.Length <= 240 ? normalized : normalized[..240];
    }
}

internal readonly record struct NetshResult(int ExitCode, string StandardOutput, bool TimedOut);

internal static class NetshRunner
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(3);

    internal static NetshResult RunAdvancedProxyQuery()
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "netsh.exe"),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            },
        };
        process.StartInfo.ArgumentList.Add("winhttp");
        process.StartInfo.ArgumentList.Add("show");
        process.StartInfo.ArgumentList.Add("advproxy");
        process.StartInfo.ArgumentList.Add("setting-scope=machine");

        if (!process.Start())
        {
            throw new InvalidOperationException("Unable to start the WinHTTP proxy query.");
        }

        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(Timeout);
        try
        {
            process.WaitForExitAsync(timeout.Token).GetAwaiter().GetResult();
            Task.WhenAll(stdout, stderr).GetAwaiter().GetResult();
            return new NetshResult(process.ExitCode, stdout.Result, TimedOut: false);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit();
            }
            catch (InvalidOperationException)
            {
                // The process exited between cancellation and termination.
            }

            return new NetshResult(-1, string.Empty, TimedOut: true);
        }
    }
}

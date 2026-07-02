using System.Runtime.Versioning;
using Microsoft.Win32;

namespace HostsGuard.Windows;

/// <summary>Raised when the hosts file changes in a way we did not write.</summary>
public sealed class HostsTamperEventArgs(string path, string sha512Hex) : EventArgs
{
    public string Path { get; } = path;

    public string Sha512Hex { get; } = sha512Hex;
}

/// <summary>
/// Real-time hosts-file tamper watch. Uses <see cref="FileSystemWatcher"/>
/// (ReadDirectoryChangesW under the hood) instead of mtime polling, and
/// distinguishes our own writes via the engine's SHA-512 self-write hash, so a
/// self-restore never re-triggers. Also exposes a registry DataBasePath check for
/// the classic hosts-redirect hijack.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HostsTamperWatch : IDisposable
{
    private const string ExpectedDataBasePath = @"%SystemRoot%\System32\drivers\etc";

    private readonly HostsEngine _engine;
    private readonly FileSystemWatcher _watcher;
    private readonly object _gate = new();
    private string _lastHash = string.Empty;

    /// <summary>Fires (once per distinct external content) when a non-self change is seen.</summary>
    public event EventHandler<HostsTamperEventArgs>? ExternalChangeDetected;

    public HostsTamperWatch(HostsEngine engine)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        var dir = Path.GetDirectoryName(_engine.HostsPath)!;
        var file = Path.GetFileName(_engine.HostsPath);
        _lastHash = SafeHash();
        _watcher = new FileSystemWatcher(dir, file)
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.CreationTime | NotifyFilters.FileName | NotifyFilters.Size,
            IncludeSubdirectories = false,
        };
        _watcher.Changed += OnChanged;
        _watcher.Created += OnChanged;
        _watcher.Renamed += OnChanged;
    }

    public void Start() => _watcher.EnableRaisingEvents = true;

    public void Stop() => _watcher.EnableRaisingEvents = false;

    private void OnChanged(object sender, FileSystemEventArgs e)
    {
        // FileSystemWatcher can fire several events per write; act only on distinct content.
        string hash;
        lock (_gate)
        {
            hash = SafeHash();
            if (hash.Length == 0 || hash == _lastHash)
            {
                return;
            }

            _lastHash = hash;
        }

        if (_engine.IsSelfChange(hash))
        {
            return; // our own write — ignore
        }

        ExternalChangeDetected?.Invoke(this, new HostsTamperEventArgs(_engine.HostsPath, hash));
    }

    private string SafeHash()
    {
        try
        {
            return _engine.CurrentFileHash();
        }
        catch (IOException)
        {
            return string.Empty; // mid-write; a later event will settle
        }
    }

    /// <summary>After acting on our own restore, resync the baseline so the resulting change isn't flagged.</summary>
    public void AcceptCurrentState()
    {
        lock (_gate)
        {
            _lastHash = SafeHash();
        }
    }

    /// <summary>
    /// The malware "hosts redirect" check: reads
    /// HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DataBasePath and
    /// returns the redirected value if it no longer points at the etc directory,
    /// otherwise null.
    /// </summary>
    public static string? CheckRegistryTamper()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");
        // GetValue expands REG_EXPAND_SZ, so the stored %SystemRoot% may already be a literal.
        var value = key?.GetValue("DataBasePath") as string;
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        static string Norm(string s) => Environment.ExpandEnvironmentVariables(s).TrimEnd('\\').ToLowerInvariant();

        var actual = Norm(value);
        var expectedFromRegTemplate = Norm(ExpectedDataBasePath);
        var expectedFromSystem = Norm(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc"));

        return actual == expectedFromRegTemplate || actual == expectedFromSystem ? null : value;
    }

    public void Dispose()
    {
        _watcher.Changed -= OnChanged;
        _watcher.Created -= OnChanged;
        _watcher.Renamed -= OnChanged;
        _watcher.Dispose();
    }
}

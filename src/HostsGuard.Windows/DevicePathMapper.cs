using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace HostsGuard.Windows;

/// <summary>
/// NT device path → DOS path mapper (WFCP-002). Security event 5157 reports the
/// application as <c>\device\harddiskvolume4\…\app.exe</c>, but firewall COM
/// rules and <see cref="FirewallIdentity.Compute"/> need the drive-letter form.
/// The volume map is built from <c>QueryDosDevice</c>, cached, and refreshed
/// once on a lookup miss (volumes mount/unmount at runtime). Unmappable paths
/// come back unchanged so callers degrade gracefully.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DevicePathMapper
{
    private readonly Func<IReadOnlyDictionary<string, string>> _queryMap;
    private readonly object _gate = new();
    private Dictionary<string, string> _map;

    public DevicePathMapper(Func<IReadOnlyDictionary<string, string>>? queryMap = null)
    {
        _queryMap = queryMap ?? QueryVolumeMap;
        _map = new Dictionary<string, string>(_queryMap(), StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Translate an NT device path; non-device or unknown-volume paths return unchanged.</summary>
    public string ToDosPath(string ntPath)
    {
        if (string.IsNullOrWhiteSpace(ntPath) ||
            !ntPath.StartsWith(@"\device\", StringComparison.OrdinalIgnoreCase))
        {
            return ntPath ?? string.Empty;
        }

        lock (_gate)
        {
            if (TryMap(ntPath, out var mapped))
            {
                return mapped;
            }

            // Volume not in the cache — a drive may have mounted since startup.
            _map = new Dictionary<string, string>(_queryMap(), StringComparer.OrdinalIgnoreCase);
            return TryMap(ntPath, out mapped) ? mapped : ntPath;
        }
    }

    private bool TryMap(string ntPath, out string mapped)
    {
        // Longest device prefix wins so \Device\HarddiskVolume1 never shadows
        // \Device\HarddiskVolume10.
        foreach (var (device, drive) in _map.OrderByDescending(kv => kv.Key.Length))
        {
            if (ntPath.Length > device.Length &&
                ntPath.StartsWith(device, StringComparison.OrdinalIgnoreCase) &&
                ntPath[device.Length] == '\\')
            {
                mapped = drive + ntPath[device.Length..];
                return true;
            }
        }

        mapped = string.Empty;
        return false;
    }

    /// <summary>Build the live volume map: "\Device\HarddiskVolumeN" → "C:".</summary>
    private static IReadOnlyDictionary<string, string> QueryVolumeMap()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var buffer = new char[1024];
        for (var letter = 'A'; letter <= 'Z'; letter++)
        {
            var drive = $"{letter}:";
            var length = QueryDosDeviceW(drive, buffer, buffer.Length);
            if (length > 2)
            {
                // Buffer is a REG_MULTI_SZ; the first string is the device target.
                var target = new string(buffer, 0, Array.IndexOf(buffer, '\0', 0, (int)length));
                if (target.Length != 0)
                {
                    map[target] = drive;
                }
            }
        }

        return map;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDeviceW(string lpDeviceName, [Out] char[] lpTargetPath, int ucchMax);
}

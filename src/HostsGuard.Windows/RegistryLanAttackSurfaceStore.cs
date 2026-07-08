using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Win32;

namespace HostsGuard.Windows;

/// <summary>HKLM-backed registry controls for reversible LAN attack-surface toggles.</summary>
[SupportedOSPlatform("windows")]
public sealed class RegistryLanAttackSurfaceStore : ILanAttackSurfaceStore
{
    private const string BackupPath = @"SOFTWARE\HostsGuard\LanAttackSurface";
    private const string Missing = "__missing__";
    private const string LlmnrPath = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
    private const string WpadPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp";
    private const string DnscacheParametersPath = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
    private const string SsdpServicePath = @"SYSTEM\CurrentControlSet\Services\SSDPSRV";
    private const string NetbiosInterfacesPath = @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";

    public bool IsBlocked(string key) => key switch
    {
        "llmnr" => DwordEquals(LlmnrPath, "EnableMulticast", 0),
        "wpad" => DwordEquals(WpadPath, "DisableWpad", 1),
        "mdns" => DwordEquals(DnscacheParametersPath, "EnableMDNS", 0),
        "ssdp" => DwordEquals(SsdpServicePath, "Start", 4),
        "netbios-ns" => NetbiosDisabled(),
        _ => false,
    };

    public void SetBlocked(string key, bool blocked)
    {
        switch (key)
        {
            case "llmnr":
                SetDwordWithBackup(key, LlmnrPath, "EnableMulticast", blocked, 0);
                break;
            case "wpad":
                SetDwordWithBackup(key, WpadPath, "DisableWpad", blocked, 1);
                break;
            case "mdns":
                SetDwordWithBackup(key, DnscacheParametersPath, "EnableMDNS", blocked, 0);
                break;
            case "ssdp":
                SetDwordWithBackup(key, SsdpServicePath, "Start", blocked, 4);
                break;
            case "netbios-ns":
                SetNetbios(blocked);
                break;
        }
    }

    private static bool DwordEquals(string path, string name, int expected)
    {
        using var key = Registry.LocalMachine.OpenSubKey(path, writable: false);
        return key?.GetValue(name) is int value && value == expected;
    }

    private static void SetDwordWithBackup(string backupName, string path, string valueName, bool blocked, int blockedValue)
    {
        using var backup = Registry.LocalMachine.CreateSubKey(BackupPath, writable: true);
        if (blocked)
        {
            using var current = Registry.LocalMachine.OpenSubKey(path, writable: false);
            if (backup.GetValue(backupName) is null)
            {
                var prior = current?.GetValue(valueName);
                backup.SetValue(backupName, prior is int priorInt ? priorInt.ToString() : Missing, RegistryValueKind.String);
            }

            using var target = Registry.LocalMachine.CreateSubKey(path, writable: true);
            target.SetValue(valueName, blockedValue, RegistryValueKind.DWord);
            return;
        }

        var saved = backup.GetValue(backupName)?.ToString();
        using (var target = Registry.LocalMachine.CreateSubKey(path, writable: true))
        {
            if (string.IsNullOrEmpty(saved) || saved == Missing)
            {
                target.DeleteValue(valueName, throwOnMissingValue: false);
            }
            else if (int.TryParse(saved, out var prior))
            {
                target.SetValue(valueName, prior, RegistryValueKind.DWord);
            }
        }

        backup.DeleteValue(backupName, throwOnMissingValue: false);
    }

    private static bool NetbiosDisabled()
    {
        using var root = Registry.LocalMachine.OpenSubKey(NetbiosInterfacesPath, writable: false);
        var names = root?.GetSubKeyNames() ?? Array.Empty<string>();
        if (names.Length == 0)
        {
            return false;
        }

        return names.All(name =>
        {
            using var key = root!.OpenSubKey(name, writable: false);
            return key?.GetValue("NetbiosOptions") is int value && value == 2;
        });
    }

    private static void SetNetbios(bool blocked)
    {
        using var root = Registry.LocalMachine.OpenSubKey(NetbiosInterfacesPath, writable: true);
        if (root is null)
        {
            return;
        }

        using var backup = Registry.LocalMachine.CreateSubKey(BackupPath, writable: true);
        const string backupName = "netbios-ns";
        if (blocked)
        {
            if (backup.GetValue(backupName) is null)
            {
                var snapshot = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (var name in root.GetSubKeyNames())
                {
                    using var key = root.OpenSubKey(name, writable: false);
                    snapshot[name] = key?.GetValue("NetbiosOptions") is int prior
                        ? prior.ToString(System.Globalization.CultureInfo.InvariantCulture)
                        : Missing;
                }

                backup.SetValue(backupName, JsonSerializer.Serialize(snapshot), RegistryValueKind.String);
            }

            foreach (var name in root.GetSubKeyNames())
            {
                using var key = root.OpenSubKey(name, writable: true);
                key?.SetValue("NetbiosOptions", 2, RegistryValueKind.DWord);
            }

            return;
        }

        var json = backup.GetValue(backupName)?.ToString();
        if (!string.IsNullOrWhiteSpace(json))
        {
            var snapshot = JsonSerializer.Deserialize<Dictionary<string, string>>(json)
                ?? new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var (name, saved) in snapshot)
            {
                using var key = root.OpenSubKey(name, writable: true);
                if (key is null)
                {
                    continue;
                }

                if (saved == Missing)
                {
                    key.DeleteValue("NetbiosOptions", throwOnMissingValue: false);
                }
                else if (int.TryParse(saved, out var prior))
                {
                    key.SetValue("NetbiosOptions", prior, RegistryValueKind.DWord);
                }
            }
        }

        backup.DeleteValue(backupName, throwOnMissingValue: false);
    }
}

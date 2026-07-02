using System.Management;
using System.Runtime.Versioning;

namespace HostsGuard.Windows;

/// <summary>Defender exclusion surface, interface-first for testability.</summary>
public interface IDefender
{
    bool IsAvailable();

    IReadOnlyList<string> GetExclusionPaths();

    /// <summary>Append a path to Defender's exclusion list. Requires elevation.</summary>
    bool AddExclusion(string path);
}

/// <summary>
/// Windows Defender preference access via WMI (root\Microsoft\Windows\Defender,
/// MSFT_MpPreference) — the PowerShell-SDK-free equivalent of
/// Get-/Add-MpPreference. Blocking telemetry endpoints trips Defender's
/// SettingsModifier:Win32/HostsFileHijack; excluding the hosts file is the
/// documented way to keep the block in place.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DefenderConfig : IDefender
{
    private const string Scope = @"root\Microsoft\Windows\Defender";
    private const string ClassName = "MSFT_MpPreference";

    public bool IsAvailable()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(Scope, $"SELECT ExclusionPath FROM {ClassName}");
            using var results = searcher.Get();
            return results.Count >= 0;
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            return false;
        }
    }

    public IReadOnlyList<string> GetExclusionPaths()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(Scope, $"SELECT ExclusionPath FROM {ClassName}");
            foreach (ManagementObject instance in searcher.Get())
            {
                using (instance)
                {
                    if (instance["ExclusionPath"] is string[] paths)
                    {
                        return paths;
                    }
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            // Defender absent/inaccessible — treated as no exclusions.
        }

        return Array.Empty<string>();
    }

    public bool AddExclusion(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        try
        {
            using var mpClass = new ManagementClass(Scope, ClassName, null);
            using var inParams = mpClass.GetMethodParameters("Add");
            inParams["ExclusionPath"] = new[] { path };
            using var result = mpClass.InvokeMethod("Add", inParams, null);
            return true;
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            return false;
        }
    }
}

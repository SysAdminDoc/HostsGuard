using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using HostsGuard.Core;

namespace HostsGuard.Windows;

/// <summary>A program's identity for firewall-rule rebind: SHA-256 + Authenticode signer.</summary>
public sealed record FileIdentity(string Path, string Sha256, string? Signer);

/// <summary>
/// Firewall program-rule identity cache and orphan detection. Ports the Python
/// <c>fw_program_identities</c> / <c>_remember_fw_program_identity</c>: because
/// Windows Firewall matches by path, an app update that moves the binary orphans
/// a program rule. We remember each rule's program signer + hash so a moved binary
/// can be confidently re-bound to the same application.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallIdentity
{
    private readonly string _cachePath;
    private readonly object _gate = new();
    private Dictionary<string, List<FileIdentity>> _cache;

    public FirewallIdentity(string cachePath)
    {
        _cachePath = cachePath ?? throw new ArgumentNullException(nameof(cachePath));
        _cache = Load();
    }

    /// <summary>Compute SHA-256 + best-effort Authenticode signer subject for a file.</summary>
    public static FileIdentity Compute(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string sha;
        using (var stream = File.OpenRead(path))
        {
            sha = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }

        string? signer = null;
        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            signer = cert.Subject;
        }
        catch (CryptographicException)
        {
            // Unsigned or catalog-signed (no embedded cert) — signer stays null.
        }

        return new FileIdentity(path, sha, signer);
    }

    /// <summary>An HG program rule whose target executable no longer exists is orphaned.</summary>
    public static bool IsOrphaned(FwRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (rule.Source != "hostsguard" || rule.Program.Length == 0)
        {
            return false;
        }

        var first = rule.Program.Split(',')[0].Trim();
        return first.Length != 0 && !File.Exists(first);
    }

    /// <summary>Record the current identity of a rule's program (deduped by hash).</summary>
    public void Remember(string ruleName, string programPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
        if (!File.Exists(programPath))
        {
            return;
        }

        var identity = Compute(programPath);
        lock (_gate)
        {
            if (!_cache.TryGetValue(ruleName, out var list))
            {
                list = new List<FileIdentity>();
                _cache[ruleName] = list;
            }

            if (!list.Any(i => i.Sha256 == identity.Sha256))
            {
                list.Add(identity);
                while (list.Count > 8)
                {
                    list.RemoveAt(0);
                }

                Save();
            }
        }
    }

    public IReadOnlyList<FileIdentity> Get(string ruleName)
    {
        lock (_gate)
        {
            return _cache.TryGetValue(ruleName, out var list) ? list.ToList() : Array.Empty<FileIdentity>();
        }
    }

    /// <summary>
    /// True if <paramref name="candidatePath"/> is the same application a rule was
    /// bound to — same file hash, or same Authenticode signer as a remembered
    /// identity. Lets the UI confidently rebind an orphaned rule after an update.
    /// </summary>
    public bool MatchesRemembered(string ruleName, string candidatePath)
    {
        if (!File.Exists(candidatePath))
        {
            return false;
        }

        var candidate = Compute(candidatePath);
        foreach (var known in Get(ruleName))
        {
            if (known.Sha256 == candidate.Sha256)
            {
                return true;
            }

            if (!string.IsNullOrEmpty(known.Signer) && known.Signer == candidate.Signer)
            {
                return true;
            }
        }

        return false;
    }

    private Dictionary<string, List<FileIdentity>> Load()
    {
        try
        {
            if (File.Exists(_cachePath))
            {
                var json = File.ReadAllText(_cachePath);
                return JsonSerializer.Deserialize<Dictionary<string, List<FileIdentity>>>(json)
                    ?? new Dictionary<string, List<FileIdentity>>(StringComparer.Ordinal);
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            // Corrupt/unreadable cache — start fresh rather than fail startup.
        }

        return new Dictionary<string, List<FileIdentity>>(StringComparer.Ordinal);
    }

    private void Save()
    {
        var dir = Path.GetDirectoryName(_cachePath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        File.WriteAllText(_cachePath, JsonSerializer.Serialize(_cache));
    }
}

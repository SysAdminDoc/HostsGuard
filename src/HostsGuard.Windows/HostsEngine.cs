using System.Security.Cryptography;
using System.Text;
using HostsGuard.Core;

namespace HostsGuard.Windows;

/// <summary>
/// Transactional hosts-file engine. Faithful port of the Python <c>HostsMgr</c>:
/// atomic temp-file + replace writes, SHA-512 self-write hashing so the tamper
/// watcher can distinguish our own writes, backups, block/unblock/bulk, and an
/// exact-set <see cref="Reconcile"/>. The hosts path is injectable so the engine
/// is fully testable against a temp file without elevation.
/// </summary>
public sealed class HostsEngine
{
    /// <summary>The default Windows hosts-file path.</summary>
    public static string DefaultHostsPath =>
        OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts")
            : "/etc/hosts";

    private readonly string _hostsPath;
    private readonly object _gate = new();
    private readonly LinkedList<string> _selfHashOrder = new();
    private readonly HashSet<string> _selfHashes = new(StringComparer.Ordinal);
    private List<string> _lines = new();
    private HashSet<string> _blocked = new(StringComparer.Ordinal);

    public HostsEngine(string? hostsPath = null)
    {
        _hostsPath = hostsPath ?? DefaultHostsPath;
        Read();
    }

    public string HostsPath => _hostsPath;

    /// <summary>Re-read the hosts file into memory and recompute the blocked set.</summary>
    public void Read()
    {
        lock (_gate)
        {
            try
            {
                _lines = File.Exists(_hostsPath) ? File.ReadAllLines(_hostsPath).ToList() : new List<string>();
                _blocked = new HashSet<string>(StringComparer.Ordinal);
                foreach (var l in _lines)
                {
                    var n = HostsFile.NormLine(l, normalize: false);
                    if (n is not null)
                    {
                        _blocked.Add(n);
                    }
                }
            }
            catch (IOException)
            {
                _lines = new List<string>();
            }
        }
    }

    public IReadOnlySet<string> GetBlocked()
    {
        lock (_gate)
        {
            return new HashSet<string>(_blocked, StringComparer.Ordinal);
        }
    }

    public IReadOnlyList<string> GetLines()
    {
        lock (_gate)
        {
            return _lines.ToList();
        }
    }

    /// <summary>Block a single domain. Returns false if invalid or already blocked.</summary>
    public bool Block(string domain)
    {
        var d = Domains.ToAscii(domain);
        if (!Domains.LooksLikeDomain(d))
        {
            return false;
        }

        lock (_gate)
        {
            if (_blocked.Contains(d))
            {
                return false;
            }

            var newLines = new List<string>(_lines) { $"0.0.0.0 {d}" };
            AtomicWrite(Join(newLines));
            _blocked.Add(d);
            _lines = newLines;
            return true;
        }
    }

    /// <summary>Block many domains in one write. Returns the count actually added.</summary>
    public int BlockBulk(IEnumerable<string> domains)
    {
        ArgumentNullException.ThrowIfNull(domains);
        lock (_gate)
        {
            var toAdd = new List<string>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var raw in domains)
            {
                var d = Domains.ToAscii(raw);
                if (!_blocked.Contains(d) && seen.Add(d) && Domains.LooksLikeDomain(d))
                {
                    toAdd.Add(d);
                }
            }

            if (toAdd.Count == 0)
            {
                return 0;
            }

            var newLines = new List<string>(_lines);
            newLines.AddRange(toAdd.Select(d => $"0.0.0.0 {d}"));
            AtomicWrite(Join(newLines));
            foreach (var d in toAdd)
            {
                _blocked.Add(d);
            }

            _lines = newLines;
            return toAdd.Count;
        }
    }

    /// <summary>Remove all block lines for a domain, preserving everything else.</summary>
    public bool Unblock(string domain)
    {
        var d = Domains.ToAscii(domain);
        lock (_gate)
        {
            var kept = new List<string>();
            foreach (var l in _lines)
            {
                var line = l.Trim();
                if (line.Length == 0 || line.StartsWith('#'))
                {
                    kept.Add(l);
                    continue;
                }

                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2
                    && parts[0] is "0.0.0.0" or "127.0.0.1" or "::" or "::1"
                    && parts.Skip(1).Any(p => Domains.ToAscii(p) == d))
                {
                    continue;
                }

                kept.Add(l);
            }

            if (kept.Count == _lines.Count)
            {
                return false;
            }

            AtomicWrite(Join(kept));
            _blocked.Remove(d);
            _lines = kept;
            return true;
        }
    }

    /// <summary>
    /// Rewrite so exactly <paramref name="targetBlocked"/> are 0.0.0.0-blocked,
    /// preserving comments and non-block lines. Returns (added, targetTotal).
    /// </summary>
    public (int Added, int Target) Reconcile(IEnumerable<string> targetBlocked)
    {
        ArgumentNullException.ThrowIfNull(targetBlocked);
        var target = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in targetBlocked)
        {
            var d = Domains.ToAscii(raw);
            if (Domains.LooksLikeDomain(d))
            {
                target.Add(d);
            }
        }

        lock (_gate)
        {
            var kept = new List<string>();
            var present = new HashSet<string>(StringComparer.Ordinal);
            foreach (var l in _lines)
            {
                var line = l.Trim();
                if (line.Length == 0 || line.StartsWith('#'))
                {
                    kept.Add(l);
                    continue;
                }

                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && parts[0] is "0.0.0.0" or "127.0.0.1" or "::" or "::1")
                {
                    var d = parts[1].ToLowerInvariant().TrimEnd('.');
                    if (Domains.LooksLikeDomain(d))
                    {
                        if (target.Contains(d))
                        {
                            present.Add(d);
                            kept.Add(l);
                        }

                        // else: drop — no longer in the target set
                        continue;
                    }
                }

                kept.Add(l);
            }

            var additions = target.Except(present).OrderBy(d => d, StringComparer.Ordinal).Select(d => $"0.0.0.0 {d}").ToList();
            var newLines = new List<string>(kept);
            newLines.AddRange(additions);
            AtomicWrite(Join(newLines));
            Read();
            return (additions.Count, target.Count);
        }
    }

    /// <summary>
    /// Re-home managed block entries under "# &lt;Category&gt;" comment sections
    /// (matching the hand-organized hosts style): entries for mapped domains are
    /// moved under their category header — appended to an existing section when
    /// one matches (case-insensitive), else a new section is created at the end.
    /// Unmapped lines, custom mappings, and hand-placed entries stay put.
    /// Returns how many entries were re-homed.
    /// </summary>
    public int OrganizeByCategory(IReadOnlyDictionary<string, string> categories)
    {
        ArgumentNullException.ThrowIfNull(categories);
        lock (_gate)
        {
            // Pass 1: pull out the sink lines for mapped domains that are
            // actually present, remembering each domain's category.
            var kept = new List<string>();
            var moved = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var l in _lines)
            {
                var line = l.Trim();
                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (line.Length != 0 && !line.StartsWith('#') &&
                    parts.Length >= 2 && parts[0] is "0.0.0.0" or "127.0.0.1" or "::" or "::1")
                {
                    var d = parts[1].ToLowerInvariant().TrimEnd('.');
                    if (categories.TryGetValue(d, out var category) && !string.IsNullOrWhiteSpace(category))
                    {
                        if (!moved.TryGetValue(category, out var list))
                        {
                            moved[category] = list = new List<string>();
                        }

                        list.Add(d);
                        continue;
                    }
                }

                kept.Add(l);
            }

            if (moved.Count == 0)
            {
                return 0;
            }

            // Pass 2: insert each group under its section header, creating the
            // section at the end when no header matches.
            var count = 0;
            foreach (var (category, domains) in moved.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase))
            {
                domains.Sort(StringComparer.Ordinal);
                count += domains.Count;
                var header = kept.FindIndex(l =>
                    l.TrimStart().StartsWith('#') &&
                    string.Equals(l.TrimStart('#', ' ', '\t').Trim(), category, StringComparison.OrdinalIgnoreCase));
                if (header < 0)
                {
                    if (kept.Count != 0 && kept[^1].Trim().Length != 0)
                    {
                        kept.Add(string.Empty);
                    }

                    kept.Add($"# {category}");
                    kept.AddRange(domains.Select(d => $"0.0.0.0 {d}"));
                    continue;
                }

                // Append after the section's contiguous entry block.
                var insert = header + 1;
                while (insert < kept.Count && kept[insert].Trim().Length != 0 && !kept[insert].TrimStart().StartsWith('#'))
                {
                    insert++;
                }

                kept.InsertRange(insert, domains.Select(d => $"0.0.0.0 {d}"));
            }

            AtomicWrite(Join(kept));
            Read();
            return count;
        }
    }

    /// <summary>
    /// Rewrite the managed sink block into a clean, consolidated set of category
    /// sections. Every blocked domain is re-filed under its canonical category —
    /// <paramref name="curated"/> wins when it knows the domain, otherwise the
    /// domain's current section header is folded through <paramref name="canonicalize"/>.
    /// This collapses the fragmented per-vendor sections ("Snapchat Tracking",
    /// "LinkedIn CDN", …) into the dozen-section taxonomy. Idempotent: returns 0
    /// and writes nothing when the file is already normalized. Any non-header,
    /// non-sink line (a foreign comment or a localhost mapping) is preserved at
    /// the top so a hand-edited file isn't clobbered.
    /// </summary>
    public int NormalizeCategorySections(
        Func<string, string> canonicalize,
        Func<string, string>? curated = null,
        IReadOnlyList<string>? categoryOrder = null)
    {
        ArgumentNullException.ThrowIfNull(canonicalize);
        lock (_gate)
        {
            var preamble = new List<string>();
            var byCategory = new Dictionary<string, SortedSet<string>>(StringComparer.OrdinalIgnoreCase);
            var currentCat = string.Empty;

            foreach (var raw in _lines)
            {
                var line = raw.Trim();
                if (line.Length == 0)
                {
                    continue;
                }

                if (line.StartsWith('#'))
                {
                    currentCat = line.TrimStart('#', ' ', '\t').Trim();
                    continue;
                }

                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && parts[0] is "0.0.0.0" or "127.0.0.1" or "::" or "::1")
                {
                    var domain = parts[1].ToLowerInvariant().TrimEnd('.');
                    var cat = curated?.Invoke(domain) ?? string.Empty;
                    if (cat.Length == 0)
                    {
                        cat = canonicalize(currentCat);
                    }

                    if (cat.Length == 0)
                    {
                        cat = "Other";
                    }

                    if (!byCategory.TryGetValue(cat, out var set))
                    {
                        byCategory[cat] = set = new SortedSet<string>(StringComparer.Ordinal);
                    }

                    set.Add(domain);
                    continue;
                }

                preamble.Add(raw);
            }

            if (byCategory.Count == 0)
            {
                return 0;
            }

            var order = categoryOrder ?? Array.Empty<string>();
            var cats = byCategory.Keys
                .OrderBy(c =>
                {
                    for (var i = 0; i < order.Count; i++)
                    {
                        if (string.Equals(order[i], c, StringComparison.OrdinalIgnoreCase))
                        {
                            return i;
                        }
                    }

                    return int.MaxValue;
                })
                .ThenBy(c => c, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var rebuilt = new List<string>();
            rebuilt.AddRange(preamble.Where(p => p.Trim().Length != 0));
            var count = 0;
            foreach (var cat in cats)
            {
                if (rebuilt.Count != 0)
                {
                    rebuilt.Add(string.Empty);
                }

                rebuilt.Add($"# {cat}");
                foreach (var d in byCategory[cat])
                {
                    rebuilt.Add($"0.0.0.0 {d}");
                    count++;
                }
            }

            var updated = Join(rebuilt);
            if (string.Equals(updated, Join(_lines), StringComparison.Ordinal))
            {
                return 0;
            }

            AtomicWrite(updated);
            Read();
            return count;
        }
    }

    /// <summary>Replace the hosts file with just the Windows sample header.</summary>
    public void EmergencyReset()
    {
        lock (_gate)
        {
            AtomicWrite(Join(HostsFile.WindowsHeader));
            Read();
        }
    }

    /// <summary>Write arbitrary raw content (used by upstream restore / raw editor).</summary>
    public void SaveRaw(string content)
    {
        ArgumentNullException.ThrowIfNull(content);
        lock (_gate)
        {
            AtomicWrite(content);
            Read();
        }
    }

    /// <summary>Copy the current hosts file to a timestamped .bak; returns its path or null.</summary>
    public string? Backup(string backupDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(backupDir);
        try
        {
            Directory.CreateDirectory(backupDir);
            var ts = DateTime.Now.ToString("yyyyMMdd_HHmmss", System.Globalization.CultureInfo.InvariantCulture);
            var dst = Path.Combine(backupDir, $"hosts_{ts}.bak");
            File.Copy(_hostsPath, dst, overwrite: true);
            return dst;
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>
    /// True if <paramref name="sha512Hex"/> matches content this process wrote and
    /// not yet consumed — lets the tamper watcher ignore our own writes. Consumes it.
    /// </summary>
    public bool IsSelfChange(string? sha512Hex)
    {
        if (string.IsNullOrEmpty(sha512Hex))
        {
            return false;
        }

        lock (_gate)
        {
            if (_selfHashes.Remove(sha512Hex))
            {
                _selfHashOrder.Remove(sha512Hex);
                return true;
            }

            return false;
        }
    }

    /// <summary>SHA-512 hex of the current on-disk hosts file (watcher helper).</summary>
    public string CurrentFileHash()
    {
        using var stream = File.OpenRead(_hostsPath);
        return Convert.ToHexString(SHA512.HashData(stream)).ToLowerInvariant();
    }

    private static string Join(IEnumerable<string> lines) => string.Join('\n', lines) + "\n";

    private void AtomicWrite(string content)
    {
        var dir = Path.GetDirectoryName(_hostsPath) ?? ".";
        Directory.CreateDirectory(dir);
        var tmp = Path.Combine(dir, $"hosts_{Guid.NewGuid():N}.tmp");
        try
        {
            var bytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(content);
            File.WriteAllBytes(tmp, bytes);

            for (var attempt = 0; ; attempt++)
            {
                try
                {
                    File.Move(tmp, _hostsPath, overwrite: true);
                    RecordSelf(bytes);
                    return;
                }
                catch (Exception ex) when (attempt < 7 && ex is IOException or UnauthorizedAccessException)
                {
                    Thread.Sleep(125);
                }
            }
        }
        catch
        {
            try { File.Delete(tmp); } catch (IOException) { /* best effort */ }
            throw;
        }
    }

    private void RecordSelf(byte[] content)
    {
        var hex = Convert.ToHexString(SHA512.HashData(content)).ToLowerInvariant();
        lock (_gate)
        {
            if (_selfHashes.Add(hex))
            {
                _selfHashOrder.AddLast(hex);
            }

            while (_selfHashOrder.Count > 16)
            {
                var oldest = _selfHashOrder.First!.Value;
                _selfHashOrder.RemoveFirst();
                _selfHashes.Remove(oldest);
            }
        }
    }
}

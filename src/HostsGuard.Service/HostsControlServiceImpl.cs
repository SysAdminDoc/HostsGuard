using System.Runtime.Versioning;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;

namespace HostsGuard.Service;

/// <summary>Implements the HostsControl gRPC service on top of the hosts engine + DB.</summary>
[SupportedOSPlatform("windows")]
public sealed class HostsControlServiceImpl : HostsControl.HostsControlBase
{
    private readonly ServiceState _state;

    public HostsControlServiceImpl(ServiceState state) => _state = state;

    public override Task<Ack> Block(DomainRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        if (!Domains.LooksLikeDomain(d))
        {
            return Task.FromResult(Error("invalid_domain", $"'{request.Domain}' is not a valid domain"));
        }

        var wrote = _state.Hosts.Block(d);
        _state.Db.AddDomain(d, "blocked", string.IsNullOrEmpty(request.Source) ? "manual" : request.Source, reason: request.Reason);
        _state.Db.LogEvent(d, "blocked", details: "hosts file", reason: request.Reason);
        return Task.FromResult(Ok(wrote ? $"blocked {d}" : $"already blocked {d}"));
    }

    public override Task<Ack> Allow(DomainRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        if (!Domains.LooksLikeDomain(d))
        {
            return Task.FromResult(Error("invalid_domain", $"'{request.Domain}' is not a valid domain"));
        }

        _state.Hosts.Unblock(d);
        _state.Db.AddDomain(d, "whitelisted", string.IsNullOrEmpty(request.Source) ? "manual" : request.Source, reason: request.Reason);
        _state.Db.LogEvent(d, "whitelisted", reason: request.Reason);
        return Task.FromResult(Ok($"allowed {d}"));
    }

    public override Task<Ack> Unblock(DomainRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        _state.Hosts.Unblock(d);
        _state.Db.RemoveDomain(d);
        return Task.FromResult(Ok($"unblocked {d}"));
    }

    public override Task<Ack> BlockRoot(DomainRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        if (!Domains.LooksLikeDomain(d))
        {
            return Task.FromResult(Error("invalid_domain", $"'{request.Domain}' is not a valid domain"));
        }

        var root = Domains.GetRoot(d);
        _state.Hosts.Block(root);
        _state.Db.AddDomain(root, "blocked", "manual", reason: request.Reason);
        return Task.FromResult(Ok($"blocked root {root}"));
    }

    public override Task<DomainList> ListDomains(ListDomainsRequest request, ServerCallContext context)
    {
        var rows = _state.Db.GetDomains(
            string.IsNullOrEmpty(request.Status) ? null : request.Status,
            string.IsNullOrEmpty(request.Search) ? null : request.Search,
            string.IsNullOrEmpty(request.Source) ? null : request.Source);

        var list = new DomainList();
        foreach (var r in rows)
        {
            list.Domains.Add(new ManagedDomain
            {
                Domain = r.Domain,
                Status = r.Status,
                Source = r.Source ?? string.Empty,
                Reason = r.Reason ?? string.Empty,
                Hits = r.Hits,
                Notes = r.Notes ?? string.Empty,
            });
        }

        return Task.FromResult(list);
    }

    public override Task<Ack> Reconcile(ReconcileRequest request, ServerCallContext context)
    {
        var (added, target) = _state.Hosts.Reconcile(request.Blocked);
        return Task.FromResult(Ok($"reconciled: +{added} to {target} target"));
    }

    public override Task<Ack> EmergencyReset(Empty request, ServerCallContext context)
    {
        _state.Hosts.EmergencyReset();
        return Task.FromResult(Ok("hosts file reset to Windows defaults"));
    }

    public override Task<Ack> TempAllow(TempAllowRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        if (!Domains.LooksLikeDomain(d))
        {
            return Task.FromResult(Error("invalid_domain", $"'{request.Domain}' is not a valid domain"));
        }

        if (request.Minutes < 1 || request.Minutes > TempAllowScheduler.MaxMinutes)
        {
            return Task.FromResult(Error("invalid_duration", $"minutes must be 1..{TempAllowScheduler.MaxMinutes}"));
        }

        _state.TempAllows.Add(d, request.Minutes, string.IsNullOrEmpty(request.Source) ? "temp_allow" : request.Source);
        return Task.FromResult(Ok($"allowed {d} for {request.Minutes} min"));
    }

    public override Task<TempAllowList> ListTempAllows(Empty request, ServerCallContext context)
    {
        var list = new TempAllowList();
        foreach (var (domain, expiresUtc) in _state.TempAllows.Pending())
        {
            list.Entries.Add(new TempAllowEntry
            {
                Domain = domain,
                Expires = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(
                    DateTime.SpecifyKind(expiresUtc, DateTimeKind.Utc)),
            });
        }

        return Task.FromResult(list);
    }

    public override Task<HostsText> GetHostsText(Empty request, ServerCallContext context)
        => Task.FromResult(new HostsText { Text = string.Join("\n", _state.Hosts.GetLines()) });

    public override Task<Ack> SetHostsText(HostsText request, ServerCallContext context)
    {
        const int MaxBytes = 10 * 1024 * 1024;
        var text = request.Text ?? string.Empty;
        if (System.Text.Encoding.UTF8.GetByteCount(text) > MaxBytes)
        {
            return Task.FromResult(Error("too_large", "hosts content exceeds 10 MB"));
        }

        _state.Hosts.SaveRaw(text);
        _state.Db.LogEvent("hosts", "raw_edit", details: "raw editor save");
        return Task.FromResult(Ok("hosts file saved"));
    }

    public override Task<Ack> HideRoot(DomainRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        if (!Domains.LooksLikeDomain(d))
        {
            return Task.FromResult(Error("invalid_domain", $"'{request.Domain}' is not a valid domain"));
        }

        var root = Domains.GetRoot(d);
        _state.Db.HideRoot(root);
        return Task.FromResult(Ok($"hidden root {root}"));
    }

    public override Task<Ack> UnhideRoot(DomainRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        var root = Domains.GetRoot(d);
        _state.Db.UnhideRoot(root);
        return Task.FromResult(Ok($"unhidden root {root}"));
    }

    public override Task<ActivityList> GetActivity(ActivityRequest request, ServerCallContext context)
    {
        var limit = request.Limit is > 0 and <= 5000 ? request.Limit : 500;
        var hiddenRoots = _state.Db.GetHiddenRoots();
        var list = new ActivityList();
        foreach (var row in _state.Db.GetFeed(limit))
        {
            var root = Domains.GetRoot(row.Domain);
            var hidden = row.Hidden != 0 || hiddenRoots.Contains(root);
            if (hidden && !request.IncludeHidden)
            {
                continue;
            }

            var record = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["domain"] = row.Domain,
                ["root"] = root,
                ["status"] = row.Status ?? string.Empty,
                ["process"] = row.Process ?? string.Empty,
                ["reason"] = row.Reason ?? string.Empty,
            };
            if (!SearchQuery.Matches(record, request.Search))
            {
                continue;
            }

            list.Rows.Add(new ActivityRow
            {
                Domain = row.Domain,
                Root = root,
                Status = row.Status ?? string.Empty,
                Process = row.Process ?? string.Empty,
                Hits = row.Hits,
                FirstSeen = row.FirstSeen ?? string.Empty,
                LastSeen = row.LastSeen ?? string.Empty,
                Hidden = hidden,
                Reason = row.Reason ?? string.Empty,
            });
        }

        return Task.FromResult(list);
    }

    public override Task<Ack> BackupHosts(Empty request, ServerCallContext context)
    {
        var backupDir = System.IO.Path.Combine(_state.DataDir, "backups");
        var path = _state.Hosts.Backup(backupDir);
        return Task.FromResult(path is null
            ? Error("backup_failed", "could not write the hosts backup")
            : Ok(path));
    }

    public override Task<BackupList> ListBackups(Empty request, ServerCallContext context)
    {
        var list = new BackupList();
        var backupDir = System.IO.Path.Combine(_state.DataDir, "backups");
        if (!System.IO.Directory.Exists(backupDir))
        {
            return Task.FromResult(list);
        }

        foreach (var file in new System.IO.DirectoryInfo(backupDir).GetFiles("*.bak")
                     .OrderByDescending(f => f.LastWriteTime))
        {
            list.Entries.Add(new BackupEntry
            {
                FileName = file.Name,
                Created = file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture),
                SizeBytes = file.Length,
            });
        }

        return Task.FromResult(list);
    }

    public override Task<Ack> RestoreBackup(BackupRequest request, ServerCallContext context)
    {
        const int MaxBytes = 10 * 1024 * 1024;
        var name = request.FileName ?? string.Empty;
        // Name must be a plain .bak file name inside the backups dir — no traversal.
        if (name.Length == 0 || name != System.IO.Path.GetFileName(name) ||
            !name.EndsWith(".bak", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(Error("invalid_backup", "backup must be a .bak file name"));
        }

        var backupDir = System.IO.Path.Combine(_state.DataDir, "backups");
        var path = System.IO.Path.Combine(backupDir, name);
        if (!System.IO.File.Exists(path))
        {
            return Task.FromResult(Error("backup_missing", $"no backup named {name}"));
        }

        if (new System.IO.FileInfo(path).Length > MaxBytes)
        {
            return Task.FromResult(Error("too_large", "backup exceeds 10 MB"));
        }

        var text = System.IO.File.ReadAllText(path);
        _state.Hosts.Backup(backupDir); // snapshot the current file before replacing it
        _state.Hosts.SaveRaw(text);
        _state.Db.LogEvent("hosts", "backup_restored", details: name);
        return Task.FromResult(Ok($"restored {name}"));
    }

    public override Task<Ack> AddDefenderExclusion(Empty request, ServerCallContext context)
    {
        if (_state.Defender is not { } defender || !defender.IsAvailable())
        {
            return Task.FromResult(Error("defender_unavailable", "Windows Defender is not accessible on this system"));
        }

        var path = _state.Hosts.HostsPath;
        if (defender.GetExclusionPaths().Any(p => string.Equals(p.TrimEnd('\\'), path, StringComparison.OrdinalIgnoreCase)))
        {
            return Task.FromResult(Ok("hosts file is already excluded"));
        }

        if (!defender.AddExclusion(path))
        {
            return Task.FromResult(Error("defender_failed", "Defender refused the exclusion (is the service elevated?)"));
        }

        _state.Db.LogEvent("defender", "exclusion_added", details: path);
        return Task.FromResult(Ok($"added Defender exclusion for {path}"));
    }

    public override Task<Ack> HardenAcl(Empty request, ServerCallContext context)
    {
        try
        {
            Windows.HostsAcl.Harden(_state.Hosts.HostsPath);
            _state.Db.LogEvent("hosts", "acl_hardened");
            return Task.FromResult(Ok("hosts file ACL hardened"));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.IO.IOException or InvalidOperationException)
        {
            return Task.FromResult(Error("acl_failed", ex.Message));
        }
    }

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };
}

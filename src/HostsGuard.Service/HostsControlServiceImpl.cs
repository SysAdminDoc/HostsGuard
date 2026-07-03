using System.Net.Http;
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

        return GuardHostsWrite(() =>
        {
            var wrote = _state.Hosts.Block(d);
            _state.Db.AddDomain(d, "blocked", string.IsNullOrEmpty(request.Source) ? "manual" : request.Source, reason: request.Reason);
            _state.Db.SetCategoryIfEmpty(d, DomainCategories.Lookup(d)); // curated defaults — no AI needed
            _state.Db.LogEvent(d, "blocked", details: "hosts file", reason: request.Reason);
            AutoCategorize(d);
            return Ok(wrote ? $"blocked {d}" : $"already blocked {d}");
        });
    }

    /// <summary>
    /// Fire-and-forget AI categorization of a freshly blocked domain (when
    /// enabled): assigns a DB category and re-homes the hosts entry under its
    /// "# Category" section. Never blocks or fails the block itself.
    /// </summary>
    private void AutoCategorize(string domain)
    {
        var settings = _state.Ai.Settings;
        if (!settings.Enabled || settings.ApiKey.Length == 0)
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await _state.Ai.CategorizeAsync(new[] { domain }, CancellationToken.None);
            }
            catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException
                or TaskCanceledException or IOException or UnauthorizedAccessException)
            {
                _state.Db.LogEvent(domain, "ai_categorize_failed", details: ex.Message);
            }
        });
    }

    public override Task<Ack> Allow(DomainRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        if (!Domains.LooksLikeDomain(d))
        {
            return Task.FromResult(Error("invalid_domain", $"'{request.Domain}' is not a valid domain"));
        }

        return GuardHostsWrite(() =>
        {
            _state.Hosts.Unblock(d);
            _state.Db.AddDomain(d, "whitelisted", string.IsNullOrEmpty(request.Source) ? "manual" : request.Source, reason: request.Reason);
            _state.Db.LogEvent(d, "whitelisted", reason: request.Reason);
            return Ok($"allowed {d}");
        });
    }

    public override Task<Ack> Unblock(DomainRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        return GuardHostsWrite(() =>
        {
            _state.Hosts.Unblock(d);
            _state.Db.RemoveDomain(d);
            return Ok($"unblocked {d}");
        });
    }

    public override Task<Ack> BlockRoot(DomainRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        if (!Domains.LooksLikeDomain(d))
        {
            return Task.FromResult(Error("invalid_domain", $"'{request.Domain}' is not a valid domain"));
        }

        var root = Domains.GetRoot(d);
        return GuardHostsWrite(() =>
        {
            _state.Hosts.Block(root);
            _state.Db.AddDomain(root, "blocked", "manual", reason: request.Reason);
            _state.Db.SetCategoryIfEmpty(root, DomainCategories.Lookup(root));
            return Ok($"blocked root {root}");
        });
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
                Category = r.Category ?? string.Empty,
            });
        }

        return Task.FromResult(list);
    }

    public override Task<Ack> Reconcile(ReconcileRequest request, ServerCallContext context)
        => GuardHostsWrite(() =>
        {
            var (added, target) = _state.Hosts.Reconcile(request.Blocked);
            return Ok($"reconciled: +{added} to {target} target");
        });

    public override Task<Ack> EmergencyReset(Empty request, ServerCallContext context)
        => GuardHostsWrite(() =>
        {
            _state.Hosts.EmergencyReset();
            return Ok("hosts file reset to Windows defaults");
        });

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

        return GuardHostsWrite(() =>
        {
            _state.Hosts.SaveRaw(text);
            _state.Db.LogEvent("hosts", "raw_edit", details: "raw editor save");
            return Ok("hosts file saved");
        });
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
        var feed = _state.Db.GetFeed(limit);
        // Reference-list membership + learned purposes for the whole page in
        // two batched queries (empty stores simply match nothing).
        var membership = _state.Db.GetListMembership(feed.Select(r => r.Domain));
        var learnedPurposes = _state.Db.GetAiKnowledge("purpose", feed.Select(r => r.Domain));
        var list = new ActivityList();
        foreach (var row in feed)
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

            var activityRow = new ActivityRow
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
            };
            if (membership.TryGetValue(row.Domain, out var lists))
            {
                activityRow.Blocklists.AddRange(lists);
            }

            // Curated purpose table first; AI-researched knowledge second.
            var curated = Domains.LooksLikeDomain(row.Domain) ? DomainPurpose.Lookup(row.Domain) : string.Empty;
            activityRow.Purpose = curated.Length != 0
                ? curated
                : learnedPurposes.GetValueOrDefault(row.Domain, string.Empty);

            list.Rows.Add(activityRow);
        }

        return Task.FromResult(list);
    }

    // ─── AI categorization (DeepSeek) ─────────────────────────────────────────

    public override Task<Ack> SetAiConfig(AiConfig request, ServerCallContext context)
    {
        try
        {
            _state.Ai.SaveSettings(request.ApiKey, request.Model, request.Endpoint, request.Enabled);
            var s = _state.Ai.Settings;
            return Task.FromResult(Ok(s.ApiKey.Length == 0
                ? "AI settings saved — add a DeepSeek API key to enable categorization"
                : $"AI settings saved — {s.Model}, auto-categorize {(s.Enabled ? "on" : "off")}"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Task.FromResult(Error("ai_config_failed", ex.Message));
        }
    }

    public override Task<AiStatus> GetAiStatus(Empty request, ServerCallContext context)
    {
        var s = _state.Ai.Settings;
        return Task.FromResult(new AiStatus
        {
            Configured = s.ApiKey.Length != 0,
            Enabled = s.Enabled,
            Model = s.Model,
            Endpoint = s.Endpoint,
            LastRun = _state.Db.GetMeta("ai_last_run") ?? string.Empty,
            LastResult = _state.Db.GetMeta("ai_last_result") ?? string.Empty,
        });
    }

    public override async Task<CategorizeResult> CategorizeDomains(CategorizeRequest request, ServerCallContext context)
    {
        if (request.HostsFile)
        {
            try
            {
                var organized = await _state.Ai.CategorizeHostsFileAsync(context.CancellationToken);
                var hostsResult = new CategorizeResult
                {
                    Ok = true,
                    Message = organized.Count == 0
                        ? "every hosts entry already has a category"
                        : $"categorized {organized.Count} hosts entries and organized the file",
                    Categorized = organized.Count,
                };
                foreach (var (domain, category) in organized)
                {
                    hostsResult.Items.Add(new DomainCategory { Domain = domain, Category = category });
                }

                return hostsResult;
            }
            catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException
                or TaskCanceledException or IOException or UnauthorizedAccessException)
            {
                return new CategorizeResult
                {
                    Ok = false,
                    Message = $"AI categorization failed: {ex.Message}",
                    ErrorCode = "hostsguard.error.v1/ai_failed",
                };
            }
        }

        var targets = request.AllUncategorized
            ? _state.Db.GetDomains(status: "blocked")
                .Where(r => string.IsNullOrEmpty(r.Category))
                .Select(r => r.Domain)
                .ToList()
            : request.Domains.ToList();
        if (targets.Count == 0)
        {
            return new CategorizeResult { Ok = true, Message = "nothing to categorize", Categorized = 0 };
        }

        try
        {
            var results = await _state.Ai.CategorizeAsync(targets, context.CancellationToken);
            var response = new CategorizeResult
            {
                Ok = true,
                Message = $"categorized {results.Count} of {targets.Count} domains",
                Categorized = results.Count,
            };
            foreach (var (domain, category) in results)
            {
                response.Items.Add(new DomainCategory { Domain = domain, Category = category });
            }

            return response;
        }
        catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException
            or TaskCanceledException or IOException or UnauthorizedAccessException)
        {
            return new CategorizeResult
            {
                Ok = false,
                Message = $"AI categorization failed: {ex.Message}",
                ErrorCode = "hostsguard.error.v1/ai_failed",
            };
        }
    }

    public override Task<Sparkline> GetSparkline(DomainRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        var root = Domains.LooksLikeDomain(d) ? Domains.GetRoot(d) : d;
        var sparkline = new Sparkline();
        if (root.Length != 0)
        {
            sparkline.Hits.AddRange(_state.Db.GetHourlyHits(root, DateTime.Now));
        }

        return Task.FromResult(sparkline);
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
        return GuardHostsWrite(() =>
        {
            _state.Hosts.Backup(backupDir); // snapshot the current file before replacing it
            _state.Hosts.SaveRaw(text);
            _state.Db.LogEvent("hosts", "backup_restored", details: name);
            return Ok($"restored {name}");
        });
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
            // Only rewrite the DACL when it's actually weak — an already-hardened
            // file needs no change and rewriting adds audit noise.
            if (!Windows.HostsAcl.HasWeakAcl(_state.Hosts.HostsPath))
            {
                return Task.FromResult(Ok("hosts file ACL already hardened"));
            }

            Windows.HostsAcl.Harden(_state.Hosts.HostsPath);
            _state.Db.LogEvent("hosts", "acl_hardened");
            return Task.FromResult(Ok("hosts file ACL hardened"));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.IO.IOException or InvalidOperationException)
        {
            return Task.FromResult(Error("acl_failed", ex.Message));
        }
    }

    /// <summary>
    /// Run a hosts-file mutation and translate write failures (typically a
    /// scanner holding the file open) into a typed, actionable Ack instead of
    /// letting the exception escape as an opaque StatusCode.Unknown RPC error.
    /// </summary>
    private static Task<Ack> GuardHostsWrite(Func<Ack> action)
    {
        try
        {
            return Task.FromResult(action());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Task.FromResult(Error("hosts_locked",
                "the hosts file is locked by another program (usually antivirus scanning it) — "
                + "wait a few seconds and retry; Tools → 'Exclude hosts in Defender' prevents this"));
        }
    }

    public override async Task<CategorizeResult> ResearchPurposes(Empty request, ServerCallContext context)
    {
        // Feed domains with no curated purpose and no learned one yet.
        var feed = _state.Db.GetFeed(2000).Select(r => r.Domain).Where(Domains.LooksLikeDomain).ToList();
        var learned = _state.Db.GetAiKnowledge("purpose", feed);
        var targets = feed
            .Where(d => DomainPurpose.Lookup(d).Length == 0 && !learned.ContainsKey(d))
            .ToList();
        if (targets.Count == 0)
        {
            return new CategorizeResult { Ok = true, Message = "every feed domain already has a purpose", Categorized = 0 };
        }

        try
        {
            var results = await _state.Ai.ResearchPurposesAsync(targets, context.CancellationToken);
            var response = new CategorizeResult
            {
                Ok = true,
                Message = $"researched {results.Count} of {targets.Count} domains",
                Categorized = results.Count,
            };
            foreach (var (domain, purpose) in results)
            {
                response.Items.Add(new DomainCategory { Domain = domain, Category = purpose });
            }

            return response;
        }
        catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException
            or TaskCanceledException or IOException or UnauthorizedAccessException)
        {
            return new CategorizeResult
            {
                Ok = false,
                Message = $"AI purpose research failed: {ex.Message}",
                ErrorCode = "hostsguard.error.v1/ai_failed",
            };
        }
    }

    public override async Task<IdentifyResult> IdentifyConnections(IdentifyRequest request, ServerCallContext context)
    {
        var items = request.Items
            .Select(i => (i.RemoteAddr ?? string.Empty, i.Host ?? string.Empty, i.Process ?? string.Empty, i.RemotePort))
            .ToList();
        if (items.Count == 0)
        {
            return new IdentifyResult { Ok = true, Message = "nothing to identify" };
        }

        try
        {
            var results = await _state.Ai.IdentifyConnectionsAsync(items, context.CancellationToken);
            var response = new IdentifyResult { Ok = true, Message = $"identified {results.Count} connections" };
            foreach (var (key, info) in results)
            {
                response.Items.Add(new IdentifiedItem { Key = key, Info = info });
            }

            return response;
        }
        catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException
            or TaskCanceledException or IOException or UnauthorizedAccessException)
        {
            return new IdentifyResult
            {
                Ok = false,
                Message = $"AI identification failed: {ex.Message}",
                ErrorCode = "hostsguard.error.v1/ai_failed",
            };
        }
    }

    public override Task<HostsText> ExportAiKnowledge(Empty request, ServerCallContext context)
    {
        var rows = _state.Db.GetAllAiKnowledge();
        var json = System.Text.Json.JsonSerializer.Serialize(
            rows.Select(r => new { kind = r.Kind, key = r.Key, value = r.Value, model = r.Model, created = r.Created }),
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        return Task.FromResult(new HostsText { Text = json });
    }

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };
}

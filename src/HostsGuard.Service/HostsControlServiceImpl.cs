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
        var d = Domains.ToAscii(request.Domain);
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
            catch (Exception ex)
            {
                // Fire-and-forget: any failure (incl. JsonException/ArgumentException
                // from a malformed AI response) must be logged, never left as an
                // unobserved task exception.
                _state.Db.LogEvent(domain, "ai_categorize_failed", details: ex.Message);
            }
        });
    }

    public override Task<Ack> Allow(DomainRequest request, ServerCallContext context)
    {
        var d = Domains.ToAscii(request.Domain);
        if (!Domains.LooksLikeDomain(d))
        {
            return Task.FromResult(Error("invalid_domain", $"'{request.Domain}' is not a valid domain"));
        }

        // NET-110: whitelisting weakens blocking — gate it behind the settings lock.
        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
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
        var d = Domains.ToAscii(request.Domain);
        // NET-110: removing a block weakens posture — gate behind the settings lock.
        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        return GuardHostsWrite(() =>
        {
            _state.Hosts.Unblock(d);
            _state.Db.RemoveDomain(d);
            return Ok($"unblocked {d}");
        });
    }

    public override Task<Ack> BlockRoot(DomainRequest request, ServerCallContext context)
    {
        var d = Domains.ToAscii(request.Domain);
        if (!Domains.LooksLikeDomain(d))
        {
            return Task.FromResult(Error("invalid_domain", $"'{request.Domain}' is not a valid domain"));
        }

        var root = Domains.GetRoot(d);
        var source = string.IsNullOrEmpty(request.Source) ? "manual" : request.Source;
        return GuardHostsWrite(() =>
        {
            _state.Hosts.Block(root);
            _state.Db.AddDomain(root, "blocked", source, reason: request.Reason);
            _state.Db.SetCategoryIfEmpty(root, DomainCategories.Lookup(root));
            return Ok($"blocked root {root}");
        });
    }

    public override Task<BulkResult> BlockMany(BulkDomainsRequest request, ServerCallContext context)
    {
        var valid = request.Domains
            .Select(d => (d ?? string.Empty).ToLowerInvariant().Trim())
            .Where(Domains.LooksLikeDomain)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (valid.Count == 0)
        {
            return Task.FromResult(new BulkResult { Ok = true, Message = "no valid domains", Total = 0 });
        }

        var source = string.IsNullOrEmpty(request.Source) ? "manual" : request.Source;
        var currentRows = _state.Db.GetDomains();
        var currentStatus = currentRows.ToDictionary(r => r.Domain, r => r.Status, StringComparer.Ordinal);
        var blocked = currentRows
            .Where(r => string.Equals(r.Status, "blocked", StringComparison.Ordinal))
            .Select(r => r.Domain)
            .ToHashSet(StringComparer.Ordinal);
        foreach (var d in valid)
        {
            if (!currentStatus.TryGetValue(d, out var status)
                || !string.Equals(status, "whitelisted", StringComparison.Ordinal))
            {
                blocked.Add(d);
            }
        }

        // ONE hosts-file write for the whole batch. Commit DB state only after
        // the file write succeeds so a held hosts file cannot create DB/file drift.
        var write = GuardBulkWrite(() =>
        {
            var (added, target) = _state.Hosts.Reconcile(blocked);
            return new BulkResult { Ok = true, Applied = added, Total = valid.Count, Message = $"blocked {valid.Count} domains (+{added} new)" };
        });
        if (!write.Ok)
        {
            return Task.FromResult(write);
        }

        _state.Db.AddDomainsBulk(valid.Select(d => (d, "blocked", source)));
        foreach (var d in valid)
        {
            _state.Db.SetCategoryIfEmpty(d, DomainCategories.Lookup(d));
        }

        _state.Db.LogEvent(
            "hosts",
            "block_many",
            details: BulkDetails(valid, write.Applied, blocked.Count),
            reason: request.Reason);
        return Task.FromResult(write);
    }

    public override Task<BulkResult> AllowMany(BulkDomainsRequest request, ServerCallContext context)
    {
        // Whitelisting weakens posture — gate behind the settings lock (NET-110).
        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(new BulkResult { Ok = false, Message = gate.Message, ErrorCode = gate.ErrorCode });
        }

        var valid = request.Domains
            .Select(d => (d ?? string.Empty).ToLowerInvariant().Trim())
            .Where(Domains.LooksLikeDomain)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (valid.Count == 0)
        {
            return Task.FromResult(new BulkResult { Ok = true, Message = "no valid domains", Total = 0 });
        }

        var source = string.IsNullOrEmpty(request.Source) ? "manual" : request.Source;
        var validSet = valid.ToHashSet(StringComparer.Ordinal);
        var blocked = _state.Db.GetDomains(status: "blocked")
            .Select(r => r.Domain)
            .Where(d => !validSet.Contains(d))
            .ToList();
        var write = GuardBulkWrite(() =>
        {
            _state.Hosts.Reconcile(blocked);
            return new BulkResult { Ok = true, Applied = valid.Count, Total = valid.Count, Message = $"allowed {valid.Count} domains" };
        });
        if (!write.Ok)
        {
            return Task.FromResult(write);
        }

        foreach (var d in valid)
        {
            _state.Db.AddDomain(d, "whitelisted", source, reason: request.Reason);
        }

        _state.Db.LogEvent("hosts", "allow_many", details: BulkDetails(valid), reason: request.Reason);
        return Task.FromResult(write);
    }

    private static string BulkDetails(IReadOnlyList<string> domains, int added = -1, int target = -1)
    {
        var preview = string.Join(", ", domains.Take(10));
        if (domains.Count > 10)
        {
            preview += $", and {domains.Count - 10} more";
        }

        var counts = added >= 0 && target >= 0
            ? $"{domains.Count} domains (+{added} to {target})"
            : $"{domains.Count} domains";
        return preview.Length == 0 ? counts : $"{counts}: {preview}";
    }

    /// <summary>Run one bulk hosts-file write, mapping an AV lock to a typed hosts_locked result.</summary>
    private static BulkResult GuardBulkWrite(Func<BulkResult> write)
    {
        try
        {
            return write();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new BulkResult
            {
                Ok = false,
                ErrorCode = "hostsguard.error.v1/hosts_locked",
                Message = "the hosts file is locked by another program (usually antivirus) — wait a few seconds and retry",
            };
        }
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
    {
        // NET-110: reconcile can remove blocks (weakening) — gate behind the lock.
        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        return GuardHostsWrite(() =>
        {
            var (added, target) = _state.Hosts.Reconcile(request.Blocked);
            return Ok($"reconciled: +{added} to {target} target");
        });
    }

    public override Task<Ack> EmergencyReset(Empty request, ServerCallContext context)
    {
        // NET-110: wiping every block is the most destructive weakening — gate it.
        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        return GuardHostsWrite(() =>
        {
            _state.Hosts.EmergencyReset();
            return Ok("hosts file reset to Windows defaults");
        });
    }

    public override Task<Ack> TempAllow(TempAllowRequest request, ServerCallContext context)
    {
        var d = Domains.ToAscii(request.Domain);
        if (!Domains.LooksLikeDomain(d))
        {
            return Task.FromResult(Error("invalid_domain", $"'{request.Domain}' is not a valid domain"));
        }

        if (request.Minutes < 1 || request.Minutes > TempAllowScheduler.MaxMinutes)
        {
            return Task.FromResult(Error("invalid_duration", $"minutes must be 1..{TempAllowScheduler.MaxMinutes}"));
        }

        // NET-110: a temp-allow lifts a block for a window (weakening) — gate it.
        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
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

        // NET-110: a raw hosts rewrite can drop every block — gate behind the lock.
        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
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
        var d = Domains.ToAscii(request.Domain);
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
        var d = Domains.ToAscii(request.Domain);
        var root = Domains.GetRoot(d);
        _state.Db.UnhideRoot(root);
        return Task.FromResult(Ok($"unhidden root {root}"));
    }

    public override async Task<Ack> HideDomains(HideDomainsRequest request, ServerCallContext context)
    {
        // Hiding is a per-row display flag on domains already IN the feed — not a
        // blocking mutation — so it must accept any feed key, including names that
        // fail LooksLikeDomain's registrable-domain check (e.g. SRV records like
        // _ldap._tcp.dc._msdcs... or _stun._udp...). Requiring LooksLikeDomain
        // here silently no-op'd those, so they could never be hidden.
        var domains = request.Domains
            .Select(x => (x ?? string.Empty).ToLowerInvariant().Trim())
            .Where(d => d.Length is > 0 and <= 253)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (domains.Count == 0)
        {
            return Ok("nothing to hide");
        }

        await _state.FlushActivityPersistenceAsync(context.CancellationToken);
        _state.Db.HideDomains(domains);
        return Ok(domains.Count == 1
            ? $"hidden {domains[0]}"
            : $"hidden {domains.Count} domains");
    }

    public override Task<Ack> UnhideDomains(HideDomainsRequest request, ServerCallContext context)
    {
        var domains = request.Domains
            .Select(x => (x ?? string.Empty).ToLowerInvariant().Trim())
            .Where(d => d.Length != 0)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        _state.Db.UnhideDomains(domains);
        return Task.FromResult(Ok($"revealed {domains.Count} domains"));
    }

    public override async Task<ActivityList> GetActivity(ActivityRequest request, ServerCallContext context)
    {
        await _state.FlushActivityPersistenceAsync(context.CancellationToken);
        var limit = request.Limit is > 0 and <= 5000 ? request.Limit : 500;
        var hiddenRoots = _state.Db.GetHiddenRoots();
        var feed = _state.Db.GetFeed(limit);
        // Reference-list membership + learned purposes for the whole page in
        // two batched queries (empty stores simply match nothing).
        var membership = _state.Db.GetListMembership(feed.Select(r => r.Domain));
        var learnedPurposes = _state.Db.GetAiKnowledge("purpose", feed.Select(r => r.Domain));
        // User overrides beat both the curated table and the AI (NET-107).
        var overriddenPurposes = _state.Db.GetUserOverrides("purpose", feed.Select(r => r.Domain));
        // Per-domain data volume (NET-108), one batched query for the page.
        var usage = _state.Db.GetDomainUsageTotals(feed.Select(r => r.Domain));
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

            activityRow.Bytes = usage.GetValueOrDefault(row.Domain, 0);

            // Precedence: user override → curated table → AI-researched knowledge.
            if (overriddenPurposes.TryGetValue(row.Domain, out var userPurpose) && userPurpose.Length != 0)
            {
                activityRow.Purpose = userPurpose;
            }
            else
            {
                var curated = Domains.LooksLikeDomain(row.Domain) ? DomainPurpose.Lookup(row.Domain) : string.Empty;
                activityRow.Purpose = curated.Length != 0
                    ? curated
                    : learnedPurposes.GetValueOrDefault(row.Domain, string.Empty);
            }

            list.Rows.Add(activityRow);
        }

        return list;
    }

    // ─── AI categorization (DeepSeek) ─────────────────────────────────────────

    public override Task<Ack> SetAiConfig(AiConfig request, ServerCallContext context)
    {
        // A custom endpoint must be https — the API key is sent as a Bearer
        // header and a plaintext endpoint would leak it. Empty keeps the default.
        if (!string.IsNullOrWhiteSpace(request.Endpoint) &&
            (!Uri.TryCreate(request.Endpoint.Trim(), UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps))
        {
            return Task.FromResult(Error("invalid_endpoint", "the AI endpoint must be an https URL"));
        }

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

    // ─── Manual-edit adoption (NET-188) ──────────────────────────────────────

    public override Task<AdoptResult> AdoptHostsEntries(Empty request, ServerCallContext context)
    {
        try
        {
            var outcome = _state.Adoption.AdoptNow("manual_trigger");
            AutoCategorizeMany(outcome.AdoptedDomains);
            return Task.FromResult(new AdoptResult
            {
                Ok = true,
                Adopted = outcome.Adopted,
                Total = outcome.FileBlocked,
                Message = outcome.Adopted == 0 && outcome.Organized == 0
                    ? "no new manual entries — hosts file already adopted and organized"
                    : $"adopted {outcome.Adopted} manual {(outcome.Adopted == 1 ? "entry" : "entries")}, "
                        + $"organized {outcome.Organized}",
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Task.FromResult(new AdoptResult
            {
                Ok = false,
                ErrorCode = "hostsguard.error.v1/hosts_locked",
                Message = "the hosts file is locked by another program (usually antivirus) — wait a few seconds and retry",
            });
        }
    }

    public override Task<Ack> SetHostsAdoption(HostsAdoptionRequest request, ServerCallContext context)
    {
        _state.Adoption.SetEnabled(request.Enabled);
        _state.Db.LogEvent("hosts", "adopt_toggle", details: request.Enabled ? "on" : "off");
        return Task.FromResult(Ok(request.Enabled
            ? "manual-edit adoption on — hand edits to the hosts file are deduped, organized, and imported automatically"
            : "manual-edit adoption off — hand edits raise a tamper alert instead of being imported"));
    }

    public override Task<HostsAdoptionStatus> GetHostsAdoptionStatus(Empty request, ServerCallContext context)
        => Task.FromResult(new HostsAdoptionStatus
        {
            Enabled = _state.Adoption.Enabled,
            LastRun = _state.Adoption.LastRun,
            LastResult = _state.Adoption.LastResult,
            Unadopted = _state.Adoption.CountUnadopted(),
        });

    /// <summary>Fire-and-forget AI categorization for a batch of freshly adopted domains.</summary>
    private void AutoCategorizeMany(IReadOnlyList<string> domains)
    {
        if (domains.Count == 0)
        {
            return;
        }

        var settings = _state.Ai.Settings;
        if (!settings.Enabled || settings.ApiKey.Length == 0)
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await _state.Ai.CategorizeAsync(domains, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _state.Db.LogEvent("hosts", "ai_categorize_failed", details: ex.Message);
            }
        });
    }

    public override async Task<Sparkline> GetSparkline(DomainRequest request, ServerCallContext context)
    {
        await _state.FlushActivityPersistenceAsync(context.CancellationToken);
        var d = Domains.ToAscii(request.Domain);
        var root = Domains.LooksLikeDomain(d) ? Domains.GetRoot(d) : d;
        var sparkline = new Sparkline();
        if (root.Length != 0)
        {
            sparkline.Hits.AddRange(_state.Db.GetHourlyHits(root, DateTime.Now));
        }

        return sparkline;
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

        // NET-110: restoring an older backup can drop current blocks — gate it.
        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
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

    // ─── AI-knowledge review & promote (NET-107) ─────────────────────────────

    private const string ReviewMetaKey = "ai_knowledge_reviewed_at";

    public override Task<AiKnowledgeList> ListAiKnowledge(AiKnowledgeRequest request, ServerCallContext context)
    {
        var lastReviewed = _state.Db.GetMeta(ReviewMetaKey) ?? string.Empty;
        var overrides = new Dictionary<(string, string), string>();
        foreach (var (kind, key, value, _) in _state.Db.GetAllUserOverrides())
        {
            overrides[(kind, key)] = value;
        }

        var list = new AiKnowledgeList { LastReviewed = lastReviewed };
        foreach (var (kind, key, value, model, created) in _state.Db.GetAllAiKnowledge())
        {
            var isNew = lastReviewed.Length == 0 || string.CompareOrdinal(created, lastReviewed) > 0;
            if (request.SinceLastReview && !isNew)
            {
                continue;
            }

            list.Entries.Add(new AiKnowledgeEntry
            {
                Kind = kind,
                Key = key,
                Value = value,
                Model = model,
                Created = created,
                UserOverride = overrides.GetValueOrDefault((kind, key), string.Empty),
                IsNew = isNew,
            });
        }

        return Task.FromResult(list);
    }

    public override Task<Ack> PromoteKnowledge(KnowledgeReviewRequest request, ServerCallContext context)
    {
        var promoted = 0;
        var discarded = 0;
        foreach (var a in request.Actions)
        {
            var kind = (a.Kind ?? string.Empty).Trim().ToLowerInvariant();
            var key = (a.Key ?? string.Empty).Trim().ToLowerInvariant();
            if (kind.Length == 0 || key.Length == 0)
            {
                continue;
            }

            switch ((a.Action ?? string.Empty).Trim().ToLowerInvariant())
            {
                case "promote":
                    var value = string.IsNullOrWhiteSpace(a.Value) ? string.Empty : a.Value.Trim();
                    if (value.Length == 0)
                    {
                        continue;
                    }

                    ApplyOverride(kind, key, value);
                    promoted++;
                    break;
                case "discard":
                    _state.Db.RemoveAiKnowledge(kind, key);
                    discarded++;
                    break;
            }
        }

        if (request.MarkReviewed)
        {
            _state.Db.SetMeta(ReviewMetaKey, DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture));
        }

        _state.Db.LogEvent("ai", "knowledge_review", details: $"promoted {promoted}, discarded {discarded}");
        return Task.FromResult(Ok($"promoted {promoted}, discarded {discarded}"));
    }

    public override Task<Ack> OverrideKnowledge(KnowledgeOverrideRequest request, ServerCallContext context)
    {
        var kind = (request.Kind ?? string.Empty).Trim().ToLowerInvariant();
        var key = (request.Key ?? string.Empty).Trim().ToLowerInvariant();
        if (kind is not ("purpose" or "category"))
        {
            return Task.FromResult(Error("invalid_override", "kind must be 'purpose' or 'category'"));
        }

        if (key.Length == 0)
        {
            return Task.FromResult(Error("invalid_override", "a domain key is required"));
        }

        ApplyOverride(kind, key, request.Value ?? string.Empty);
        return Task.FromResult(Ok(string.IsNullOrWhiteSpace(request.Value)
            ? $"cleared {kind} override for {key}"
            : $"set {kind} for {key} to \"{request.Value.Trim()}\""));
    }

    /// <summary>
    /// Persist a user override and, for categories, reflect it live in the managed
    /// row + hosts-file section so the correction is immediately visible.
    /// </summary>
    private void ApplyOverride(string kind, string key, string value)
    {
        _state.Db.UpsertUserOverride(kind, key, value);
        if (kind == "category" && !string.IsNullOrWhiteSpace(value) && Domains.LooksLikeDomain(key))
        {
            var canonical = DomainCategories.Canonicalize(value.Trim());
            _state.Db.SetCategory(key, canonical);
            if (_state.Hosts.GetBlocked().Contains(key))
            {
                _state.Hosts.OrganizeByCategory(new Dictionary<string, string>(StringComparer.Ordinal) { [key] = canonical });
            }
        }
    }

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };
}

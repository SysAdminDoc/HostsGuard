using System.Runtime.Versioning;
using Google.Protobuf.WellKnownTypes;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Temp-allow windows with persisted expiry re-arm (parity with the Python
/// build's config-backed temp_allows). Add() whitelists + unblocks now and
/// persists the expiry; a single timer re-blocks at the earliest expiry.
/// Resume() runs at service start: expired windows revert immediately, live
/// ones re-arm — a reboot never turns a temporary hole into a permanent one.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TempAllowScheduler : IDisposable
{
    public const int MaxMinutes = 7 * 24 * 60;

    private readonly HostsEngine _hosts;
    private readonly HostsDatabase _db;
    private readonly EventBus _bus;
    private readonly object _gate = new();
    private readonly Timer _timer;
    private bool _disposed;

    public TempAllowScheduler(HostsEngine hosts, HostsDatabase db, EventBus bus)
    {
        _hosts = hosts ?? throw new ArgumentNullException(nameof(hosts));
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        _timer = new Timer(_ => Sweep(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
    }

    /// <summary>Allow <paramref name="domain"/> for <paramref name="minutes"/>, persisted.</summary>
    public void Add(string domain, int minutes, string source = "temp_allow")
    {
        var d = domain.ToLowerInvariant().Trim();
        var expires = DateTime.UtcNow.AddMinutes(Math.Clamp(minutes, 1, MaxMinutes));
        _hosts.Unblock(d);
        _db.AddDomain(d, "whitelisted", "temp_allow");
        _db.SetTempAllow(d, expires);
        _db.LogEvent(d, "temp_allowed", details: $"{minutes} min", reason: source);
        lock (_gate)
        {
            if (!_disposed)
            {
                Rearm();
            }
        }
    }

    /// <summary>Re-arm persisted windows after a service restart.</summary>
    public void Resume()
    {
        Sweep();
    }

    /// <summary>Currently pending windows (domain, UTC expiry).</summary>
    public IReadOnlyList<(string Domain, DateTime ExpiresUtc)> Pending() => _db.GetTempAllows();

    private void Sweep()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            foreach (var (domain, expiresUtc) in _db.GetTempAllows())
            {
                if (expiresUtc <= DateTime.UtcNow)
                {
                    Revert(domain);
                }
            }

            Rearm();
        }
    }

    private void Revert(string domain)
    {
        _db.RemoveTempAllow(domain);

        // Only revert if the domain is still ours: a manual allow/block since
        // the window opened wins over the automatic revert.
        if (_db.GetDomainSource(domain) != "temp_allow")
        {
            return;
        }

        _hosts.Block(domain);
        // AddDomain's allowlist-wins UPSERT would refuse this downgrade; the
        // revert of our own temporary whitelist is the one legitimate case.
        _db.UpdateStatus(domain, "blocked", "temp_reverted");
        _db.LogEvent(domain, "blocked", details: "temp-allow expired", reason: "temp_reverted");
        _bus.Publish(new ActivityEvent
        {
            Ts = Timestamp.FromDateTime(DateTime.UtcNow),
            Domain = domain,
            Action = "blocked",
            Details = "temp-allow expired",
            Reason = "temp_reverted",
        });
    }

    private void Rearm()
    {
        var pending = _db.GetTempAllows();
        if (pending.Count == 0)
        {
            _timer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            return;
        }

        var next = pending.Min(p => p.ExpiresUtc) - DateTime.UtcNow;
        if (next < TimeSpan.FromSeconds(1))
        {
            next = TimeSpan.FromSeconds(1);
        }

        _timer.Change(next, Timeout.InfiniteTimeSpan);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
        }

        // Drain: wait for an in-flight Sweep so a re-block/revert can never touch
        // the DB after ServiceState disposes it (Db.Dispose runs last).
        using var drained = new ManualResetEvent(false);
        if (_timer.Dispose(drained))
        {
            drained.WaitOne(TimeSpan.FromSeconds(5));
        }
    }
}

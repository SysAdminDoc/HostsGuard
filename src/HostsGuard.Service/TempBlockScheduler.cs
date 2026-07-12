using System.Runtime.Versioning;
using Google.Protobuf.WellKnownTypes;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Temp-block windows: the mirror image of <see cref="TempAllowScheduler"/>.
/// Add() blocks a domain now and persists the expiry plus the status to restore
/// when the window closes; a single timer reverts at the earliest expiry.
/// Resume() runs at service start so a reboot never leaves a temporary block
/// stuck on forever — expired windows revert immediately, live ones re-arm.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TempBlockScheduler : IDisposable
{
    public const int MaxMinutes = 7 * 24 * 60;

    private readonly HostsEngine _hosts;
    private readonly HostsDatabase _db;
    private readonly EventBus _bus;
    private readonly object _gate = new();
    private readonly Timer _timer;
    private bool _disposed;

    public TempBlockScheduler(HostsEngine hosts, HostsDatabase db, EventBus bus)
    {
        _hosts = hosts ?? throw new ArgumentNullException(nameof(hosts));
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        _timer = new Timer(_ => Sweep(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
    }

    /// <summary>Block <paramref name="domain"/> for <paramref name="minutes"/>, persisted, with auto-revert.</summary>
    public void Add(string domain, int minutes, string source = "temp_block")
    {
        var d = domain.ToLowerInvariant().Trim();
        var expires = DateTime.UtcNow.AddMinutes(Math.Clamp(minutes, 1, MaxMinutes));

        // Remember what to restore: an already-whitelisted or already-blocked
        // domain must return to that state, an unmanaged one back to unmanaged.
        var prior = _db.GetDomainStatus(d) ?? string.Empty;

        _hosts.Block(d);
        _db.AddDomain(d, "blocked", source);
        _db.SetTempBlock(d, expires, prior);
        _db.LogEvent(d, "temp_blocked", details: $"{minutes} min", reason: source);
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
    public IReadOnlyList<(string Domain, DateTime ExpiresUtc)> Pending()
        => _db.GetTempBlocks().Select(b => (b.Domain, b.ExpiresUtc)).ToList();

    private void Sweep()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            foreach (var (domain, expiresUtc, priorStatus) in _db.GetTempBlocks())
            {
                if (expiresUtc <= DateTime.UtcNow)
                {
                    Revert(domain, priorStatus);
                }
            }

            Rearm();
        }
    }

    private void Revert(string domain, string priorStatus)
    {
        _db.RemoveTempBlock(domain);

        // Only revert if the domain is still ours: a manual allow/block since the
        // window opened wins over the automatic revert.
        if (_db.GetDomainSource(domain) != "temp_block")
        {
            return;
        }

        if (string.Equals(priorStatus, "blocked", StringComparison.Ordinal))
        {
            // It was already permanently blocked before the temp-block; leave it.
            _db.UpdateStatus(domain, "blocked", "manual");
            return;
        }

        _hosts.Unblock(domain);
        if (string.Equals(priorStatus, "whitelisted", StringComparison.Ordinal))
        {
            _db.AddDomain(domain, "whitelisted", "temp_reverted");
        }
        else
        {
            _db.RemoveDomain(domain);
        }

        _db.LogEvent(domain, "unblocked", details: "temp-block expired", reason: "temp_reverted");
        _bus.Publish(new ActivityEvent
        {
            Ts = Timestamp.FromDateTime(DateTime.UtcNow),
            Domain = domain,
            Action = "unblocked",
            Details = "temp-block expired",
            Reason = "temp_reverted",
        });
    }

    private void Rearm()
    {
        var pending = _db.GetTempBlocks();
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

        // Drain: wait for an in-flight Sweep so a revert can never touch the DB
        // after ServiceState disposes it (Db.Dispose runs last).
        using var drained = new ManualResetEvent(false);
        if (_timer.Dispose(drained))
        {
            drained.WaitOne(TimeSpan.FromSeconds(5));
        }
    }
}

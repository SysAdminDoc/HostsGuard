namespace HostsGuard.Service;

/// <summary>
/// Single service clock for TTL, expiry, scheduling, and timestamp decisions.
/// Tests inject an adjustable implementation; production uses
/// <see cref="SystemClock.Instance"/>.
/// </summary>
public interface IClock
{
    DateTime UtcNow { get; }

    DateTime Now { get; }
}

public sealed class SystemClock : IClock
{
    public static SystemClock Instance { get; } = new();

    private SystemClock()
    {
    }

    public DateTime UtcNow => DateTime.UtcNow;

    public DateTime Now => DateTime.Now;
}

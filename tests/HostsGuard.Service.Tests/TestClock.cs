namespace HostsGuard.Service.Tests;

internal sealed class TestClock : IClock
{
    private long _utcTicks;

    public TestClock(DateTime utcNow)
    {
        _utcTicks = DateTime.SpecifyKind(utcNow, DateTimeKind.Utc).Ticks;
    }

    public DateTime UtcNow => new(Interlocked.Read(ref _utcTicks), DateTimeKind.Utc);

    public DateTime Now => UtcNow.ToLocalTime();

    public void Advance(TimeSpan by) => Interlocked.Add(ref _utcTicks, by.Ticks);
}

namespace HostsGuard.Windows;

/// <summary>OS registry controls behind LAN attack-surface toggles.</summary>
public interface ILanAttackSurfaceStore
{
    bool IsBlocked(string key);

    void SetBlocked(string key, bool blocked);
}

public sealed class NullLanAttackSurfaceStore : ILanAttackSurfaceStore
{
    public static NullLanAttackSurfaceStore Instance { get; } = new();

    private NullLanAttackSurfaceStore()
    {
    }

    public bool IsBlocked(string key) => false;

    public void SetBlocked(string key, bool blocked)
    {
    }
}

namespace HostsGuard.Core;

/// <summary>
/// One firewall profile's posture: whether the profile is enabled and whether
/// its default outbound action is Block (all three blocking = lockdown).
/// </summary>
public sealed record FwProfilePosture(string Name, bool Enabled, bool OutboundBlock);

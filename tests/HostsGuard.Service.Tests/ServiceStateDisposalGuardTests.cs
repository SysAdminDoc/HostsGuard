using System.Reflection;
using FluentAssertions;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// Guards the recurring "a new IDisposable/timer-owning collaborator was added to
/// <see cref="ServiceState"/> but never disposed" regression (the class fixed for
/// IpBlocklistCoordinator, ListImporter, and others). This test pins every
/// IDisposable-typed member of ServiceState into exactly one ownership bucket:
/// disposed by <c>ServiceState.Dispose</c>, or owned (via <c>using var</c>) by
/// <c>Program.cs</c>. Adding or changing a disposable member fails here, forcing
/// the author to decide and record which owner disposes it.
/// </summary>
public sealed class ServiceStateDisposalGuardTests
{
    // Disposed in ServiceState.Dispose, in reverse construction order.
    private static readonly HashSet<string> DisposedByServiceState = new(StringComparer.Ordinal)
    {
        "Db",
        "Schedules",
        "Lists",
        "IpBlocklists",
        "GeoIp",
        "Asn",
        "Intel",
        "Ai",
        "ActivityPersistence",
        "Consent",
        "SecureRules",
        "FirewallDrift",
        "WfpFilterDrift",
        "ProxyBaseline",
        "TempAllows",
        "TempBlocks",
        "EnforcementPause",
        "ResolverHealth",
        "DomainFirewall",
    };

    // Constructed with `using var` in Program.cs and disposed there; ServiceState
    // only references them, so ServiceState.Dispose must NOT dispose them.
    private static readonly HashSet<string> OwnedByProgram = new(StringComparer.Ordinal)
    {
        "Bandwidth",
        "Sni",
        "KillSwitch",
        "AppVpnBindings",
    };

    [Fact]
    public void Every_disposable_member_has_a_declared_owner()
    {
        var expected = new HashSet<string>(DisposedByServiceState, StringComparer.Ordinal);
        expected.UnionWith(OwnedByProgram);

        var actual = DisposableMemberNames();
        actual.Should().BeEquivalentTo(expected,
            "every IDisposable-typed member of ServiceState must be disposed by exactly " +
            "one owner — ServiceState.Dispose or a Program.cs `using var` — a diff here " +
            "means a collaborator's lifecycle was added/changed without recording its owner");
    }

    private static HashSet<string> DisposableMemberNames()
    {
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        var names = new HashSet<string>(StringComparer.Ordinal);

        foreach (var p in typeof(ServiceState).GetProperties(flags))
        {
            if (typeof(IDisposable).IsAssignableFrom(p.PropertyType))
            {
                names.Add(p.Name);
            }
        }

        foreach (var f in typeof(ServiceState).GetFields(flags))
        {
            // Skip compiler-generated auto-property backing fields (counted above)
            // and the private shutdown CancellationTokenSource, which Dispose owns
            // directly and is not a collaborator lifecycle.
            if (f.Name.Contains("BackingField", StringComparison.Ordinal) || f.Name == "_shutdown")
            {
                continue;
            }

            if (typeof(IDisposable).IsAssignableFrom(f.FieldType))
            {
                names.Add(f.Name);
            }
        }

        return names;
    }
}

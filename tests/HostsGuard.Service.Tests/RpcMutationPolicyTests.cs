using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using FluentAssertions;
using HostsGuard.Contracts;
using Xunit;

namespace HostsGuard.Service.Tests;

[SupportedOSPlatform("windows")]
public sealed class RpcMutationPolicyTests
{
    [Fact]
    public void Every_published_rpc_has_exactly_one_explicit_lock_classification()
    {
        var contract = HostsguardReflection.Descriptor.Services
            .SelectMany(service => service.Methods.Select(method => $"{service.FullName}/{method.Name}"))
            .OrderBy(key => key, StringComparer.Ordinal)
            .ToArray();

        RpcMutationPolicy.All.Keys.OrderBy(key => key, StringComparer.Ordinal)
            .Should().Equal(contract);
        RpcMutationPolicy.All.Values.Should().Contain(RpcMutationKind.ReadOnly);
        RpcMutationPolicy.All.Values.Should().Contain(RpcMutationKind.ProtectiveMutation);
        RpcMutationPolicy.All.Values.Should().Contain(RpcMutationKind.LockProtectedMutation);
    }

    [Fact]
    public void Every_lock_protected_rpc_calls_the_centralized_gate()
    {
        var root = FindRepoRoot();
        foreach (var (key, kind) in RpcMutationPolicy.All.Where(pair => pair.Value == RpcMutationKind.LockProtectedMutation))
        {
            var separator = key.LastIndexOf('/');
            var service = key[(key.LastIndexOf('.') + 1)..separator];
            var method = key[(separator + 1)..];
            var path = Path.Combine(root, "src", "HostsGuard.Service", service + "ServiceImpl.cs");
            var source = File.ReadAllText(path);
            var signature = Regex.Match(
                source,
                $@"public\s+override\s+(?:async\s+)?Task(?:<[^>]+>)?\s+{Regex.Escape(method)}\s*\(",
                RegexOptions.CultureInvariant);
            signature.Success.Should().BeTrue($"{service}/{method} must have a service implementation");
            var next = source.IndexOf("\n    public override", signature.Index + signature.Length, StringComparison.Ordinal);
            var body = source[signature.Index..(next < 0 ? source.Length : next)];
            body.Should().Contain($"GateWhenLocked(\"{service}\")",
                $"{service}/{method} is lock-protected and must enforce the centralized policy directly");
        }
    }

    private static string FindRepoRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "HostsGuard.sln")))
        {
            current = current.Parent;
        }

        return current?.FullName ?? throw new DirectoryNotFoundException("HostsGuard.sln was not found above the test output");
    }
}

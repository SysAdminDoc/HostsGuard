using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using FluentAssertions;
using HostsGuard.Ipc;
using Xunit;

namespace HostsGuard.Ipc.Tests;

[SupportedOSPlatform("windows")]
public class SecurityPrimitiveTests
{
    [Fact]
    public void PipeAcl_grants_only_current_user_and_admins()
    {
        var security = NamedPipeSecurity.CreateForCurrentUserAndAdmins();
        var sids = NamedPipeSecurity.GrantedSids(security);

        var currentUser = WindowsIdentity.GetCurrent().User!;
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

        sids.Should().Contain(currentUser);
        sids.Should().Contain(admins);
        sids.Should().NotContain(everyone);
        sids.Should().HaveCount(2);
    }

    [Fact]
    public void CrossSession_acl_lets_interactive_users_connect_but_not_own()
    {
        // WFCP-000b + NET-087: the LocalSystem service and the unelevated
        // user-session UI share the pipe — SYSTEM/Admins keep full control, the
        // INTERACTIVE group gets read-write only, nobody else appears. INTERACTIVE
        // (not Authenticated Users) excludes service accounts and remote/NETWORK
        // logons.
        var security = NamedPipeSecurity.CreateCrossSession();
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<System.IO.Pipes.PipeAccessRule>()
            .ToDictionary(r => (SecurityIdentifier)r.IdentityReference, r => r.PipeAccessRights);

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
        var authenticated = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
        var network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

        rules.Should().HaveCount(3);
        rules[system].Should().HaveFlag(System.IO.Pipes.PipeAccessRights.FullControl);
        rules[admins].Should().HaveFlag(System.IO.Pipes.PipeAccessRights.FullControl);
        // The ACL layer appends Synchronize to usable grants — assert the
        // contract: connectable, but no ownership/permission rights.
        rules[interactive].Should().HaveFlag(System.IO.Pipes.PipeAccessRights.ReadWrite);
        rules[interactive].Should().NotHaveFlag(System.IO.Pipes.PipeAccessRights.ChangePermissions);
        rules[interactive].Should().NotHaveFlag(System.IO.Pipes.PipeAccessRights.TakeOwnership);
        // The over-broad principals are gone.
        rules.Should().NotContainKey(authenticated);
        rules.Should().NotContainKey(network);
        rules.Should().NotContainKey(everyone);
    }

    [Fact]
    public void Default_acl_is_per_user_outside_the_service_context()
    {
        // Test processes never run as LocalSystem, so the default must be the
        // per-user shape here.
        WindowsIdentity.GetCurrent().IsSystem.Should().BeFalse();
        NamedPipeSecurity.GrantedSids(NamedPipeSecurity.CreateDefault())
            .Should().Contain(WindowsIdentity.GetCurrent().User!);
    }

    [Fact]
    public void Pipe_owner_trust_accepts_system_admins_and_the_current_user()
    {
        var currentUser = WindowsIdentity.GetCurrent().User!;
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var localService = new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null);
        var networkService = new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null);

        // Production (LocalSystem) and dev/console (current user) owners are trusted.
        PipeServerTrust.IsTrustedOwner(system, currentUser).Should().BeTrue();
        PipeServerTrust.IsTrustedOwner(admins, currentUser).Should().BeTrue();
        PipeServerTrust.IsTrustedOwner(localService, currentUser).Should().BeTrue();
        PipeServerTrust.IsTrustedOwner(networkService, currentUser).Should().BeTrue();
        PipeServerTrust.IsTrustedOwner(currentUser, currentUser).Should().BeTrue();
        foreach (var owner in new[] { system, admins, localService, networkService, currentUser })
        {
            var act = () => PipeServerTrust.EnsureTrustedServer(PipeOwnerProbeResult.Success(owner), currentUser);
            act.Should().NotThrow();
        }
    }

    [Fact]
    public void Pipe_owner_trust_rejects_a_different_user_and_indeterminate_owner()
    {
        // A pipe owned by some OTHER interactive user is the squatter case.
        var me = new SecurityIdentifier("S-1-5-21-111-222-333-1001");
        var squatter = new SecurityIdentifier("S-1-5-21-111-222-333-1002");
        PipeServerTrust.IsTrustedOwner(squatter, me).Should().BeFalse();
        PipeServerTrust.EvaluateOwner(squatter, me).Should().Be(PipeServerTrustDecision.Untrusted);
        PipeServerTrust.EvaluateOwner(null, me).Should().Be(PipeServerTrustDecision.Indeterminate);
        PipeServerTrust.EvaluateOwner(me, null).Should().Be(PipeServerTrustDecision.Indeterminate);
        PipeServerTrust.IsTrustedOwner(null, me).Should().BeFalse();
        var untrusted = () => PipeServerTrust.EnsureTrustedServer(PipeOwnerProbeResult.Success(squatter), me);
        untrusted.Should().Throw<PipeServerTrustException>()
            .Which.ErrorCode.Should().Be(PipeServerTrust.UntrustedOwnerError);
        var unknownCurrentUser = () => PipeServerTrust.EnsureTrustedServer(PipeOwnerProbeResult.Success(me), null);
        unknownCurrentUser.Should().Throw<PipeServerTrustException>()
            .Which.ErrorCode.Should().Be(PipeServerTrust.IndeterminateOwnerError);
    }

    public static TheoryData<PipeOwnerProbeResult, string> FailedOwnerProbes => new()
    {
        { PipeOwnerProbeResult.Failed(PipeOwnerProbeFailure.InvalidHandle), PipeServerTrust.InvalidHandleError },
        { PipeOwnerProbeResult.Failed(PipeOwnerProbeFailure.AccessDenied, 5), PipeServerTrust.AccessDeniedError },
        { PipeOwnerProbeResult.Failed(PipeOwnerProbeFailure.MissingOwner), PipeServerTrust.IndeterminateOwnerError },
        { PipeOwnerProbeResult.Failed(PipeOwnerProbeFailure.InvalidOwner), PipeServerTrust.IndeterminateOwnerError },
        { PipeOwnerProbeResult.Failed(PipeOwnerProbeFailure.ApiUnavailable), PipeServerTrust.ProbeUnavailableError },
        { PipeOwnerProbeResult.Failed(PipeOwnerProbeFailure.NativeFailure, 87), PipeServerTrust.ProbeFailedError },
        { new PipeOwnerProbeResult(null, PipeOwnerProbeFailure.None), PipeServerTrust.IndeterminateOwnerError },
    };

    [Theory]
    [MemberData(nameof(FailedOwnerProbes))]
    public void Pipe_owner_probe_failures_fail_closed_with_safe_codes(
        PipeOwnerProbeResult probe,
        string expectedCode)
    {
        var currentUser = WindowsIdentity.GetCurrent().User!;
        var token = SessionToken.Generate();

        var act = () => PipeServerTrust.EnsureTrustedServer(probe, currentUser);

        var error = act.Should().Throw<PipeServerTrustException>().Which;
        error.ErrorCode.Should().Be(expectedCode);
        error.Message.Should().StartWith(expectedCode)
            .And.NotContain(currentUser.Value)
            .And.NotContain(token);
    }

    [Fact]
    public void Invalid_pipe_handle_has_a_typed_probe_failure()
    {
        using var invalid = new Microsoft.Win32.SafeHandles.SafePipeHandle(IntPtr.Zero, ownsHandle: false);

        PipeServerTrust.ProbeOwner(invalid).Failure.Should().Be(PipeOwnerProbeFailure.InvalidHandle);
    }

    [Fact]
    public async Task Current_user_pipe_owner_is_proven_before_use()
    {
        var pipeName = "HostsGuard.OwnerProbe." + Guid.NewGuid().ToString("N");
        using var server = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        using var client = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            TokenImpersonationLevel.Anonymous);

        var accepting = server.WaitForConnectionAsync();
        await client.ConnectAsync();
        await accepting;

        var probe = PipeServerTrust.ProbeOwner(client.SafePipeHandle);
        var currentUser = WindowsIdentity.GetCurrent().User!;
        probe.Succeeded.Should().BeTrue();
        probe.Owner.Should().Be(currentUser);
        var act = () => PipeServerTrust.EnsureTrustedServer(probe, currentUser);
        act.Should().NotThrow();
    }

    [Fact]
    public void Token_generate_is_256bit_hex_and_unique()
    {
        var a = SessionToken.Generate();
        var b = SessionToken.Generate();
        a.Should().HaveLength(64).And.MatchRegex("^[0-9a-f]{64}$");
        a.Should().NotBe(b);
    }

    [Fact]
    public void ConstantTimeEquals_matches_and_rejects()
    {
        var t = SessionToken.Generate();
        var replacement = t[^1] == '0' ? '1' : '0';
        SessionToken.ConstantTimeEquals(t, t).Should().BeTrue();
        SessionToken.ConstantTimeEquals(t, t[..^1] + replacement).Should().BeFalse();
        SessionToken.ConstantTimeEquals(t, null).Should().BeFalse();
        SessionToken.ConstantTimeEquals(null, t).Should().BeFalse();
    }

    [Fact]
    public void Handshake_file_roundtrips_and_is_acl_locked()
    {
        var dir = Path.Combine(Path.GetTempPath(), "hg_ipc_" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(dir, "session_token");
        try
        {
            var token = SessionToken.Generate();
            SessionToken.WriteHandshake(path, token);
            SessionToken.ReadHandshake(path).Should().Be(token);

            var acl = new FileInfo(path).GetAccessControl();
            var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));
            var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            rules.Cast<System.Security.AccessControl.FileSystemAccessRule>()
                .Any(r => r.IdentityReference.Equals(everyone)).Should().BeFalse();

            // NET-179: atomic publish leaves no temp file behind.
            File.Exists(path + ".tmp").Should().BeFalse();
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task ReadHandshake_recovers_from_a_transient_empty_token_during_rotation()
    {
        // NET-179: a client reading mid-rotation must not cache an empty token.
        var dir = Path.Combine(Path.GetTempPath(), "hg_ipc_rot_" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(dir, "session_token");
        Directory.CreateDirectory(dir);
        try
        {
            var token = SessionToken.Generate();
            File.WriteAllText(path, string.Empty); // simulate the empty mid-rotation window

            // A writer fills in the real token shortly after the read begins.
            var writer = Task.Run(async () =>
            {
                // Exceeds the old fixed five-attempt (~100 ms) retry budget;
                // scheduler pressure during a service restart can do the same.
                await Task.Delay(150);
                File.WriteAllText(path, token);
            });

            SessionToken.ReadHandshake(path).Should().Be(token);
            await writer;
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* best effort */ }
        }
    }
}
